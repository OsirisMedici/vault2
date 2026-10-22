#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Create encrypted recovery bundles and verify isolated Vault 2 data restores."""
import argparse
import datetime as dt
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import zipfile

from crypto_native import Crypto

ROOT = Path.home() / '.local/share/agent-vault-upstream-raven'
MAGIC = b'VAULT2-BACKUP-1\n'
LIMIT = 128 * 1024 * 1024


def private_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
        raise ValueError('unsafe private directory')


def private_read(path, limit=LIMIT, public_certificate=False):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        s = os.fstat(f.fileno())
        modes = (0o600, 0o644) if public_certificate else (0o600,)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) not in modes or s.st_nlink != 1 or not 0 < s.st_size <= limit:
            raise ValueError('unsafe private file')
        return f.read(limit+1)


def private_write(path, content):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as f:
        f.write(content); f.flush(); os.fsync(f.fileno())


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def create():
    private_dir(ROOT)
    if (Path.home()/'.agent-vault').resolve() != ROOT/'state':
        raise ValueError('unexpected state binding')
    for name in ('backups', 'recovery-keys', 'restore-checks'): private_dir(ROOT/name)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup, keyfile = ROOT/'backups'/f'{stamp}.vault2', ROOT/'recovery-keys'/f'{stamp}.key'
    scratch = Path(tempfile.mkdtemp(prefix='backup-', dir=ROOT))
    try:
        snapshot = scratch/'agent-vault.db'
        private_write(snapshot, b'')
        with sqlite3.connect('file:'+str(ROOT/'state/agent-vault.db')+'?mode=ro', uri=True) as source, sqlite3.connect(snapshot) as target:
            source.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('snapshot integrity failed')
            if target.execute('SELECT count(*) FROM master_key WHERE dek_plaintext IS NULL AND length(dek_ciphertext)>0').fetchone()[0] != 1:
                raise ValueError('password protection not established')
        files = {'state/agent-vault.db':private_read(snapshot)}
        for name in ('master-password', 'demo-owner.json', 'bitwarden-import-manifest.json', 'bitwarden-import-receipt.json'):
            files[name] = private_read(ROOT/name)
        for name in ('t3-raven-agent.json','ghl-selection.json'):
            if (ROOT/name).exists(): files[name] = private_read(ROOT/name)
        for p in sorted((ROOT/'state/ca').iterdir()):
            if not p.is_file() or p.is_symlink(): raise ValueError('unexpected CA entry')
            files['state/ca/'+p.name] = private_read(p, public_certificate=p.name=='ca.crt.pem')
        manifest = {'format':1,'createdAtUTC':stamp,'engineVersion':'v0.40.2',
                    'sourceCommit':'d5836ec3bb2315de38043d742ae5daca11a4944a',
                    'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()},
                    'excluded':['session.json','pid files','logs','original plaintext export'],
                    'containsPrivateRecoveryMaterial':True}
        archive = io.BytesIO()
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
            for name,data in files.items(): z.writestr(name,data)
            z.writestr('bundle-manifest.json',json_bytes(manifest))
        key, nonce = os.urandom(32), os.urandom(12)
        encrypted = MAGIC + nonce + Crypto().gcm(key,nonce,archive.getvalue())
        private_write(keyfile,key)
        private_write(backup,encrypted)
        return {'backup':str(backup),'keyFile':str(keyfile),'encrypted':True,'liveDatabaseModified':False,
                'copyOffDeviceSeparately':True}
    finally:
        shutil.rmtree(scratch)


def verify(backup, keyfile, destination):
    if destination.exists(): raise ValueError('restore destination already exists')
    private_dir(destination.parent)
    raw, key = private_read(backup), private_read(keyfile,32)
    if len(key)!=32 or not raw.startswith(MAGIC): raise ValueError('unsupported bundle')
    crypto = Crypto(); nonce=raw[len(MAGIC):len(MAGIC)+12]; ciphertext=raw[len(MAGIC)+12:]
    plain=crypto.gcm(key,nonce,ciphertext,True)
    try:
        crypto.gcm(key,nonce,ciphertext[:-1]+bytes([ciphertext[-1]^1]),True)
    except ValueError: pass
    else: raise ValueError('tamper detection failed')
    with zipfile.ZipFile(io.BytesIO(plain)) as archive:
        infos=archive.infolist()
        if len(infos)>32 or len({i.filename for i in infos})!=len(infos) or sum(i.file_size for i in infos)>LIMIT:
            raise ValueError('unexpected recovery bundle')
        manifest=json.loads(archive.read('bundle-manifest.json'))
        if manifest.get('format')!=1 or set(archive.namelist())!=set(manifest['files'])|{'bundle-manifest.json'}:
            raise ValueError('unexpected recovery manifest')
        files={name:archive.read(name) for name in manifest['files']}
        if any(not hmac.compare_digest(hashlib.sha256(data).hexdigest(),manifest['files'][name]) for name,data in files.items()):
            raise ValueError('recovery file mismatch')
    destination.mkdir(mode=0o700)
    # Only encrypted database and metadata are restored to disk. Master/owner
    # recovery inputs remain in memory for this validation and are not extracted.
    database=destination/'agent-vault.db';private_write(database,files['state/agent-vault.db'])
    with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row
        if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('restored database integrity failed')
        mk=db.execute('SELECT * FROM master_key').fetchone()
        if mk['dek_plaintext'] is not None: raise ValueError('restored database is passwordless')
        master=files['master-password'].rstrip(b'\r\n')
        kek=crypto.derive(master,mk['salt'],mk['kdf_time'],mk['kdf_memory'],mk['kdf_threads'])
        dek=crypto.gcm(kek,mk['dek_nonce'],mk['dek_ciphertext'],True)
        if crypto.gcm(dek,mk['sentinel_nonce'],mk['sentinel'],True)!=b'agent-vault-master-key-check':
            raise ValueError('restored master unlock failed')
        owner=json.loads(files['demo-owner.json'])
        user=db.execute('SELECT * FROM users WHERE email=?',(owner['email'],)).fetchone()
        if not user or user['role']!='owner': raise ValueError('restored owner missing')
        derived=crypto.derive(owner['password'].encode(),user['password_salt'],user['kdf_time'],user['kdf_memory'],user['kdf_threads'])
        if not hmac.compare_digest(derived,user['password_hash']): raise ValueError('restored owner password failed')
        vault=db.execute('SELECT id FROM vaults WHERE name=?',('bitwarden-import',)).fetchone()
        values={r['key']:crypto.gcm(dek,r['nonce'],r['ciphertext'],True).decode() for r in db.execute('SELECT * FROM credentials WHERE vault_id=?',(vault['id'],))}
        imported=json.loads(files['bitwarden-import-manifest.json'])
        complete=incomplete=0
        for row in imported['records']:
            metadata=json.loads(values[row['metadataKey']])
            if metadata['id']!=row['sourceID']: raise ValueError('restored source ID mismatch')
            for field in ('username','password'):
                if row.get(field+'Key') and not values[row[field+'Key']]: raise ValueError('restored credential missing')
            if row.get('usernameKey') and row.get('passwordKey'): complete+=1
            else: incomplete+=1
        receipt=json.loads(files['bitwarden-import-receipt.json'])
        if len(values)!=receipt['encryptedCredentialRowsVerified'] or complete!=receipt['completeLogins'] or incomplete!=receipt['incompleteLogins']:
            raise ValueError('restored inventory mismatch')
        export_metadata=json.loads(values[imported['metadataKey']])
        folders=len(export_metadata.get('folders') or [])
        if folders!=receipt['preservedFolders']:raise ValueError('restored folder inventory mismatch')
        agent_roles=[r[0] for r in db.execute('SELECT g.role FROM vault_grants g JOIN agents a ON a.id=g.actor_id WHERE g.vault_id=? AND a.name=?',(vault['id'],'t3-raven'))]
        result={'databaseIntegrity':'ok','outerEncryptionAuthenticated':True,'tamperRejected':True,
                'masterUnlockVerified':True,'ownerPasswordVerified':True,'decryptedImportedFields':len(values),
                'loginRecords':len(imported['records']),'completeLogins':complete,'incompleteLogins':incomplete,
                'folders':folders,'t3AgentVaultRoles':agent_roles,
                'restoredEngineLaunched':False,'liveStateChanged':False,'secretsPrinted':False,
                'verifiedAtUTC':dt.datetime.now(dt.timezone.utc).isoformat()}
    private_write(destination/'verification.json',json_bytes(result))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest='action',required=True)
    sub.add_parser('create')
    check=sub.add_parser('verify');check.add_argument('--backup',type=Path,required=True);check.add_argument('--key-file',type=Path,required=True);check.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    try:
        result=create() if args.action=='create' else verify(args.backup.expanduser(),args.key_file.expanduser(),args.destination.expanduser())
        print(json.dumps(result,indent=2))
    except Exception:
        print(json.dumps({'state':'needs_attention','reason':'recovery_check_failed','privateInputsNotPrinted':True}));sys.exit(1)


if __name__=='__main__':main()
