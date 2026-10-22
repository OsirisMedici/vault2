#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Private local startup and readiness for the existing Raven Vault 2 instance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error

from recovery import ROOT, private_dir, private_read, private_write, json_bytes
from crypto_native import Crypto

SERVICE=ROOT/'service'
LABELS=('com.osiris.vault2.engine','com.osiris.vault2.web')
BINARY=ROOT/'releases/v0.40.2/unpacked/agent-vault'
BINARY_SHA='bc7473f958fad55159f388a0ebdd89f2acee9fd1b90359b773d2ffc017e95401'
DOMAIN='gui/'+str(os.getuid())


def configuration():
    return json.loads(private_read(SERVICE/'configuration.json'))


def validate_state():
    if not ROOT.is_dir() or not (ROOT/'state').is_dir():raise ValueError('state_binding_mismatch')
    private_dir(ROOT);private_dir(ROOT/'state')
    if not (Path.home()/'.agent-vault').is_symlink() or (Path.home()/'.agent-vault').resolve()!=ROOT/'state':
        raise ValueError('state_binding_mismatch')
    private_read(ROOT/'state/agent-vault.db')
    with sqlite3.connect('file:'+str(ROOT/'state/agent-vault.db')+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row
        row=db.execute('SELECT * FROM master_key').fetchone()
        if not row or row['dek_plaintext'] is not None or not row['dek_ciphertext']:
            raise ValueError('password_protected_state_required')
        if db.execute('SELECT count(*) FROM users').fetchone()[0]<1: raise ValueError('owner_missing')
        return dict(row)


def verify_unlock():
    mk=validate_state()
    password=private_read(ROOT/'master-password',1024).rstrip(b'\r\n')
    crypto=Crypto();kek=crypto.derive(password,mk['salt'],mk['kdf_time'],mk['kdf_memory'],mk['kdf_threads'])
    dek=crypto.gcm(kek,mk['dek_nonce'],mk['dek_ciphertext'],True)
    if crypto.gcm(dek,mk['sentinel_nonce'],mk['sentinel'],True)!=b'agent-vault-master-key-check': raise ValueError('needs_private_unlock')


def run_engine():
    # Refuse missing state before calling upstream, which can initialize a new DB.
    verify_unlock()
    if hashlib.sha256(BINARY.read_bytes()).hexdigest()!=BINARY_SHA: raise ValueError('binary_pin_mismatch')
    env={k:v for k,v in os.environ.items() if not k.startswith(('AGENT_VAULT_','_AGENT_VAULT_','INFISICAL_')) and k not in ('DATABASE_URL','PORT')}
    env.update(AGENT_VAULT_TELEMETRY='off',AGENT_VAULT_ADDR='https://raven.tailf4bdfc.ts.net:9443')
    fd=os.open(ROOT/'master-password',os.O_RDONLY|os.O_NOFOLLOW);os.dup2(fd,0);os.close(fd)
    os.execve(BINARY,[str(BINARY),'--telemetry=false','server','--host','127.0.0.1','--port','14321','--mitm-port','14322','--password-stdin'],env)


def api(path,body=None,token=None,base='http://127.0.0.1:14321'):
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
    with urllib.request.urlopen(req,timeout=5) as response:return json.load(response)


def ready():
    result={'state':'needs_attention','engine':False,'frontend':False,'buildVerified':False,'privateInputProtected':False,
            'vaultAccess':False,'temporarySessionRevoked':False,'rebootObserved':False}
    try:verify_unlock();result['privateInputProtected']=True
    except Exception:result['state']='needs_private_unlock';return result
    try:result['engine']=api('/health').get('status')=='ok'
    except Exception:return result
    try:
        cfg=configuration();release=Path(cfg['frontend'])
        result['buildVerified']=all(hashlib.sha256((release/name).read_bytes()).hexdigest()==digest for name,digest in cfg['frontendFiles'].items())
        result['frontend']=api('/health',base='http://127.0.0.1:14421').get('status')=='ok'
    except Exception:pass
    token=None
    try:
        owner=json.loads(private_read(ROOT/'demo-owner.json'))
        token=api('/v1/auth/login',{'email':owner['email'],'password':owner['password'],'device_label':'Vault2 local readiness'})['token']
        me=api('/v1/auth/me',token=token)
        context=api('/v1/vaults/bitwarden-import/context',token=token)
        keys=api('/v1/credentials?vault=bitwarden-import',token=token)['keys']
        result['vaultAccess']=me['email']==owner['email'] and me['role']=='owner' and context['vault_role']=='admin'
        result['importedFields']=len(keys)
    except Exception:pass
    finally:
        if token:
            try:
                api('/v1/auth/logout',{},token)
                try:api('/v1/auth/me',token=token)
                except urllib.error.HTTPError as e:result['temporarySessionRevoked']=e.code==401
            except Exception:pass
    if all(result[k] for k in ('engine','frontend','buildVerified','vaultAccess','temporarySessionRevoked')):result['state']='ready'
    return result


def launchctl(*args,check=True):
    return subprocess.run(['/bin/launchctl',*args],check=check,capture_output=True,text=True)


def install(candidate):
    validate_state();private_dir(SERVICE)
    source=Path(__file__).resolve().parent
    repo=source.parents[1]
    pin=json.loads((repo/'branding/vault2/upstream.json').read_text())
    if subprocess.check_output(['git','-C',str(candidate),'rev-parse','HEAD'],text=True).strip()!=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip():raise ValueError('candidate_pin_mismatch')
    dist=candidate/'internal/server/webdist'
    if not (dist/'index.html').is_file() or '<title>Vault 2</title>' not in (dist/'index.html').read_text():raise ValueError('frontend_missing')
    digest=hashlib.sha256((repo/'branding/vault2/source.patch').read_bytes()).hexdigest()
    private_dir(SERVICE/'releases');release=SERVICE/'releases'/digest
    if release.exists():raise ValueError('release_already_installed')
    shutil.copytree(dist,release)
    for p in [release,*release.rglob('*')]:
        if p.is_symlink():raise ValueError('frontend_symlink')
        p.chmod(0o700 if p.is_dir() else 0o600)
    private_dir(SERVICE/'bin');private_dir(SERVICE/'logs')
    for name in ('service.py','recovery.py','crypto_native.py','web-server.mjs'):
        private_write(SERVICE/'bin'/name,(source/name).read_bytes())
    cfg={'engineVersion':'v0.40.2','sourceCommit':pin['commit'],'brandPatchSHA256':digest,'frontend':str(release),
         'privateURL':'https://raven.tailf4bdfc.ts.net:9444/','privateUnlock':'existing owner-only input file; no Touch ID',
         'frontendFiles':{str(p.relative_to(release)):hashlib.sha256(p.read_bytes()).hexdigest() for p in release.rglob('*') if p.is_file()}}
    private_write(SERVICE/'configuration.json',json_bytes(cfg))
    agent_dir=Path.home()/'Library/LaunchAgents'
    if not agent_dir.is_dir():raise ValueError('launch_agents_directory_missing')
    programs=([sys.executable,str(SERVICE/'bin/service.py'),'run-engine'],[str(Path.home()/'.bun/bin/bun'),str(SERVICE/'bin/web-server.mjs'),str(release)])
    for label,program in zip(LABELS,programs):
        path=agent_dir/(label+'.plist')
        if path.exists():raise ValueError('launch_agent_already_exists')
        log=SERVICE/'logs'/(label+'.log');private_write(log,b'')
        value={'Label':label,'ProgramArguments':program,'WorkingDirectory':str(SERVICE),
               'RunAtLoad':True,'KeepAlive':{'SuccessfulExit':False},'ThrottleInterval':30,
               'ProcessType':'Background','ExitTimeOut':20,'Umask':0o077,'StandardOutPath':str(log),'StandardErrorPath':str(log)}
        private_write(path,plistlib.dumps(value))
    command=Path.home()/'.local/bin/vault2'
    if command.exists() or command.is_symlink():raise ValueError('command_already_exists')
    command.write_text('#!/bin/sh\nexec '+shlex_quote(sys.executable)+' '+shlex_quote(str(SERVICE/'bin/service.py'))+' "$@"\n')
    command.chmod(0o700)
    return {'installed':True,'servicesLoaded':False,'frontendCopiedOutsideCheckout':True,'engineRebuilt':False}


def shlex_quote(value):
    import shlex
    return shlex.quote(value)


def control(action):
    started=time.monotonic()
    if action in ('stop','restart'):
        for label in reversed(LABELS):launchctl('bootout',DOMAIN+'/'+label,check=False)
        for _ in range(100):
            listening=False
            for port in (14321,14421):
                with socket.socket() as s:
                    s.settimeout(0.1)
                    listening |= s.connect_ex(('127.0.0.1',port))==0
            removed=all(launchctl('print',DOMAIN+'/'+label,check=False).returncode!=0 for label in LABELS)
            if not listening and removed:break
            time.sleep(0.1)
        else:raise ValueError('services_did_not_stop')
    if action in ('start','restart'):
        for label in LABELS:
            if launchctl('print',DOMAIN+'/'+label,check=False).returncode!=0:
                launchctl('bootstrap',DOMAIN,str(Path.home()/'Library/LaunchAgents'/(label+'.plist')))
        for _ in range(80):
            try:
                if api('/health').get('status')=='ok' and api('/health',base='http://127.0.0.1:14421').get('status')=='ok':break
            except Exception:pass
            time.sleep(0.1)
        result=ready()
        if result['state']!='ready':raise ValueError('startup_not_ready')
    else:result={'state':'stopped'}
    return {'action':action,'elapsedMilliseconds':round((time.monotonic()-started)*1000),**result}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['install','run-engine','ready','start','stop','restart','backup','verify-backup']);parser.add_argument('--candidate',type=Path)
    parser.add_argument('--backup',type=Path);parser.add_argument('--key-file',type=Path);parser.add_argument('--destination',type=Path)
    args=parser.parse_args()
    try:
        if args.action=='run-engine':run_engine();return
        if args.action=='install':result=install(args.candidate.resolve())
        elif args.action=='ready':result=ready()
        elif args.action=='backup':
            from recovery import create
            result=create()
        elif args.action=='verify-backup':
            from recovery import verify
            result=verify(args.backup.expanduser(),args.key_file.expanduser(),args.destination.expanduser())
        else:result=control(args.action)
        print(json.dumps(result,indent=2))
        if args.action=='ready' and result['state']!='ready':sys.exit(1)
    except Exception as error:
        known={'state_binding_mismatch','password_protected_state_required','owner_missing','needs_private_unlock',
               'binary_pin_mismatch','services_did_not_stop','startup_not_ready','candidate_pin_mismatch',
               'frontend_missing','release_already_installed','launch_agent_already_exists','command_already_exists'}
        reason=str(error) if isinstance(error,ValueError) and str(error) in known else 'private_startup_check_failed'
        print(json.dumps({'state':'needs_attention','reason':reason,'privateInputsNotPrinted':True}));sys.exit(1)


if __name__=='__main__':main()
