# SPDX-License-Identifier: GPL-3.0-only
"""Focused recovery/startup safety checks; these do not establish live acceptance."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from crypto_native import Crypto
from recovery import private_read, private_write
import service


class RecoverySafety(unittest.TestCase):
    def test_authenticated_recovery_rejects_wrong_key_and_changed_data(self):
        crypto=Crypto();key=bytes(range(32));nonce=bytes(range(12))
        value=crypto.gcm(key,nonce,b'synthetic recovery fixture')
        self.assertEqual(crypto.gcm(key,nonce,value,True),b'synthetic recovery fixture')
        for wrong_key,data in ((bytes(32),value),(key,value[:-1]+bytes([value[-1]^1]))):
            with self.assertRaises(ValueError):crypto.gcm(wrong_key,nonce,data,True)

    def test_recovery_key_permissions_and_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'fixture.key';private_write(p,b'synthetic-key')
            self.assertEqual(private_read(p),b'synthetic-key')
            with self.assertRaises(FileExistsError):private_write(p,b'replacement')
            p.chmod(0o644)
            with self.assertRaises(ValueError):private_read(p)
            p.chmod(0o600);link=Path(directory)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):private_read(link)

    def test_missing_state_cannot_create_or_start_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'missing'
            with patch.object(service,'ROOT',root),patch.object(service.os,'execve') as execute:
                with self.assertRaises(ValueError):service.run_engine()
                execute.assert_not_called()
                self.assertFalse(root.exists())


if __name__=='__main__':unittest.main()
