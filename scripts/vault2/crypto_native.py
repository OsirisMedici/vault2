# SPDX-License-Identifier: GPL-3.0-only
"""Recovery-only OpenSSL bindings. No key, plaintext or native errors are logged."""

import ctypes as C
from pathlib import Path


class Param(C.Structure):
    _fields_ = [("key", C.c_char_p), ("data_type", C.c_uint), ("data", C.c_void_p),
                ("data_size", C.c_size_t), ("return_size", C.c_size_t)]


class Crypto:
    def __init__(self, library=None):
        path = library or Path.home() / ".homebrew/opt/openssl@3/lib/libcrypto.3.dylib"
        self.lib = C.CDLL(str(path))
        signatures = {
            "EVP_KDF_fetch": ([C.c_void_p, C.c_char_p, C.c_char_p], C.c_void_p),
            "EVP_KDF_CTX_new": ([C.c_void_p], C.c_void_p),
            "EVP_KDF_free": ([C.c_void_p], None),
            "EVP_KDF_CTX_free": ([C.c_void_p], None),
            "EVP_KDF_derive": ([C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(Param)], C.c_int),
            "EVP_CIPHER_CTX_new": ([], C.c_void_p),
            "EVP_CIPHER_CTX_free": ([C.c_void_p], None),
            "EVP_aes_256_gcm": ([], C.c_void_p),
            "EVP_CIPHER_CTX_ctrl": ([C.c_void_p, C.c_int, C.c_int, C.c_void_p], C.c_int),
        }
        for action in ("Encrypt", "Decrypt"):
            signatures[f"EVP_{action}Init_ex"] = ([C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p], C.c_int)
            signatures[f"EVP_{action}Update"] = ([C.c_void_p, C.c_void_p, C.POINTER(C.c_int), C.c_void_p, C.c_int], C.c_int)
            signatures[f"EVP_{action}Final_ex"] = ([C.c_void_p, C.c_void_p, C.POINTER(C.c_int)], C.c_int)
        for name, (args, result) in signatures.items():
            f = getattr(self.lib, name); f.argtypes = args; f.restype = result

    @staticmethod
    def check(result):
        if result != 1:
            raise ValueError("cryptographic verification failed")

    def derive(self, password, salt, iterations, memory, lanes):
        if not (1 <= iterations <= 20 and 8 <= memory <= 1048576 and 1 <= lanes <= 32):
            raise ValueError("unsupported recovery KDF parameters")
        buffers = [C.create_string_buffer(password), C.create_string_buffer(salt)]
        integers = [C.c_uint(iterations), C.c_uint(memory), C.c_uint(lanes), C.c_uint(1)]
        params = (Param * 7)()
        for i, (name, buf, size) in enumerate([(b"pass", buffers[0], len(password)), (b"salt", buffers[1], len(salt))]):
            params[i] = Param(name, 5, C.cast(buf, C.c_void_p), size, 0)
        # One execution thread, original lane count: deterministic Argon2id output.
        for i, name in enumerate((b"iter", b"memcost", b"lanes", b"threads"), 2):
            params[i] = Param(name, 2, C.cast(C.pointer(integers[i-2]), C.c_void_p), C.sizeof(C.c_uint), 0)
        kdf = self.lib.EVP_KDF_fetch(None, b"ARGON2ID", None)
        if not kdf:
            raise ValueError("OpenSSL Argon2id unavailable")
        ctx = self.lib.EVP_KDF_CTX_new(kdf)
        out = C.create_string_buffer(32)
        try:
            if not ctx:
                raise ValueError("OpenSSL KDF unavailable")
            self.check(self.lib.EVP_KDF_derive(ctx, out, 32, params))
            return out.raw
        finally:
            if ctx: self.lib.EVP_KDF_CTX_free(ctx)
            self.lib.EVP_KDF_free(kdf)
            for buf in buffers + [out]: C.memset(buf, 0, C.sizeof(buf))

    def gcm(self, key, nonce, data, decrypt=False):
        if len(key) != 32 or len(nonce) != 12 or (decrypt and len(data) < 16):
            raise ValueError("invalid encrypted recovery data")
        ctx = self.lib.EVP_CIPHER_CTX_new()
        if not ctx: raise ValueError("OpenSSL cipher unavailable")
        action = "Decrypt" if decrypt else "Encrypt"
        keybuf, noncebuf = C.create_string_buffer(key), C.create_string_buffer(nonce)
        source = C.create_string_buffer(data[:-16] if decrypt else data)
        out, length, tail = C.create_string_buffer(len(data)+32), C.c_int(), C.c_int()
        tag = C.create_string_buffer(data[-16:] if decrypt else bytes(16))
        try:
            self.check(getattr(self.lib, f"EVP_{action}Init_ex")(ctx, self.lib.EVP_aes_256_gcm(), None, keybuf, noncebuf))
            self.check(getattr(self.lib, f"EVP_{action}Update")(ctx, out, C.byref(length), source, len(data)-16 if decrypt else len(data)))
            if decrypt: self.check(self.lib.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, tag))
            self.check(getattr(self.lib, f"EVP_{action}Final_ex")(ctx, C.byref(out, length.value), C.byref(tail)))
            if not decrypt: self.check(self.lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag))
            result = out.raw[:length.value+tail.value]
            return result if decrypt else result + tag.raw[:16]
        finally:
            self.lib.EVP_CIPHER_CTX_free(ctx)
            for buf in (keybuf, noncebuf, source, out, tag): C.memset(buf, 0, C.sizeof(buf))
