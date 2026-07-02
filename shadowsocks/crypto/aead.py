#!/usr/bin/env python
#
# Shadowsocks AEAD ciphers (SIP004) support.

from __future__ import absolute_import, division, print_function, \
    with_statement

import hmac
import hashlib
import struct
from ctypes import byref, c_char_p, c_int, c_void_p, create_string_buffer

from shadowsocks import common
from shadowsocks.crypto import openssl

__all__ = ['ciphers', 'is_aead_cipher', 'encrypt_packet', 'decrypt_packet']

TAG_SIZE = 16
NONCE_SIZE = 12
MAX_CHUNK_SIZE = 0x3fff
SUBKEY_INFO = b'ss-subkey'

EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11


cipher_key_salt_len = {
    'aes-128-gcm': (16, 16),
    'aes-256-gcm': (32, 32),
}


def _ensure_openssl():
    if not openssl.loaded:
        openssl.load_openssl()
    lib = openssl.libcrypto

    lib.EVP_EncryptInit_ex.restype = c_int
    lib.EVP_EncryptInit_ex.argtypes = (c_void_p, c_void_p, c_void_p,
                                       c_char_p, c_char_p)
    lib.EVP_DecryptInit_ex.restype = c_int
    lib.EVP_DecryptInit_ex.argtypes = (c_void_p, c_void_p, c_void_p,
                                       c_char_p, c_char_p)
    lib.EVP_EncryptUpdate.restype = c_int
    lib.EVP_EncryptUpdate.argtypes = (c_void_p, c_void_p, c_void_p,
                                      c_char_p, c_int)
    lib.EVP_DecryptUpdate.restype = c_int
    lib.EVP_DecryptUpdate.argtypes = (c_void_p, c_void_p, c_void_p,
                                      c_char_p, c_int)
    lib.EVP_EncryptFinal_ex.restype = c_int
    lib.EVP_EncryptFinal_ex.argtypes = (c_void_p, c_void_p, c_void_p)
    lib.EVP_DecryptFinal_ex.restype = c_int
    lib.EVP_DecryptFinal_ex.argtypes = (c_void_p, c_void_p, c_void_p)
    lib.EVP_CIPHER_CTX_ctrl.restype = c_int
    lib.EVP_CIPHER_CTX_ctrl.argtypes = (c_void_p, c_int, c_int, c_void_p)
    return lib


def _hkdf_sha1(secret, salt, info, length):
    secret = common.to_bytes(secret)
    salt = common.to_bytes(salt)
    prk = hmac.new(salt, secret, hashlib.sha1).digest()
    okm = b''
    prev = b''
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + common.chr(counter),
                        hashlib.sha1).digest()
        okm += prev
        counter += 1
    return okm[:length]


def _increment_nonce(nonce):
    for i in range(len(nonce)):
        nonce[i] = (nonce[i] + 1) & 0xff
        if nonce[i] != 0:
            break


def _get_cipher(method):
    lib = _ensure_openssl()
    cipher = lib.EVP_get_cipherbyname(common.to_bytes(method))
    if not cipher:
        cipher = openssl.load_cipher(method)
    if not cipher:
        raise Exception('cipher %s not found in libcrypto' % method)
    return lib, cipher


def _seal(method, key, nonce, data):
    data = common.to_bytes(data)
    nonce = bytes(nonce)
    lib, cipher = _get_cipher(method)
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise Exception('can not create cipher context')
    try:
        if not lib.EVP_EncryptInit_ex(ctx, cipher, None, None, None):
            raise Exception('can not initialize AEAD cipher')
        if not lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                       len(nonce), None):
            raise Exception('can not set AEAD nonce length')
        if not lib.EVP_EncryptInit_ex(ctx, None, None, c_char_p(key),
                                      c_char_p(nonce)):
            raise Exception('can not set AEAD key/nonce')

        out = create_string_buffer(max(len(data), 1) + TAG_SIZE)
        out_len = c_int(0)
        if data and not lib.EVP_EncryptUpdate(ctx, out, byref(out_len),
                                              c_char_p(data), len(data)):
            raise Exception('AEAD encrypt update failed')

        final = create_string_buffer(TAG_SIZE)
        final_len = c_int(0)
        if not lib.EVP_EncryptFinal_ex(ctx, final, byref(final_len)):
            raise Exception('AEAD encrypt final failed')

        tag = create_string_buffer(TAG_SIZE)
        if not lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                                       tag):
            raise Exception('can not get AEAD tag')
        return out.raw[:out_len.value] + final.raw[:final_len.value] + tag.raw
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def _open(method, key, nonce, data):
    data = common.to_bytes(data)
    if len(data) < TAG_SIZE:
        raise Exception('AEAD ciphertext is too short')
    nonce = bytes(nonce)
    ciphertext = data[:-TAG_SIZE]
    tag = data[-TAG_SIZE:]
    lib, cipher = _get_cipher(method)
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise Exception('can not create cipher context')
    try:
        if not lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None):
            raise Exception('can not initialize AEAD cipher')
        if not lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                       len(nonce), None):
            raise Exception('can not set AEAD nonce length')
        if not lib.EVP_DecryptInit_ex(ctx, None, None, c_char_p(key),
                                      c_char_p(nonce)):
            raise Exception('can not set AEAD key/nonce')

        out = create_string_buffer(max(len(ciphertext), 1) + TAG_SIZE)
        out_len = c_int(0)
        if ciphertext and not lib.EVP_DecryptUpdate(
                ctx, out, byref(out_len), c_char_p(ciphertext),
                len(ciphertext)):
            raise Exception('AEAD decrypt update failed')

        tag_buf = create_string_buffer(tag, TAG_SIZE)
        if not lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                                       tag_buf):
            raise Exception('can not set AEAD tag')

        final = create_string_buffer(TAG_SIZE)
        final_len = c_int(0)
        if lib.EVP_DecryptFinal_ex(ctx, final, byref(final_len)) <= 0:
            raise Exception('AEAD authentication failed')
        return out.raw[:out_len.value] + final.raw[:final_len.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def is_aead_cipher(method):
    return method.lower() in cipher_key_salt_len


def make_subkey(method, master_key, salt):
    key_len, _ = cipher_key_salt_len[method.lower()]
    return _hkdf_sha1(master_key, salt, SUBKEY_INFO, key_len)


def encrypt_packet(method, master_key, salt, data, with_salt=True):
    method = method.lower()
    subkey = make_subkey(method, master_key, salt)
    result = _seal(method, subkey, b'\x00' * NONCE_SIZE, data)
    if with_salt:
        return salt + result
    return result


def decrypt_packet(method, master_key, data):
    method = method.lower()
    _, salt_len = cipher_key_salt_len[method]
    if len(data) < salt_len + TAG_SIZE:
        raise Exception('AEAD packet is too short')
    salt = data[:salt_len]
    subkey = make_subkey(method, master_key, salt)
    return _open(method, subkey, b'\x00' * NONCE_SIZE, data[salt_len:]), salt


class AeadCrypto(object):
    def __init__(self, cipher_name, key, salt, op):
        self._cipher_name = cipher_name
        self._key = make_subkey(cipher_name, key, salt)
        self._op = op
        self._nonce = bytearray(NONCE_SIZE)
        self._buffer = b''

    def update(self, data):
        if self._op:
            return self._encrypt_chunks(data)
        return self._decrypt_chunks(data)

    def _encrypt_chunks(self, data):
        data = common.to_bytes(data)
        result = []
        while data:
            chunk = data[:MAX_CHUNK_SIZE]
            data = data[MAX_CHUNK_SIZE:]
            result.append(_seal(self._cipher_name, self._key, self._nonce,
                                struct.pack('>H', len(chunk))))
            _increment_nonce(self._nonce)
            result.append(_seal(self._cipher_name, self._key, self._nonce,
                                chunk))
            _increment_nonce(self._nonce)
        return b''.join(result)

    def _decrypt_chunks(self, data):
        self._buffer += common.to_bytes(data)
        result = []
        while True:
            if len(self._buffer) < 2 + TAG_SIZE:
                break
            enc_len = self._buffer[:2 + TAG_SIZE]
            length = struct.unpack('>H', _open(self._cipher_name, self._key,
                                               self._nonce, enc_len))[0]
            if length > MAX_CHUNK_SIZE:
                raise Exception('AEAD chunk is too large')
            if len(self._buffer) < 2 + TAG_SIZE + length + TAG_SIZE:
                break
            self._buffer = self._buffer[2 + TAG_SIZE:]
            _increment_nonce(self._nonce)

            enc_payload = self._buffer[:length + TAG_SIZE]
            result.append(_open(self._cipher_name, self._key, self._nonce,
                                enc_payload))
            self._buffer = self._buffer[length + TAG_SIZE:]
            _increment_nonce(self._nonce)
        return b''.join(result)


ciphers = {
    'aes-128-gcm': (16, 16, AeadCrypto),
    'aes-256-gcm': (32, 32, AeadCrypto),
}
