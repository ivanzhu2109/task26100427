"""AES-256-GCM 分块流式加解密。

密文格式：
    header: MAGIC(8B) | version(1B) | chunk_size(4B, big endian)
    每块:   nonce(12B) | ciphertext(chunk_size B, 最后一块可能更短) | tag(16B)
每块独立认证，任何一字节损坏都会在解密时被 CorruptCiphertextError 报告。
分块使单文件处理内存与文件大小无关，峰值约为一个块的大小。
"""

import os
import struct
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import CorruptCiphertextError

CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB，远低于 64 MiB 内存约束

_MAGIC = b"FPROT001"
_VERSION = 1
_NONCE_LEN = 12
_TAG_LEN = 16
_HEADER_LEN = len(_MAGIC) + 1 + 4


def generate_key() -> bytes:
    """生成一个新的 256 位密钥。"""
    return AESGCM.generate_key(bit_length=256)


def encrypt_stream(key: bytes, src: BinaryIO, dst: BinaryIO,
                   chunk_size: int = CHUNK_SIZE) -> None:
    """把 src 的明文流加密写入 dst。"""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes (AES-256)")
    aes = AESGCM(key)
    dst.write(_MAGIC)
    dst.write(bytes([_VERSION]))
    dst.write(struct.pack(">I", chunk_size))
    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            break
        nonce = os.urandom(_NONCE_LEN)
        ct = aes.encrypt(nonce, chunk, None)
        dst.write(nonce)
        dst.write(ct)


def _read_exact(src: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf.extend(part)
    return bytes(buf)


def decrypt_stream(key: bytes, src: BinaryIO, dst: BinaryIO) -> None:
    """把 src 的密文流解密写入 dst，损坏时抛 CorruptCiphertextError。"""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes (AES-256)")
    aes = AESGCM(key)
    header = _read_exact(src, _HEADER_LEN)
    if len(header) != _HEADER_LEN or not header.startswith(_MAGIC):
        raise CorruptCiphertextError("bad ciphertext header")
    version = header[len(_MAGIC)]
    if version != _VERSION:
        raise CorruptCiphertextError(f"unsupported version {version}")
    (chunk_size,) = struct.unpack(">I", header[len(_MAGIC) + 1:])
    if chunk_size <= 0 or chunk_size > 64 * 1024 * 1024:
        raise CorruptCiphertextError("invalid chunk size")
    while True:
        nonce = _read_exact(src, _NONCE_LEN)
        if not nonce:
            break
        if len(nonce) != _NONCE_LEN:
            raise CorruptCiphertextError("truncated chunk nonce")
        body = _read_exact(src, chunk_size + _TAG_LEN)
        if len(body) < _TAG_LEN + 1:
            raise CorruptCiphertextError("truncated chunk body")
        try:
            plain = aes.decrypt(nonce, body, None)
        except Exception as exc:
            raise CorruptCiphertextError("chunk authentication failed") from exc
        dst.write(plain)


def reencrypt_stream(old_key: bytes, new_key: bytes, src: BinaryIO,
                     dst: BinaryIO) -> None:
    """把 src 的密文用新密钥重加密写入 dst，全程流式、无中间明文落盘。"""
    if len(old_key) != 32 or len(new_key) != 32:
        raise ValueError("keys must be 32 bytes (AES-256)")
    old_aes = AESGCM(old_key)
    new_aes = AESGCM(new_key)
    header = _read_exact(src, _HEADER_LEN)
    if len(header) != _HEADER_LEN or not header.startswith(_MAGIC):
        raise CorruptCiphertextError("bad ciphertext header")
    version = header[len(_MAGIC)]
    if version != _VERSION:
        raise CorruptCiphertextError(f"unsupported version {version}")
    (chunk_size,) = struct.unpack(">I", header[len(_MAGIC) + 1:])
    if chunk_size <= 0 or chunk_size > 64 * 1024 * 1024:
        raise CorruptCiphertextError("invalid chunk size")
    dst.write(_MAGIC)
    dst.write(bytes([_VERSION]))
    dst.write(struct.pack(">I", chunk_size))
    while True:
        nonce = _read_exact(src, _NONCE_LEN)
        if not nonce:
            break
        if len(nonce) != _NONCE_LEN:
            raise CorruptCiphertextError("truncated chunk nonce")
        body = _read_exact(src, chunk_size + _TAG_LEN)
        if len(body) < _TAG_LEN + 1:
            raise CorruptCiphertextError("truncated chunk body")
        try:
            plain = old_aes.decrypt(nonce, body, None)
        except Exception as exc:
            raise CorruptCiphertextError("chunk authentication failed") from exc
        new_nonce = os.urandom(_NONCE_LEN)
        dst.write(new_nonce)
        dst.write(new_aes.encrypt(new_nonce, plain, None))
