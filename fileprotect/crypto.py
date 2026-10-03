"""Chunked AES-256-GCM encryption helpers (streaming, bounded memory).

On-disk format:
    header  = MAGIC(4) | chunk_size(4, BE) | base_nonce(12)
    chunk_i = ciphertext(chunk_size or less for the last one) | GCM tag(16)

The GCM nonce for chunk i is ``base_nonce`` with its last 8 bytes XORed with
the chunk index, so nonces are unique within a file and (via the random
base_nonce) across files.  Each chunk's AAD binds the header, the chunk index
and an "is last" flag, so reordering, truncation and appending are detected.
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import BinaryIO, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE: int = 1 << 20  # 1 MiB plaintext per chunk
MAGIC: bytes = b"FP01"
_TAG_SIZE = 16
_HEADER = struct.Struct(">4sI12s")  # magic, chunk_size, base_nonce
_AAD_SUFFIX = struct.Struct(">QB")  # chunk index, is_last flag


class CorruptCiphertextError(Exception):
    """Raised when ciphertext fails authentication or is malformed."""


def generate_key() -> bytes:
    """Generate a fresh 256-bit data-encryption key."""
    return AESGCM.generate_key(bit_length=256)


def _chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    head, tail = base_nonce[:4], struct.unpack(">Q", base_nonce[4:])[0]
    return head + struct.pack(">Q", tail ^ index)


def _read_exact(stream: BinaryIO, count: int) -> bytes:
    data = stream.read(count)
    if len(data) != count:
        raise CorruptCiphertextError("truncated ciphertext header")
    return data


_EOF = object()


def _as_chunk_iter(src: BinaryIO | Iterator[bytes]) -> Iterator[bytes]:
    if hasattr(src, "read"):
        while True:
            chunk = src.read(CHUNK_SIZE)
            yield chunk
            if len(chunk) < CHUNK_SIZE:
                break
    else:
        yield from src


def encrypt_stream(
    key: bytes, src: BinaryIO | Iterator[bytes], dst: Path
) -> tuple[int, str]:
    """Encrypt all plaintext from src (file object or chunk iterator) into
    dst (fsynced).  Returns (plaintext_size, sha256_hex).
    """
    aes = AESGCM(key)
    base_nonce = os.urandom(12)
    header = _HEADER.pack(MAGIC, CHUNK_SIZE, base_nonce)
    sha = hashlib.sha256()
    total = 0
    index = 0
    iterator = _as_chunk_iter(src)
    pending = next(iterator, _EOF)
    if pending is _EOF:
        pending = b""
        exhausted = True
    else:
        exhausted = False
    with open(dst, "wb") as fout:
        fout.write(header)
        while True:
            nxt = _EOF if exhausted else next(iterator, _EOF)
            is_last = 1 if nxt is _EOF else 0
            aad = header + _AAD_SUFFIX.pack(index, is_last)
            fout.write(aes.encrypt(_chunk_nonce(base_nonce, index), pending, aad))
            sha.update(pending)
            total += len(pending)
            index += 1
            if is_last:
                break
            pending = nxt
        fout.flush()
        os.fsync(fout.fileno())
    return total, sha.hexdigest()


def encrypt_file(key: bytes, src: Path, dst: Path) -> tuple[int, str]:
    """Encrypt src -> dst. Returns (plaintext_size, sha256_hex)."""
    with open(src, "rb") as fin:
        return encrypt_stream(key, fin, dst)


def iter_decrypt(key: bytes, src: Path) -> Iterator[bytes]:
    """Yield plaintext chunks of the ciphertext at src (authenticated)."""
    aes = AESGCM(key)
    with open(src, "rb") as fin:
        header = _read_exact(fin, _HEADER.size)
        magic, chunk_size, base_nonce = _HEADER.unpack(header)
        if magic != MAGIC:
            raise CorruptCiphertextError("bad magic")
        if chunk_size != CHUNK_SIZE:
            raise CorruptCiphertextError("unsupported chunk size")
        index = 0
        while True:
            blob = fin.read(chunk_size + _TAG_SIZE)
            if not blob:
                raise CorruptCiphertextError("missing final chunk")
            is_last = 1 if len(blob) < chunk_size + _TAG_SIZE else 0
            aad = header + _AAD_SUFFIX.pack(index, is_last)
            try:
                chunk = aes.decrypt(_chunk_nonce(base_nonce, index), blob, aad)
            except Exception as exc:
                raise CorruptCiphertextError("authentication failed") from exc
            index += 1
            yield chunk
            if is_last:
                break
        if fin.read(1):
            raise CorruptCiphertextError("trailing data after final chunk")


def decrypt_file(key: bytes, src: Path, dst: BinaryIO) -> tuple[int, str]:
    """Decrypt src into dst (binary stream). Returns (size, sha256_hex)."""
    sha = hashlib.sha256()
    total = 0
    for chunk in iter_decrypt(key, src):
        dst.write(chunk)
        sha.update(chunk)
        total += len(chunk)
    return total, sha.hexdigest()
