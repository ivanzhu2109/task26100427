"""FileProtector: public API of the local file protection library.

Directory layout under the managed root:
    protect.db   SQLite: keys, file registry, rotation records
    data/        committed ciphertexts, one per (file, generation)
    tmp/         transient ciphertexts (never plaintext)

Crash-safety invariants:
  * A ciphertext is written to tmp/, fsynced, then atomically renamed into
    data/ before the matching SQLite row is updated (synchronous=FULL).
  * The old ciphertext is deleted only after the new generation is committed
    in SQLite, so the generation recorded in the DB always has a complete
    ciphertext on disk.
  * Reopening the library deletes stray ciphertexts/temp files and finishes
    any pending post-rotation cleanup; both are idempotent.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from . import crypto
from .db import Database

_DB_NAME = "protect.db"
_DATA_DIR = "data"
_TMP_DIR = "tmp"


@dataclass
class RotationResult:
    rotation_id: str
    target_generation: int
    total: int
    completed: int
    success: bool


@dataclass
class Status:
    rotation_id: str | None
    target_generation: int | None
    completed: int
    total: int
    success: bool
    key_generations: list[int] = field(default_factory=list)


def _encode_id(file_id: str) -> str:
    encoded = base64.urlsafe_b64encode(file_id.encode("utf-8")).decode("ascii")
    if len(encoded) <= 200:
        return encoded
    # Very long ids would exceed filename limits; use a stable digest instead.
    return "h-" + hashlib.sha256(file_id.encode("utf-8")).hexdigest()


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class FileProtector:
    def __init__(self, directory: str | Path) -> None:
        self._root = Path(directory)
        self._data = self._root / _DATA_DIR
        self._tmp = self._root / _TMP_DIR
        self._data.mkdir(parents=True, exist_ok=True)
        self._tmp.mkdir(parents=True, exist_ok=True)
        self._db = Database(self._root / _DB_NAME)
        self._db.ensure_initial_generation(crypto.generate_key())
        self._recover()

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "FileProtector":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _crash_point(self, name: str) -> None:
        """Test hook: no-op in production, lets tests simulate a hard crash."""

    # -- recovery ----------------------------------------------------------
    def _recover(self) -> None:
        self._clean_tmp()
        self._crash_point("recover_tmp_cleaned")
        self._reconcile_data()
        self._crash_point("recover_reconciled")
        latest = self._db.latest_rotation()
        if latest is not None and latest["status"] == "success":
            self._remove_stale_keys()
            self._crash_point("recover_keys_removed")

    def _clean_tmp(self) -> None:
        for entry in self._tmp.iterdir():
            if entry.is_file():
                entry.unlink()
        _fsync_dir(self._tmp)

    def _expected_names(self) -> dict[str, str]:
        """Map ciphertext filename -> file_id for DB-committed generations."""
        return {
            self._cipher_name(file_id, generation): file_id
            for file_id, generation, _size, _sha in self._db.list_files()
        }

    def _reconcile_data(self) -> None:
        expected = self._expected_names()
        changed = False
        for entry in self._data.iterdir():
            if entry.is_file() and entry.name not in expected:
                entry.unlink()  # stray ciphertext from an interrupted rotation
                changed = True
                self._crash_point("recover_stray_deleted")
        if changed:
            _fsync_dir(self._data)
        for name in expected:
            if not (self._data / name).is_file():
                raise RuntimeError(
                    f"missing ciphertext for committed record: {name}"
                )

    def _remove_stale_keys(self) -> None:
        current = self._db.current_generation()
        for generation in self._db.key_generations():
            if generation != current:
                self._db.remove_key(generation)

    # -- naming ------------------------------------------------------------
    @staticmethod
    def _cipher_name(file_id: str, generation: int) -> str:
        return f"{_encode_id(file_id)}.g{generation}.enc"

    def _cipher_path(self, file_id: str, generation: int) -> Path:
        return self._data / self._cipher_name(file_id, generation)

    def _tmp_path(self) -> Path:
        return self._tmp / f"{secrets.token_hex(16)}.tmp"

    def _commit_ciphertext(self, tmp: Path, file_id: str, generation: int) -> Path:
        final = self._cipher_path(file_id, generation)
        os.replace(tmp, final)
        _fsync_dir(self._data)
        return final

    # -- public API --------------------------------------------------------
    def import_file(self, file_id: str, source: str | Path) -> None:
        if any(f[0] == file_id for f in self._db.list_files()):
            raise ValueError(f"file_id already imported: {file_id!r}")
        generation = self._db.current_generation()
        key = self._db.get_key(generation)
        tmp = self._tmp_path()
        try:
            size, sha256 = crypto.encrypt_file(key, Path(source), tmp)
            self._commit_ciphertext(tmp, file_id, generation)
            self._db.add_file(file_id, generation, size, sha256)
        finally:
            tmp.unlink(missing_ok=True)

    def read_file(self, file_id: str, dst: BinaryIO | None = None) -> bytes | None:
        record = self._file_record(file_id)
        if record is None:
            raise KeyError(f"unknown file_id: {file_id!r}")
        _fid, generation, _size, _sha = record
        key = self._db.get_key(generation)
        cipher_path = self._cipher_path(file_id, generation)
        if dst is not None:
            crypto.decrypt_file(key, cipher_path, dst)
            return None
        import io

        buffer = io.BytesIO()
        crypto.decrypt_file(key, cipher_path, buffer)
        return buffer.getvalue()

    def rotate(self, rotation_id: str) -> RotationResult:
        rotation = self._db.get_rotation(rotation_id)
        if rotation is not None and rotation["status"] == "success":
            return RotationResult(
                rotation_id=rotation_id,
                target_generation=rotation["target_generation"],
                total=rotation["total"],
                completed=rotation["total"],
                success=True,
            )
        if rotation is None:
            running = [
                r
                for r in (self._db.latest_rotation(),)
                if r is not None and r["status"] == "running"
            ]
            if running:
                raise RuntimeError(
                    f"rotation {running[0]['rotation_id']!r} still in progress"
                )
            target = self._db.current_generation() + 1
            total = len(self._db.list_files())
            self._db.start_rotation(rotation_id, target, crypto.generate_key(), total)
            rotation = self._db.get_rotation(rotation_id)
        target = rotation["target_generation"]
        new_key = self._db.get_key(target)
        for file_id, generation, _size, _sha in self._db.list_files():
            if generation == target:
                continue  # already switched in a previous attempt
            self._rotate_file(file_id, generation, target, new_key)
        self._finalize_rotation(rotation_id, target)
        total = rotation["total"]
        return RotationResult(
            rotation_id=rotation_id,
            target_generation=target,
            total=total,
            completed=total,
            success=True,
        )

    def status(self) -> Status:
        latest = self._db.latest_rotation()
        generations = self._db.key_generations()
        if latest is None:
            return Status(
                rotation_id=None,
                target_generation=None,
                completed=0,
                total=0,
                success=False,
                key_generations=generations,
            )
        target = latest["target_generation"]
        return Status(
            rotation_id=latest["rotation_id"],
            target_generation=target,
            completed=self._db.count_files_at(target),
            total=latest["total"],
            success=latest["status"] == "success",
            key_generations=generations,
        )

    # -- rotation internals --------------------------------------------------
    def _file_record(self, file_id: str):
        for record in self._db.list_files():
            if record[0] == file_id:
                return record
        return None

    def _rotate_file(
        self, file_id: str, old_generation: int, target: int, new_key: bytes
    ) -> None:
        old_key = self._db.get_key(old_generation)
        old_path = self._cipher_path(file_id, old_generation)
        tmp = self._tmp_path()
        try:
            crypto.encrypt_stream(new_key, crypto.iter_decrypt(old_key, old_path), tmp)
            self._crash_point("tmp_written")
            self._commit_ciphertext(tmp, file_id, target)
            self._crash_point("renamed")
            self._db.set_file_generation(file_id, target)
            self._crash_point("db_committed")
            old_path.unlink(missing_ok=True)
            _fsync_dir(self._data)
            self._crash_point("old_deleted")
        finally:
            tmp.unlink(missing_ok=True)

    def _finalize_rotation(self, rotation_id: str, target: int) -> None:
        self._db.mark_rotation_success(rotation_id, target)
        self._crash_point("success_marked")
        self._remove_stale_keys()
        self._crash_point("keys_removed")
        self._clean_tmp()
        self._reconcile_data()
