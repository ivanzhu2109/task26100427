"""SQLite persistence layer: keys, files, rotation state.

All mutating multi-statement operations run inside IMMEDIATE transactions so a
crash can never leave a half-applied update.  Per-file rotation progress is
therefore monotonic: a committed file switch can never be rolled back.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION: int = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
    generation INTEGER PRIMARY KEY,
    key        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    file_id    TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    size       INTEGER NOT NULL,
    sha256     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rotations (
    rotation_id       TEXT PRIMARY KEY,
    target_generation INTEGER NOT NULL,
    total             INTEGER NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('running', 'success'))
);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def _get_meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # --- key generations ---
    def current_generation(self) -> int | None:
        value = self._get_meta("current_generation")
        return int(value) if value is not None else None

    def ensure_initial_generation(self, key: bytes) -> int:
        existing = self.current_generation()
        if existing is not None:
            return existing
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute("INSERT INTO keys(generation, key) VALUES(1, ?)", (key,))
            self._set_meta("current_generation", "1")
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return 1

    def add_key(self, generation: int, key: bytes) -> None:
        self._conn.execute(
            "INSERT INTO keys(generation, key) VALUES(?, ?)", (generation, key)
        )

    def get_key(self, generation: int) -> bytes:
        row = self._conn.execute(
            "SELECT key FROM keys WHERE generation = ?", (generation,)
        ).fetchone()
        if row is None:
            raise KeyError(f"no key for generation {generation}")
        return bytes(row[0])

    def key_generations(self) -> list[int]:
        rows = self._conn.execute("SELECT generation FROM keys ORDER BY generation")
        return [r[0] for r in rows]

    def remove_key(self, generation: int) -> None:
        self._conn.execute("DELETE FROM keys WHERE generation = ?", (generation,))

    # --- files ---
    def add_file(self, file_id: str, generation: int, size: int, sha256: str) -> None:
        self._conn.execute(
            "INSERT INTO files(file_id, generation, size, sha256) VALUES(?, ?, ?, ?)",
            (file_id, generation, size, sha256),
        )

    def set_file_generation(self, file_id: str, generation: int) -> None:
        self._conn.execute(
            "UPDATE files SET generation = ? WHERE file_id = ?", (generation, file_id)
        )

    def list_files(self) -> list[tuple[str, int, int, str]]:
        rows = self._conn.execute(
            "SELECT file_id, generation, size, sha256 FROM files ORDER BY file_id"
        )
        return [(r[0], r[1], r[2], r[3]) for r in rows]

    def count_files_at(self, generation: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM files WHERE generation = ?", (generation,)
        ).fetchone()
        return row[0]

    # --- rotations ---
    def get_rotation(self, rotation_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT rotation_id, target_generation, total, status "
            "FROM rotations WHERE rotation_id = ?",
            (rotation_id,),
        ).fetchone()
        return self._rotation_row(row) if row else None

    def latest_rotation(self) -> dict | None:
        row = self._conn.execute(
            "SELECT rotation_id, target_generation, total, status "
            "FROM rotations ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return self._rotation_row(row) if row else None

    @staticmethod
    def _rotation_row(row) -> dict:
        return {
            "rotation_id": row[0],
            "target_generation": row[1],
            "total": row[2],
            "status": row[3],
        }

    def start_rotation(
        self, rotation_id: str, target_generation: int, key: bytes, total: int
    ) -> None:
        """Atomically persist the new key generation and the rotation record."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO keys(generation, key) VALUES(?, ?)",
                (target_generation, key),
            )
            self._conn.execute(
                "INSERT INTO rotations(rotation_id, target_generation, total, status)"
                " VALUES(?, ?, ?, 'running')",
                (rotation_id, target_generation, total),
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def create_rotation(
        self, rotation_id: str, target_generation: int, total: int
    ) -> None:
        self._conn.execute(
            "INSERT INTO rotations(rotation_id, target_generation, total, status) "
            "VALUES(?, ?, ?, 'running')",
            (rotation_id, target_generation, total),
        )

    def mark_rotation_success(self, rotation_id: str, target_generation: int) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE rotations SET status = 'success' WHERE rotation_id = ?",
                (rotation_id,),
            )
            self._set_meta("current_generation", str(target_generation))
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
