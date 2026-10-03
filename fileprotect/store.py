"""SQLite 持久化：密钥代次、文件记录、轮换状态。

设计要点：
- 每次文件代次切换都独立提交，崩溃后已提交进度不丢失。
- 轮换完成与旧密钥删除在同一个事务里，不会出现“轮换标记完成但旧密钥还在”
  或反过来的中间态。
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    generation INTEGER PRIMARY KEY,
    key BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    file_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rotations (
    rotation_id TEXT PRIMARY KEY,
    target_generation INTEGER NOT NULL,
    status TEXT NOT NULL,            -- 'in_progress' | 'done'
    completed INTEGER NOT NULL,
    total INTEGER NOT NULL
);
"""


@dataclass
class FileRecord:
    file_id: str
    generation: int


@dataclass
class RotationRecord:
    rotation_id: str
    target_generation: int
    status: str  # 'in_progress' | 'done'
    completed: int
    total: int


class Store:
    """封装 vault.db 的全部读写。"""

    def __init__(self, db_path: Path) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ---- 密钥代次 ----

    def latest_generation(self) -> Optional[int]:
        row = self._conn.execute("SELECT MAX(generation) FROM keys").fetchone()
        return row[0] if row and row[0] is not None else None

    def available_generations(self) -> List[int]:
        rows = self._conn.execute(
            "SELECT generation FROM keys ORDER BY generation").fetchall()
        return [r[0] for r in rows]

    def get_key(self, generation: int) -> Optional[bytes]:
        row = self._conn.execute(
            "SELECT key FROM keys WHERE generation = ?", (generation,)).fetchone()
        return bytes(row[0]) if row else None

    def add_key(self, generation: int, key: bytes) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO keys(generation, key) VALUES (?, ?)",
                (generation, key))

    def ensure_initial_key(self, key: bytes) -> int:
        """没有任何密钥代次时建立第 1 代，返回当前最新代次。"""
        gen = self.latest_generation()
        if gen is None:
            self.add_key(1, key)
            return 1
        return gen

    # ---- 文件记录 ----

    def add_file(self, file_id: str, generation: int) -> bool:
        """登记文件；已存在返回 False。"""
        with self._conn:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO files(file_id, generation) VALUES (?, ?)",
                (file_id, generation))
        return cur.rowcount > 0

    def get_file(self, file_id: str) -> Optional[FileRecord]:
        row = self._conn.execute(
            "SELECT file_id, generation FROM files WHERE file_id = ?",
            (file_id,)).fetchone()
        return FileRecord(row[0], row[1]) if row else None

    def all_files(self) -> List[FileRecord]:
        rows = self._conn.execute(
            "SELECT file_id, generation FROM files ORDER BY file_id").fetchall()
        return [FileRecord(r[0], r[1]) for r in rows]

    def file_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def set_file_generation(self, file_id: str, generation: int) -> None:
        """切换单个文件的代次，立即独立提交。"""
        with self._conn:
            self._conn.execute(
                "UPDATE files SET generation = ? WHERE file_id = ?",
                (generation, file_id))

    def count_files_at(self, generation: int) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM files WHERE generation = ?",
            (generation,)).fetchone()[0]

    # ---- 轮换 ----

    def get_rotation(self, rotation_id: str) -> Optional[RotationRecord]:
        row = self._conn.execute(
            "SELECT rotation_id, target_generation, status, completed, total"
            " FROM rotations WHERE rotation_id = ?", (rotation_id,)).fetchone()
        return RotationRecord(*row) if row else None

    def latest_rotation(self) -> Optional[RotationRecord]:
        row = self._conn.execute(
            "SELECT rotation_id, target_generation, status, completed, total"
            " FROM rotations ORDER BY rowid DESC LIMIT 1").fetchone()
        return RotationRecord(*row) if row else None

    def create_rotation(self, rotation_id: str, target_generation: int,
                        total: int) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO rotations(rotation_id, target_generation, status,"
                " completed, total) VALUES (?, ?, 'in_progress', 0, ?)",
                (rotation_id, target_generation, total))

    def update_rotation_progress(self, rotation_id: str, completed: int) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE rotations SET completed = ? WHERE rotation_id = ?",
                (completed, rotation_id))

    def finish_rotation(self, rotation_id: str, completed: int,
                        keep_generation: int) -> None:
        """同一事务：标记轮换完成并删除其余代次的密钥。"""
        with self._conn:
            self._conn.execute(
                "UPDATE rotations SET status = 'done', completed = ?"
                " WHERE rotation_id = ?", (completed, rotation_id))
            self._conn.execute(
                "DELETE FROM keys WHERE generation != ?", (keep_generation,))

    def begin_rotation(self, rotation_id: str, key: bytes) -> int:
        """同一事务：建立新密钥代次并登记轮换，返回新代次号。"""
        with self._conn:
            row = self._conn.execute("SELECT MAX(generation) FROM keys").fetchone()
            gen = (row[0] or 0) + 1
            self._conn.execute(
                "INSERT INTO keys(generation, key) VALUES (?, ?)", (gen, key))
            self._conn.execute(
                "INSERT INTO rotations(rotation_id, target_generation, status,"
                " completed, total)"
                " VALUES (?, ?, 'in_progress', 0,"
                "  (SELECT COUNT(*) FROM files))", (rotation_id, gen))
        return gen
