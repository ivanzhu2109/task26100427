"""对外主入口：FileProtector。

目录布局（directory 下）：
    vault.db                      SQLite，存密钥代次 / 文件记录 / 轮换状态
    blobs/<hash>.gen<N>.enc       已提交的密文
    blobs/<hash>.gen<N>.tmp       写入中的临时密文（恢复时清除）

其中 <hash> 是 file_id 的 SHA-256，避免把调用方标识直接暴露为文件名，
同时天然免疫路径穿越与非法字符。

崩溃一致性：
- 单文件切换顺序：写 tmp -> fsync -> 原子 rename -> 提交数据库 -> 删旧密文。
  任意点中断后，数据库记录的有效密文始终完整可读；孤儿 tmp/enc 由打开时的
  恢复流程清理。
- 轮换完成：标记 done 与删除旧密钥在同一事务，之后清扫遗留旧密文。
"""

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from . import crypto
from .errors import (CorruptCiphertextError, DuplicateFileError,
                     RotationConflictError, UnknownFileError)
from .store import RotationRecord, Store


@dataclass
class RotationResult:
    rotation_id: str
    target_generation: int
    completed: int
    total: int
    done: bool


@dataclass
class Status:
    rotation_id: Optional[str]
    target_generation: Optional[int]
    completed: int
    total: int
    done: bool
    available_generations: List[int]


def _blob_name(file_id: str, generation: int, suffix: str) -> str:
    digest = hashlib.sha256(file_id.encode("utf-8")).hexdigest()
    return f"{digest}.gen{generation}.{suffix}"


class FileProtector:
    """本地文件保护库：导入、回读、轮换、查询。

    crash_hook: 测试注入点，在关键位置以位置名调用，可抛异常模拟进程被杀。
    """

    def __init__(self, directory: str,
                 crash_hook: Optional[Callable[[str], None]] = None) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._blobs = self._dir / "blobs"
        self._blobs.mkdir(exist_ok=True)
        self._crash_hook = crash_hook or (lambda point: None)
        self._store = Store(self._dir / "vault.db")
        self._recover()

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "FileProtector":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- 打开时恢复 ----

    def _recover(self) -> None:
        self._crash_hook("recover:start")
        files = {f.file_id: f for f in self._store.all_files()}
        known_names = set()
        for rec in files.values():
            name = _blob_name(rec.file_id, rec.generation, "enc")
            if not (self._blobs / name).exists():
                raise CorruptCiphertextError(
                    f"missing ciphertext for {rec.file_id!r}; vault damaged")
            known_names.add(name)
        for entry in self._blobs.iterdir():
            if entry.name.endswith(".tmp"):
                entry.unlink()  # 未提交的临时密文直接丢弃
            elif entry.name.endswith(".enc") and entry.name not in known_names:
                entry.unlink()  # 孤儿密文：旧代次残留或导入中断残留
            self._crash_hook("recover:entry")
        self._crash_hook("recover:done")

    # ---- 导入 ----

    def import_file(self, file_id: str, source_path: str) -> None:
        if self._store.get_file(file_id) is not None:
            raise DuplicateFileError(file_id)
        rotation = self._store.latest_rotation()
        if rotation is not None and rotation.status == "in_progress":
            raise RotationConflictError("rotation in progress; import rejected")
        generation = self._store.latest_generation()
        if generation is None:
            generation = self._store.ensure_initial_key(crypto.generate_key())
        key = self._store.get_key(generation)
        tmp = self._blobs / _blob_name(file_id, generation, "tmp")
        enc = self._blobs / _blob_name(file_id, generation, "enc")
        with open(source_path, "rb") as src, open(tmp, "wb") as dst:
            crypto.encrypt_stream(key, src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp, enc)
        self._fsync_dir()
        if not self._store.add_file(file_id, generation):
            enc.unlink(missing_ok=True)
            raise DuplicateFileError(file_id)

    # ---- 回读 ----

    def read_file(self, file_id: str, dest_path: str) -> None:
        rec = self._store.get_file(file_id)
        if rec is None:
            raise UnknownFileError(file_id)
        key = self._store.get_key(rec.generation)
        if key is None:
            raise CorruptCiphertextError(
                f"key generation {rec.generation} unavailable")
        enc = self._blobs / _blob_name(file_id, rec.generation, "enc")
        with open(enc, "rb") as src, open(dest_path, "wb") as dst:
            crypto.decrypt_stream(key, src, dst)

    # ---- 轮换 ----

    def rotate(self, rotation_id: str) -> RotationResult:
        rec = self._store.get_rotation(rotation_id)
        if rec is not None and rec.status == "done":
            # 同一标识已完成：直接返回原结果，绝不重新加密或回退。
            return RotationResult(rec.rotation_id, rec.target_generation,
                                  rec.completed, rec.total, True)
        if rec is None:
            latest = self._store.latest_rotation()
            if latest is not None and latest.status == "in_progress":
                raise RotationConflictError(
                    f"rotation {latest.rotation_id!r} still in progress")
            target = self._store.begin_rotation(rotation_id,
                                                crypto.generate_key())
            rec = self._store.get_rotation(rotation_id)
        return self._run_rotation(rec)

    def _run_rotation(self, rec: RotationRecord) -> RotationResult:
        target = rec.target_generation
        new_key = self._store.get_key(target)
        for frec in self._store.all_files():
            if frec.generation == target:
                continue  # 已切换的文件在同轮重试时不再加密
            old_key = self._store.get_key(frec.generation)
            old_enc = self._blobs / _blob_name(frec.file_id, frec.generation, "enc")
            tmp = self._blobs / _blob_name(frec.file_id, target, "tmp")
            new_enc = self._blobs / _blob_name(frec.file_id, target, "enc")
            with open(old_enc, "rb") as src, open(tmp, "wb") as dst:
                crypto.reencrypt_stream(old_key, new_key, src, dst)
                dst.flush()
                os.fsync(dst.fileno())
            os.replace(tmp, new_enc)
            self._fsync_dir()
            self._crash_hook("rotate:after_rename")
            self._store.set_file_generation(frec.file_id, target)
            self._crash_hook("rotate:after_commit")
            old_enc.unlink(missing_ok=True)
            done = self._store.count_files_at(target)
            self._store.update_rotation_progress(rec.rotation_id, done)
            self._crash_hook("rotate:after_file")
        total = self._store.file_count()
        self._crash_hook("rotate:before_finish")
        self._store.finish_rotation(rec.rotation_id, total,
                                    keep_generation=target)
        self._crash_hook("rotate:after_finish")
        self._sweep_strays()
        return RotationResult(rec.rotation_id, target, total, total, True)

    def _sweep_strays(self) -> None:
        """轮换完成后清扫任何残留的旧代次密文与临时文件。"""
        keep = {_blob_name(f.file_id, f.generation, "enc")
                for f in self._store.all_files()}
        for entry in self._blobs.iterdir():
            if entry.name not in keep:
                entry.unlink()

    # ---- 查询 ----

    def status(self) -> Status:
        rec = self._store.latest_rotation()
        generations = self._store.available_generations()
        if rec is None:
            return Status(None, None, 0, self._store.file_count(), False,
                          generations)
        if rec.status == "done":
            return Status(rec.rotation_id, rec.target_generation,
                          rec.completed, rec.total, True, generations)
        # 进行中的轮换：完成数直接统计文件表，已提交进度单调不减。
        completed = self._store.count_files_at(rec.target_generation)
        return Status(rec.rotation_id, rec.target_generation, completed,
                      rec.total, False, generations)

    # ---- 工具 ----

    def _fsync_dir(self) -> None:
        fd = os.open(self._blobs, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
