"""中断恢复与轮换语义的自动化测试。"""

import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile

import pytest

from fileprotect import (CorruptCiphertextError, DuplicateFileError,
                         FileProtector, RotationConflictError, UnknownFileError)


class Crash(Exception):
    """模拟进程被杀。"""


def hook_at(point, times=1):
    """返回一个 crash_hook：第 times 次命中 point 时抛 Crash。"""
    state = {"n": 0}

    def hook(name):
        if name == point:
            state["n"] += 1
            if state["n"] >= times:
                raise Crash(point)

    return hook


def make_files(root, count, size=4096):
    files = {}
    src_dir = root / "src"
    src_dir.mkdir()
    for i in range(count):
        data = os.urandom(size)
        path = src_dir / f"f{i}.bin"
        path.write_bytes(data)
        files[f"file-{i}"] = data
    return files


def import_all(fp, files, root):
    for fid in files:
        fp.import_file(fid, str(root / "src" / f"f{fid.split('-')[1]}.bin"))


def assert_all_readable(vault_dir, files, tmp):
    fp = FileProtector(str(vault_dir))
    try:
        for fid, data in files.items():
            out = tmp / f"out_{fid}"
            fp.read_file(fid, str(out))
            assert out.read_bytes() == data, f"{fid} content mismatch"
    finally:
        fp.close()


def blob_files(vault_dir):
    return sorted(p.name for p in (vault_dir / "blobs").iterdir())


@pytest.fixture()
def env():
    root = pathlib.Path(tempfile.mkdtemp())
    vault_dir = root / "vault"
    tmp = root / "tmp"
    tmp.mkdir()
    files = make_files(root, 8)
    fp = FileProtector(str(vault_dir))
    import_all(fp, files, root)
    fp.close()
    return root, vault_dir, tmp, files


def test_import_and_readback(env):
    _, vault_dir, tmp, files = env
    assert_all_readable(vault_dir, files, tmp)


def test_duplicate_import_rejected(env):
    root, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir))
    with pytest.raises(DuplicateFileError):
        fp.import_file("file-0", str(root / "src" / "0.bin"))
    with pytest.raises(UnknownFileError):
        fp.read_file("nope", str(tmp / "x"))
    fp.close()


def test_clean_rotation(env):
    _, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir))
    res = fp.rotate("rot-1")
    assert res.done and res.target_generation == 2 and res.completed == 8
    st = fp.status()
    assert st.done and st.available_generations == [2]
    fp.close()
    assert_all_readable(vault_dir, files, tmp)
    # 旧密文与临时文件全部清理
    assert all(".gen2.enc" in n for n in blob_files(vault_dir))


def test_crash_mid_rotation_partial_switch(env):
    """部分文件已切换时中断：重开全部可读，续跑后只剩目标代次。"""
    _, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir), crash_hook=hook_at("rotate:after_file", 3))
    with pytest.raises(Crash):
        fp.rotate("rot-1")
    del fp
    # 重开：所有文件逐字节可读（混合代次）
    assert_all_readable(vault_dir, files, tmp)
    fp = FileProtector(str(vault_dir))
    st = fp.status()
    assert st.rotation_id == "rot-1" and not st.done
    assert st.completed == 3  # 3 个文件已提交切换
    assert st.available_generations == [1, 2]
    # 同一标识续跑：不产生新代次
    res = fp.rotate("rot-1")
    assert res.done and res.target_generation == 2
    assert fp.status().available_generations == [2]
    fp.close()
    assert_all_readable(vault_dir, files, tmp)
    assert all(".gen2.enc" in n for n in blob_files(vault_dir))


def test_crash_between_switch_and_commit(env):
    """文件切换与状态更新之间中断：孤儿新密文被清理，不重复加密已提交文件。"""
    _, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir),
                       crash_hook=hook_at("rotate:after_rename", 2))
    with pytest.raises(Crash):
        fp.rotate("rot-1")
    del fp
    assert_all_readable(vault_dir, files, tmp)
    fp = FileProtector(str(vault_dir))
    assert fp.status().completed == 1  # 第 2 个文件未提交，进度为 1
    res = fp.rotate("rot-1")
    assert res.done and res.target_generation == 2
    fp.close()
    assert_all_readable(vault_dir, files, tmp)
    assert all(".gen2.enc" in n for n in blob_files(vault_dir))


def test_crash_after_all_switched_before_key_cleanup(env):
    """全部文件切换后、旧密钥清理前中断：续跑完成清理。"""
    _, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir),
                       crash_hook=hook_at("rotate:before_finish"))
    with pytest.raises(Crash):
        fp.rotate("rot-1")
    del fp
    assert_all_readable(vault_dir, files, tmp)
    fp = FileProtector(str(vault_dir))
    st = fp.status()
    assert st.completed == 8 and not st.done
    assert st.available_generations == [1, 2]  # 旧密钥尚未移除
    res = fp.rotate("rot-1")
    assert res.done
    assert fp.status().available_generations == [2]
    fp.close()
    assert_all_readable(vault_dir, files, tmp)


def test_crash_during_recovery_then_recover_again(env):
    """恢复过程再次中断：再次打开后恢复最终完成。"""
    _, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir), crash_hook=hook_at("rotate:after_file", 2))
    with pytest.raises(Crash):
        fp.rotate("rot-1")
    del fp
    # 第一次恢复在中途被杀
    with pytest.raises(Crash):
        FileProtector(str(vault_dir), crash_hook=hook_at("recover:entry", 1))
    # 第二次恢复完成
    assert_all_readable(vault_dir, files, tmp)
    fp = FileProtector(str(vault_dir))
    res = fp.rotate("rot-1")
    assert res.done and fp.status().available_generations == [2]
    fp.close()
    assert_all_readable(vault_dir, files, tmp)


def test_progress_never_regresses(env):
    """已查询到的进度不因重启减少。"""
    _, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir), crash_hook=hook_at("rotate:after_file", 4))
    with pytest.raises(Crash):
        fp.rotate("rot-1")
    del fp
    fp = FileProtector(str(vault_dir))
    seen = fp.status().completed
    assert seen == 4
    fp.close()
    fp = FileProtector(str(vault_dir))
    assert fp.status().completed >= seen
    fp.close()


def test_old_rotation_id_after_later_rotation_done(env):
    """旧标识在后续轮换成功后再次提交：返回原结果，不产生多余代次。"""
    _, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir))
    r1 = fp.rotate("rot-1")
    assert r1.done and r1.target_generation == 2
    r2 = fp.rotate("rot-2")
    assert r2.done and r2.target_generation == 3
    again = fp.rotate("rot-1")
    assert again.done and again.target_generation == 2 and again.completed == 8
    st = fp.status()
    assert st.available_generations == [3]  # 没有多余代次
    fp.close()
    assert_all_readable(vault_dir, files, tmp)


def test_import_rejected_during_rotation(env):
    root, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir), crash_hook=hook_at("rotate:after_file", 1))
    with pytest.raises(Crash):
        fp.rotate("rot-1")
    del fp
    fp = FileProtector(str(vault_dir))
    with pytest.raises(RotationConflictError):
        fp.import_file("late", str(root / "src" / "0.bin"))
    with pytest.raises(RotationConflictError):
        fp.rotate("rot-other")
    fp.close()


def test_corruption_detected(env):
    _, vault_dir, tmp, files = env
    fp = FileProtector(str(vault_dir))
    blob = next((vault_dir / "blobs").iterdir())
    raw = bytearray(blob.read_bytes())
    raw[len(raw) // 2] ^= 1
    blob.write_bytes(bytes(raw))
    victim = None
    for fid in files:
        try:
            fp.read_file(fid, str(tmp / "x"))
        except CorruptCiphertextError:
            victim = fid
    assert victim is not None
    fp.close()


def test_large_file_near_limit_and_memory():
    """接近 500 MiB 上限：回读逐字节一致，库处理额外内存 <= 64 MiB。

    在子进程中运行，用 getrusage(RUSAGE_SELF) 读取峰值 RSS，
    与空转基线子进程对比，差值即库处理的额外内存。
    """
    root = pathlib.Path(tempfile.mkdtemp())
    size = 500 * 1024 * 1024 - 4096  # 接近单文件上限
    src = root / "big.bin"
    chunk = os.urandom(1024 * 1024)
    h = hashlib.sha256()
    with open(src, "wb") as f:
        written = 0
        while written < size:
            n = min(len(chunk), size - written)
            f.write(chunk[:n])
            h.update(chunk[:n])
            written += n
    expected = h.hexdigest()

    child = r'''
import hashlib, resource, sys
from fileprotect import FileProtector
root, expected = sys.argv[1], sys.argv[2]
fp = FileProtector(root + "/vault")
fp.import_file("big", root + "/big.bin")
fp.read_file("big", root + "/out.bin")
fp.close()
h = hashlib.sha256()
with open(root + "/out.bin", "rb") as f:
    for blk in iter(lambda: f.read(1 << 20), b""):
        h.update(blk)
assert h.hexdigest() == expected, "large file roundtrip mismatch"
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
if sys.platform != "darwin":
    peak *= 1024
print(peak)
'''
    code, peak = _run_child(child, str(root), expected)
    assert code == 0
    _, base = _run_child("print(0)" if False else
                         "import resource, sys\n"
                         "peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss\n"
                         "if sys.platform != 'darwin': peak *= 1024\n"
                         "print(peak)")
    extra_mib = (peak - base) / (1024 * 1024)
    assert extra_mib <= 64, f"extra memory {extra_mib:.1f} MiB exceeds 64 MiB"


def _run_child(code, *args):
    proc = subprocess.run([sys.executable, "-c", code, *args],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return proc.returncode, int(proc.stdout.strip().splitlines()[-1])
