"""Acceptance and crash-recovery tests for the fileprotect library."""

import hashlib
import os
import random
import resource
import subprocess
import sys
from pathlib import Path

import pytest

from fileprotect import FileProtector
from fileprotect.crypto import CorruptCiphertextError

REPO_ROOT = Path(__file__).resolve().parent.parent
N_FILES = 6


def make_sources(srcdir: Path, n: int = N_FILES, size_base: int = 4096) -> dict:
    """Create deterministic pseudo-random source files; return {id: bytes}."""
    srcdir.mkdir(parents=True, exist_ok=True)
    contents = {}
    for i in range(n):
        file_id = f"file-{i}"
        data = random.Random(1000 + i).randbytes(size_base * (i + 1))
        (srcdir / file_id).write_bytes(data)
        contents[file_id] = data
    return contents


def run_child(vault: Path, srcdir: Path, mode: str, kill_point: str, kill_count: int):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.crash_child",
            str(vault),
            str(srcdir),
            mode,
            kill_point,
            str(kill_count),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def assert_all_readable(fp: FileProtector, contents: dict):
    for file_id, data in contents.items():
        assert fp.read_file(file_id) == data, f"content mismatch: {file_id}"


def data_files(vault: Path) -> list[Path]:
    return sorted((vault / "data").iterdir())


def assert_clean_final_state(fp: FileProtector, vault: Path, contents: dict,
                             generation: int):
    """Only the target generation remains: one key, one ciphertext per file."""
    status = fp.status()
    assert status.key_generations == [generation]
    assert status.success
    assert status.completed == len(contents)
    files = data_files(vault)
    assert len(files) == len(contents)
    assert all(f".g{generation}." in p.name for p in files)
    assert list((vault / "tmp").iterdir()) == []
    assert_all_readable(fp, contents)


# --------------------------------------------------------------------------
# basic API
# --------------------------------------------------------------------------

def test_import_read_status_rotate_reopen(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    with FileProtector(vault) as fp:
        for file_id, path in zip(contents, sorted((tmp_path / "src").iterdir())):
            fp.import_file(file_id, path)
        status = fp.status()
        assert status.rotation_id is None
        assert status.key_generations == [1]
        assert_all_readable(fp, contents)
        result = fp.rotate("rot-1")
        assert result.success and result.target_generation == 2
        assert result.completed == len(contents)
        assert_all_readable(fp, contents)
    with FileProtector(vault) as fp:
        assert_clean_final_state(fp, vault, contents, 2)


def test_read_independent_of_source_after_import(tmp_path):
    contents = make_sources(tmp_path / "src", n=2)
    vault = tmp_path / "vault"
    with FileProtector(vault) as fp:
        for file_id in contents:
            fp.import_file(file_id, tmp_path / "src" / file_id)
        for path in (tmp_path / "src").iterdir():
            path.unlink()  # source gone; reads must still work
        assert_all_readable(fp, contents)


def test_duplicate_import_and_unknown_read(tmp_path):
    contents = make_sources(tmp_path / "src", n=1)
    with FileProtector(tmp_path / "vault") as fp:
        fp.import_file("file-0", tmp_path / "src" / "file-0")
        with pytest.raises(ValueError):
            fp.import_file("file-0", tmp_path / "src" / "file-0")
        with pytest.raises(KeyError):
            fp.read_file("nope")


def test_unusual_file_ids(tmp_path):
    src = tmp_path / "src.bin"
    data = os.urandom(1234)
    src.write_bytes(data)
    ids = ["a/b/c", "uni-文件-✓", "with space & %", ".hidden", "x" * 200]
    with FileProtector(tmp_path / "vault") as fp:
        for file_id in ids:
            fp.import_file(file_id, src)
        for file_id in ids:
            assert fp.read_file(file_id) == data
        assert fp.rotate("r").success
        for file_id in ids:
            assert fp.read_file(file_id) == data


def test_empty_file(tmp_path):
    src = tmp_path / "empty"
    src.write_bytes(b"")
    with FileProtector(tmp_path / "vault") as fp:
        fp.import_file("empty", src)
        assert fp.read_file("empty") == b""
        assert fp.rotate("r").success
        assert fp.read_file("empty") == b""


def test_tampered_ciphertext_detected(tmp_path):
    contents = make_sources(tmp_path / "src", n=1)
    vault = tmp_path / "vault"
    with FileProtector(vault) as fp:
        fp.import_file("file-0", tmp_path / "src" / "file-0")
        cipher = data_files(vault)[0]
        blob = bytearray(cipher.read_bytes())
        blob[len(blob) // 2] ^= 0xFF
        cipher.write_bytes(bytes(blob))
        with pytest.raises(CorruptCiphertextError):
            fp.read_file("file-0")


def test_streaming_read_into_caller_sink(tmp_path):
    contents = make_sources(tmp_path / "src", n=1)
    with FileProtector(tmp_path / "vault") as fp:
        fp.import_file("file-0", tmp_path / "src" / "file-0")
        sha = hashlib.sha256()
        class Sink:
            def write(self, chunk):
                sha.update(chunk)
        assert fp.read_file("file-0", Sink()) is None
        assert sha.hexdigest() == hashlib.sha256(contents["file-0"]).hexdigest()


# --------------------------------------------------------------------------
# crash during rotation
# --------------------------------------------------------------------------

def test_crash_with_partial_files_switched(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    proc = run_child(vault, tmp_path / "src", "import-and-rotate", "db_committed", 3)
    assert proc.returncode != 0
    with FileProtector(vault) as fp:  # recovery on open
        assert_all_readable(fp, contents)
        status = fp.status()
        assert status.rotation_id == "rot-1"
        assert status.target_generation == 2
        assert status.completed == 3
        assert not status.success
        assert sorted(status.key_generations) == [1, 2]
        result = fp.rotate("rot-1")  # continue the same rotation
        assert result.success and result.target_generation == 2
        assert_clean_final_state(fp, vault, contents, 2)


def test_crash_between_cipher_switch_and_state_update(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    proc = run_child(vault, tmp_path / "src", "import-and-rotate", "renamed", 1)
    assert proc.returncode != 0
    with FileProtector(vault) as fp:
        # crash left a stray new-generation ciphertext; DB still says gen 1
        assert_all_readable(fp, contents)
        assert fp.status().completed == 0
        assert len(data_files(vault)) == len(contents)  # stray cleaned up
        result = fp.rotate("rot-1")
        assert result.success
        assert_clean_final_state(fp, vault, contents, 2)


def test_crash_after_all_switched_before_old_key_cleanup(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    proc = run_child(vault, tmp_path / "src", "import-and-rotate", "success_marked", 1)
    assert proc.returncode != 0
    with FileProtector(vault) as fp:  # recovery finishes the cleanup
        assert_all_readable(fp, contents)
        status = fp.status()
        assert status.success
        assert status.key_generations == [2]  # stale key removed by recovery
        assert_clean_final_state(fp, vault, contents, 2)


def test_recovery_itself_interrupted(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    # First crash: rotation committed but old key not yet removed.
    proc = run_child(vault, tmp_path / "src", "import-and-rotate", "success_marked", 1)
    assert proc.returncode != 0
    # Plant extra stray ciphertexts so recovery has several things to delete.
    for i in range(3):
        (vault / "data" / f"stray-{i}.g1.enc").write_bytes(os.urandom(64))
    # Second crash: recovery dies after deleting the first stray.
    proc = run_child(vault, tmp_path / "src", "reopen", "recover_stray_deleted", 1)
    assert proc.returncode != 0
    # Third open: recovery must complete and finish everything.
    with FileProtector(vault) as fp:
        assert_clean_final_state(fp, vault, contents, 2)
        result = fp.rotate("rot-1")  # already done: replay returns stored result
        assert result.success and result.target_generation == 2
        assert_clean_final_state(fp, vault, contents, 2)


def test_repeated_crashes_then_completion(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    # Crash after 1, 2, 3, ... further file commits each round, until a round
    # runs to completion.  Every reopen in between must serve all files.
    crashes = 0
    kill_count = 1
    while True:
        proc = run_child(
            vault, tmp_path / "src", "import-and-rotate", "db_committed", kill_count
        )
        with FileProtector(vault) as fp:
            assert_all_readable(fp, contents)
        if proc.returncode == 0:
            break
        crashes += 1
        kill_count += 1
        assert kill_count <= N_FILES + 2, "rotation never completes"
    assert crashes >= 2
    with FileProtector(vault) as fp:
        assert_clean_final_state(fp, vault, contents, 2)


# --------------------------------------------------------------------------
# rotation id semantics
# --------------------------------------------------------------------------

def test_completed_rotation_id_replay_and_no_regress(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    with FileProtector(vault) as fp:
        for file_id in contents:
            fp.import_file(file_id, tmp_path / "src" / file_id)
        first = fp.rotate("rot-1")
        assert first.target_generation == 2
        second = fp.rotate("rot-2")
        assert second.target_generation == 3
        inodes_before = {p.name: p.stat().st_ino for p in data_files(vault)}
        # Old id after a newer rotation: stored result, no re-encryption.
        replay = fp.rotate("rot-1")
        assert replay.success and replay.target_generation == 2
        assert replay.completed == replay.total == len(contents)
        status = fp.status()
        assert status.rotation_id == "rot-2"
        assert status.target_generation == 3
        assert status.key_generations == [3]
        assert {p.name: p.stat().st_ino for p in data_files(vault)} == inodes_before
        assert_all_readable(fp, contents)


def test_same_id_retry_produces_single_generation(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    proc = run_child(vault, tmp_path / "src", "import-and-rotate", "db_committed", 2)
    assert proc.returncode != 0
    with FileProtector(vault) as fp:
        completed_before = fp.status().completed
        assert completed_before == 2
    with FileProtector(vault) as fp:  # reopen again: progress must not regress
        assert fp.status().completed >= completed_before
        switched = {
            p.name: p.stat().st_ino
            for p in data_files(vault)
            if ".g2." in p.name
        }
        result = fp.rotate("rot-1")
        assert result.success and result.target_generation == 2
        assert fp.status().key_generations == [2]  # exactly one new generation
        after = {p.name: p.stat().st_ino for p in data_files(vault)}
        # Files switched before the crash were not re-encrypted.
        for name, ino in switched.items():
            assert after[name] == ino
        assert_clean_final_state(fp, vault, contents, 2)


def test_new_rotation_rejected_while_one_running(tmp_path):
    contents = make_sources(tmp_path / "src")
    vault = tmp_path / "vault"
    proc = run_child(vault, tmp_path / "src", "import-and-rotate", "db_committed", 1)
    assert proc.returncode != 0
    with FileProtector(vault) as fp:
        with pytest.raises(RuntimeError):
            fp.rotate("rot-other")
        assert fp.rotate("rot-1").success  # same id continues fine


# --------------------------------------------------------------------------
# large file near the 500 MiB limit
# --------------------------------------------------------------------------

@pytest.mark.slow
def test_large_file_roundtrip_memory_bounded(tmp_path):
    script = r"""
import hashlib, resource, sys
from pathlib import Path
from fileprotect import FileProtector

vault = Path(sys.argv[1])
src = Path(sys.argv[2])
block = 8 << 20
total = 480 << 20  # 480 MiB, near the 500 MiB limit

import os
data_block = os.urandom(block)
sha = hashlib.sha256()
with open(src, "wb") as f:
    written = 0
    while written < total:
        f.write(data_block)
        sha.update(data_block)
        written += block
expected = sha.hexdigest()
del data_block

def rss():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == "darwin" else value * 1024

fp = FileProtector(vault)
fp.import_file("big", src)
baseline = rss()

sha2 = hashlib.sha256()
class Sink:
    def write(self, chunk):
        sha2.update(chunk)
fp.read_file("big", Sink())
assert sha2.hexdigest() == expected, "readback mismatch"

assert fp.rotate("rot-big").success
sha3 = hashlib.sha256()
class Sink2:
    def write(self, chunk):
        sha3.update(chunk)
fp.read_file("big", Sink2())
assert sha3.hexdigest() == expected, "readback after rotation mismatch"
fp.close()

delta = rss() - baseline
limit = 64 << 20
assert delta < limit, f"extra memory {delta >> 20} MiB >= 64 MiB"
print(f"memory delta: {delta >> 20} MiB")
"""
    result = subprocess.run(
        [sys.executable, "-c", script,
         str(tmp_path / "vault"), str(tmp_path / "big.bin")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, result.stderr
