"""Child-process entry for crash-injection tests.

Usage:
    python -m tests.crash_child <vault> <srcdir> <mode> <kill_point> <kill_count>

mode:
    import-and-rotate   import every file in <srcdir>, then rotate("rot-1")
    reopen              just open the vault (runs recovery)

The crash hook calls os._exit(1) at the <kill_count>-th occurrence of
<kill_point>, simulating a hard crash (no cleanup, no finally blocks).
A kill_point of "none" disables killing (used for plain continuation runs).
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fileprotect import FileProtector  # noqa: E402


def main() -> None:
    vault, srcdir, mode, kill_point, kill_count = (
        Path(sys.argv[1]),
        Path(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
        int(sys.argv[5]),
    )
    counter = {"n": 0}

    def hook(self, name):
        if name == kill_point:
            counter["n"] += 1
            if counter["n"] >= kill_count:
                os._exit(1)

    FileProtector._crash_point = hook

    fp = FileProtector(vault)
    if mode == "import-and-rotate":
        for src in sorted(srcdir.iterdir()):
            try:
                fp.import_file(src.name, src)
            except ValueError:
                pass  # already imported by a previous crashed attempt
        result = fp.rotate("rot-1")
        assert result.success
    elif mode == "reopen":
        pass
    else:
        raise SystemExit(f"unknown mode {mode}")
    fp.close()


if __name__ == "__main__":
    main()
