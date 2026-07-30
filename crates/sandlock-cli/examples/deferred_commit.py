#!/usr/bin/env python3
"""Exercise the sandlock deferred-commit CLI protocol end to end.

Run on Linux after building the CLI:

    cargo build -p sandlock-cli
    python3 crates/sandlock-cli/examples/deferred_commit.py
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[3]


def find_sandlock(explicit: str | None) -> Path:
    local_binary = REPO_ROOT / "target" / "debug" / "sandlock"
    if explicit:
        binary = Path(explicit).resolve()
    elif local_binary.is_file():
        binary = local_binary
    elif installed := shutil.which("sandlock"):
        binary = Path(installed)
    else:
        binary = local_binary

    if not binary.is_file():
        raise SystemExit(
            f"sandlock binary not found at {binary}; "
            "run `cargo build -p sandlock-cli` or pass --sandlock"
        )
    return binary


def run_candidate(
    sandlock: Path,
    workdir: Path,
    label: str,
    decision: str,
    expected_before: str,
) -> None:
    status_read, status_write = os.pipe()
    decision_read, decision_write = os.pipe()
    candidate_file = workdir / f"only-{label}.txt"

    readable = ["/usr", "/lib", "/bin", "/etc"]
    if Path("/lib64").exists():
        readable.append("/lib64")

    command = [str(sandlock), "run"]
    for path in readable:
        command.extend(["-r", path])
    command.extend(
        [
            "--workdir",
            str(workdir),
            "--defer-commit",
            "--decision-fd",
            str(decision_read),
            "--status-fd",
            str(status_write),
            "--",
            "sh",
            "-c",
            (
                f"printf '{label}\\n' > selected.txt; "
                f"printf 'created by {label}\\n' > only-{label}.txt"
            ),
        ]
    )

    process = subprocess.Popen(
        command,
        pass_fds=(decision_read, status_write),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    os.close(decision_read)
    os.close(status_write)

    try:
        with os.fdopen(status_read, encoding="utf-8") as status_stream:
            status_line = status_stream.readline()
        if not status_line:
            stdout, stderr = process.communicate(timeout=10)
            raise RuntimeError(
                f"{label}: sandlock exited before reporting pending\n"
                f"stdout: {stdout}\nstderr: {stderr}"
            )

        status = json.loads(status_line)
        assert status == {"state": "pending", "exit_code": 0}, status
        assert process.poll() is None, "sandlock must wait for the decision"
        assert (workdir / "selected.txt").read_text() == expected_before
        assert not candidate_file.exists()

        print(f"[{label}] status: {status}")
        print(f"[{label}] before {decision}: real workdir is unchanged")

        os.write(decision_write, f"{decision}\n".encode())
        os.close(decision_write)
        decision_write = -1

        stdout, stderr = process.communicate(timeout=10)
        if process.returncode != 0:
            raise RuntimeError(
                f"{label}: sandlock exited with {process.returncode}\n"
                f"stdout: {stdout}\nstderr: {stderr}"
            )

        if decision == "commit":
            assert (workdir / "selected.txt").read_text() == f"{label}\n"
            assert candidate_file.read_text() == f"created by {label}\n"
        else:
            assert (workdir / "selected.txt").read_text() == expected_before
            assert not candidate_file.exists()
        print(f"[{label}] after {decision}: assertions passed")
    finally:
        if decision_write >= 0:
            os.close(decision_write)
        if process.poll() is None:
            process.kill()
            process.wait()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sandlock",
        help="path to the sandlock binary (default: PATH or target/debug/sandlock)",
    )
    args = parser.parse_args()
    sandlock = find_sandlock(args.sandlock)

    with tempfile.TemporaryDirectory(prefix="sandlock-deferred-example-") as tmp:
        workdir = Path(tmp)
        selected = workdir / "selected.txt"
        selected.write_text("original\n")

        run_candidate(sandlock, workdir, "candidate-commit", "commit", "original\n")
        run_candidate(
            sandlock,
            workdir,
            "candidate-abort",
            "abort",
            "candidate-commit\n",
        )

        assert selected.read_text() == "candidate-commit\n"
        assert (workdir / "only-candidate-commit.txt").exists()
        assert not (workdir / "only-candidate-abort.txt").exists()

    print("deferred-commit CLI example passed")


if __name__ == "__main__":
    main()
