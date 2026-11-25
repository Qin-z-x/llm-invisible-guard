"""Shared helpers for the invisi_guard test-suite."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
DOCS = ROOT / "docs"
PYTHON = sys.executable

INVISIBLE_RANGES = (
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x2069),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xE0000, 0xE007F),
    (0xE0100, 0xE01EF),
)


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def has_invisible(text: str) -> list[int]:
    """Return code points of invisible characters present in ``text``."""
    found: set[int] = set()
    for ch in text:
        cp = ord(ch)
        for low, high in INVISIBLE_RANGES:
            if low <= cp <= high:
                found.add(cp)
                break
    return sorted(found)


def run_cli(args: list[str], stdin_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    """Run ``python -m invisi_guard ...`` in the repository root."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    return subprocess.run(
        [PYTHON, "-m", "invisi_guard"] + list(args),
        cwd=str(ROOT),
        input=stdin_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=180,
        check=False,
    )


def out(proc: subprocess.CompletedProcess) -> str:
    return proc.stdout.decode("utf-8", "replace")


def err(proc: subprocess.CompletedProcess) -> str:
    return proc.stderr.decode("utf-8", "replace")


def json_out(proc: subprocess.CompletedProcess):
    return json.loads(out(proc))


def load_schemas() -> dict[str, dict]:
    schemas = {}
    for name in ("finding.schema.json", "scan-result.schema.json"):
        schemas[name] = json.loads((DOCS / name).read_text(encoding="utf-8"))
    return schemas
