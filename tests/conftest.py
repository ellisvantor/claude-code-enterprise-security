"""Shared helpers: run a hook script as a subprocess the way Claude Code does."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
PAYLOADS_DIR = Path(__file__).resolve().parent / "payloads"


def run_hook(script_name, stdin_text):
    """Run hooks/<script_name> with stdin_text on stdin; return CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(HOOKS_DIR / script_name)],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=30,
    )


def decision(proc):
    """Parse the hook's stdout as a JSON decision object; None when stdout is empty."""
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)


@pytest.fixture
def payload_file():
    """Return the parsed JSON payload sample with the given filename."""
    def _load(filename):
        return json.loads((PAYLOADS_DIR / filename).read_text(encoding="utf-8"))
    return _load
