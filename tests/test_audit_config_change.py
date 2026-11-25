"""Tests for hooks/audit_config_change.py (ConfigChange)."""
import json

from conftest import run_hook

SCRIPT = "audit_config_change.py"


def test_appends_audit_line(tmp_path, payload_file):
    """A valid event appends one JSON line to .claude/config-audit.jsonl."""
    raw = payload_file("audit_config_change.json")
    raw["cwd"] = str(tmp_path)
    proc = run_hook(SCRIPT, json.dumps(raw))
    assert proc.returncode == 0
    lines = (tmp_path / ".claude" / "config-audit.jsonl").read_text(
        encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["source"] == "settings"
    assert entry["file_path"] == ".claude/settings.json"
    assert entry["session_id"] == "test-session-audit"


def test_appends_across_events(tmp_path):
    """Two events produce two lines in order."""
    for i in range(2):
        proc = run_hook(SCRIPT, json.dumps({
            "cwd": str(tmp_path),
            "source": "skills",
            "file_path": f".claude/skills/skill{i}.md",
        }))
        assert proc.returncode == 0
    lines = (tmp_path / ".claude" / "config-audit.jsonl").read_text(
        encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["file_path"] == ".claude/skills/skill1.md"


def test_malformed_stdin_exits_0():
    """Bad stdin never blocks the session: exit 0, no audit file."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        proc = run_hook(SCRIPT, "not-json")
        assert proc.returncode == 0
        assert not (Path(d) / ".claude" / "config-audit.jsonl").exists()


def test_edge_missing_fields_use_defaults(tmp_path):
    """A payload missing fields still audits with default values."""
    proc = run_hook(SCRIPT, json.dumps({"cwd": str(tmp_path)}))
    assert proc.returncode == 0
    entry = json.loads(
        (tmp_path / ".claude" / "config-audit.jsonl").read_text(encoding="utf-8"))
    assert entry["source"] == "unknown"
    assert entry["file_path"] == ""
