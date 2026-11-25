"""Tests for hooks/block_secrets_edit.py (PreToolUse, Write|Edit)."""
import json

from conftest import decision, run_hook

SCRIPT = "block_secrets_edit.py"


def test_allow_clean_edit():
    """A benign edit produces no decision JSON and exits 0 (implicit allow)."""
    proc = run_hook(SCRIPT, json.dumps({
        "tool_name": "Write",
        "tool_input": {"file_path": "app.py", "content": "print('hello')\n"},
    }))
    assert proc.returncode == 0
    assert decision(proc) is None


def test_allow_from_payload_sample(payload_file):
    """The clean payload sample is allowed."""
    proc = run_hook(SCRIPT, json.dumps(payload_file("block_secrets_allow.json")))
    assert proc.returncode == 0
    assert decision(proc) is None


def test_deny_aws_key(payload_file):
    """An AWS access key id in the edit is denied with a JSON decision."""
    proc = run_hook(SCRIPT, json.dumps(payload_file("block_secrets_deny_aws.json")))
    assert proc.returncode == 0
    out = decision(proc)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "AWS access key id" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_deny_private_key_block(payload_file):
    """A private key block is denied."""
    proc = run_hook(SCRIPT, json.dumps(payload_file("block_secrets_deny_privkey.json")))
    assert proc.returncode == 0
    out = decision(proc)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_deny_hardcoded_password():
    """A hard-coded password assignment is denied."""
    proc = run_hook(SCRIPT, json.dumps({
        "tool_name": "Edit",
        "tool_input": {"file_path": "db.py", "new_string": 'password = "hunter2hunter2"'},
    }))
    assert proc.returncode == 0
    out = decision(proc)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "hard-coded credential" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_malformed_stdin_exits_2():
    """Non-JSON stdin is rejected with exit code 2 and no decision."""
    proc = run_hook(SCRIPT, "this is not json{{{")
    assert proc.returncode == 2
    assert decision(proc) is None


def test_edge_empty_tool_input():
    """Missing/empty tool_input does not crash and allows."""
    proc = run_hook(SCRIPT, json.dumps({"tool_name": "Write", "tool_input": {}}))
    assert proc.returncode == 0
    assert decision(proc) is None


def test_edge_secret_lookalike_not_flagged():
    """Words like 'password' in prose without a quoted value are not denied."""
    proc = run_hook(SCRIPT, json.dumps({
        "tool_name": "Write",
        "tool_input": {"file_path": "docs.md", "content": "# Password policy\nRotate quarterly.\n"},
    }))
    assert proc.returncode == 0
    assert decision(proc) is None
