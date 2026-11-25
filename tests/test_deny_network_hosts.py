"""Tests for hooks/deny_network_hosts.py (PreToolUse, Bash)."""
import json

from conftest import decision, run_hook

SCRIPT = "deny_network_hosts.py"

ALLOWLIST = ["api.internal.example.com", "*.trusted.example.net"]


def _payload(tmp_path, command):
    (tmp_path / ".claude").mkdir(exist_ok=True)
    (tmp_path / ".claude" / "network-allowlist.json").write_text(
        json.dumps(ALLOWLIST), encoding="utf-8")
    return json.dumps({
        "cwd": str(tmp_path),
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })


def test_allow_non_network_command(tmp_path):
    """A command with no network tool is ignored (exit 0, no decision)."""
    proc = run_hook(SCRIPT, _payload(tmp_path, "ls -la && grep foo bar.txt"))
    assert proc.returncode == 0
    assert decision(proc) is None


def test_allow_allowlisted_host_from_payload_sample(tmp_path, payload_file):
    """The allowlisted curl payload sample is allowed."""
    raw = payload_file("deny_network_allow.json")
    raw["cwd"] = str(tmp_path)
    (tmp_path / ".claude").mkdir(exist_ok=True)
    (tmp_path / ".claude" / "network-allowlist.json").write_text(
        json.dumps(ALLOWLIST), encoding="utf-8")
    proc = run_hook(SCRIPT, json.dumps(raw))
    assert proc.returncode == 0
    assert decision(proc) is None


def test_deny_non_allowlisted_host(tmp_path, payload_file):
    """wget to a host outside the allowlist is denied."""
    raw = payload_file("deny_network_deny.json")
    raw["cwd"] = str(tmp_path)
    (tmp_path / ".claude").mkdir(exist_ok=True)
    (tmp_path / ".claude" / "network-allowlist.json").write_text(
        json.dumps(ALLOWLIST), encoding="utf-8")
    proc = run_hook(SCRIPT, json.dumps(raw))
    assert proc.returncode == 0
    out = decision(proc)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "evil.example.org" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_malformed_stdin_allows_safely():
    """Non-JSON stdin: exit 0, no decision (fail-open by design)."""
    proc = run_hook(SCRIPT, "")
    assert proc.returncode == 0
    assert decision(proc) is None


def test_edge_wildcard_rule_allows_subdomain(tmp_path):
    """A '*.trusted.example.net' wildcard covers subdomains."""
    proc = run_hook(
        SCRIPT, _payload(tmp_path, "curl https://mirror.trusted.example.net/file.tar.gz"))
    assert proc.returncode == 0
    assert decision(proc) is None


def test_edge_missing_allowlist_denies_unknown_host(tmp_path):
    """No allowlist file: unknown hosts are denied (empty rules allow nothing)."""
    proc = run_hook(
        SCRIPT, json.dumps({
            "cwd": str(tmp_path),
            "tool_name": "Bash",
            "tool_input": {"command": "curl https://evil.example.org/x"},
        }))
    assert proc.returncode == 0
    out = decision(proc)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
