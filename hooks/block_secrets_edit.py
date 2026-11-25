#!/usr/bin/env python3
"""PreToolUse hook (matcher: Write|Edit): block edits that introduce secrets.
Reads hook JSON on stdin; denies with a reason when a secret pattern matches."""
import json, re, sys

PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{60,}", "GitHub fine-grained token"),
    (r"sk-ant-[A-Za-z0-9-]{20,}", "Anthropic API key"),
    (r"-----BEGIN AGE SECRET KEY-----", "age secret key"),
    (r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*[=:]\s*[\"'][^\"']{8,}[\"']", "hard-coded credential assignment"),
]

def string_values(value):
    """Yield every string in the payload so patterns match raw text,
    not JSON-escaped text (json.dumps turns quotes into \\", which hides
    quoted-credential patterns from the regex)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from string_values(v)
    elif isinstance(value, list):
        for v in value:
            yield from string_values(v)

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        print("invalid hook input", file=sys.stderr)
        sys.exit(2)
    tool_input = payload.get("tool_input", {}) or {}
    blob = "\n".join(string_values(tool_input))
    for pattern, label in PATTERNS:
        if re.search(pattern, blob):
            out = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason":
                        f"Blocked: edit matches secret pattern ({label}). "
                        "Store secrets in the approved vault and reference them by name.",
                }
            }
            print(json.dumps(out))
            sys.exit(0)
    sys.exit(0)

if __name__ == "__main__":
    main()
