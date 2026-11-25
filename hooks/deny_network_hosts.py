#!/usr/bin/env python3
"""PreToolUse hook (matcher: Bash): deny network commands to non-allowlisted hosts.
Parses hosts out of the command text and compares them to an allowlist file
(.claude/network-allowlist.json: a JSON array of domains, "*.example.com" wildcards allowed)."""
import json, re, sys, os

NETWORK_TOOLS = ("curl", "wget", "http", "https", "nc ", "netcat", "ftp")

def hosts_in(command):
    found = set()
    for match in re.finditer(r"https?://([A-Za-z0-9._-]+)", command):
        found.add(match.group(1).lower())
    for match in re.finditer(r"(?:^|\s)(?:curl|wget)\s+(?:[^\s]+\s+)*?([A-Za-z0-9._-]+\.[A-Za-z]{2,})", command):
        found.add(match.group(1).lower())
    return found

def allowed(domain, rules):
    for rule in rules:
        rule = rule.lower().strip()
        if not rule:
            continue
        if rule.startswith("*."):
            if domain == rule[2:] or domain.endswith("." + rule[2:]):
                return True
        elif domain == rule:
            return True
    return False

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    command = (payload.get("tool_input", {}) or {}).get("command", "")
    lowered = " " + command.lower() + " "
    if not any(t in lowered for t in NETWORK_TOOLS):
        sys.exit(0)
    cwd = payload.get("cwd") or os.getcwd()
    list_path = os.path.join(cwd, ".claude", "network-allowlist.json")
    rules = []
    try:
        with open(list_path, encoding="utf-8") as f:
            rules = json.load(f)
    except Exception:
        rules = []
    hosts = hosts_in(command)
    blocked = [h for h in hosts if not allowed(h, rules)]
    if blocked:
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason":
                    "Blocked: command reaches non-allowlisted host(s): "
                    + ", ".join(sorted(blocked))
                    + ". Request an allowlist addition through the network-policy process.",
            }
        }
        print(json.dumps(out))
    sys.exit(0)

if __name__ == "__main__":
    main()
