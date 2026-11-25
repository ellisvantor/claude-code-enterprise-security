#!/usr/bin/env python3
"""ConfigChange hook: append an audit line for every settings/skill file change.
Writes one JSON object per event to .claude/config-audit.jsonl next to the project."""
import datetime, json, os, sys

def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # auditing must never block on bad input
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "source": payload.get("source", "unknown"),
        "file_path": payload.get("file_path", ""),
        "session_id": payload.get("session_id", ""),
        "cwd": payload.get("cwd", ""),
    }
    cwd = payload.get("cwd") or os.getcwd()
    log_dir = os.path.join(cwd, ".claude")
    try:
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "config-audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # never block the session over audit-log IO
    sys.exit(0)

if __name__ == "__main__":
    main()
