# Claude Code enterprise security: companion examples

Working examples from the book **Securing Claude Code for Enterprises: Policy, Sandboxing, MCP Control, and Audit for Cybersecurity Teams** by Ellis Vantor.

Get the book: https://www.securingclaudecode.com

## What's here

| Path | What it does |
|---|---|
| `hooks/block_secrets_edit.py` | PreToolUse hook (`Write\|Edit`): denies edits that introduce secrets such as cloud access keys, private key blocks, and hard-coded credentials |
| `hooks/audit_config_change.py` | ConfigChange hook: appends one JSON line per settings or skill file change to `.claude/config-audit.jsonl` |
| `hooks/deny_network_hosts.py` | PreToolUse hook (`Bash`): denies network commands to hosts not in `.claude/network-allowlist.json` |
| `telemetry/managed-otel-baseline.json` | Managed-settings `env` block that pins the OpenTelemetry log exporter to your collector |
| `checklists/policy-verification.md` | Three-step loop to prove a managed policy is in force |
| `detections/README.md` | Sample SIEM detections (SPL + KQL) for mode escalation, policy refusals, and plugin provenance |

## Run the tests

```bash
pip install pytest
pytest tests
```

## Using the hooks

Each hook reads the hook JSON on stdin and exits with a decision. Wire one up in settings, for example:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          { "type": "command",
            "command": "python \"${CLAUDE_PROJECT_DIR}/.claude/hooks/block_secrets_edit.py\"" }
        ]
      }
    ]
  }
}
```

For enforcement, deliver hooks through managed settings and set `allowManagedHooksOnly`, so a repository cannot add or replace them.

## Read this first

- These are examples. Test them in your own environment before production use.
- Claude Code changes frequently. Verify every setting, event, and hook field against the current documentation.
- Hooks are one layer. They do not replace permission rules, sandboxing, or network egress control.

## What the book adds

- A threat model for agentic coding tools
- Three complete managed-settings baselines (Strict, Standard, Research)
- Ten SIEM detections with Splunk SPL and KQL examples
- MCP, plugin, and marketplace review checklists
- A control mapping to NIST CSF 2.0, ISO 27001, and the OWASP LLM Top 10
- A phased rollout plan and an incident response playbook

## License and disclaimer

Code is released under the MIT License (see `LICENSE`).

Independent publication. Not affiliated with, sponsored by, or endorsed by Anthropic, PBC. Claude and Claude Code are trademarks of Anthropic, PBC.
