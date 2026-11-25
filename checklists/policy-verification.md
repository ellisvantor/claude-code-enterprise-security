# Policy verification loop

Run on one canary machine per platform, before and after every policy change.

1. **Source.** Run `/status`. Confirm the `Setting sources` line names the source you deployed. No line means no managed source delivered a policy key. Check `Skipped sources` if a different source won.
2. **Dropped entries.** Run `claude doctor`. Archive the list of dropped entries with source and field. A policy that drops keys enforces only part of its intent.
3. **Behavior.** In a real session, confirm one denial per control area: a denied file read, a blocked provider, a refused plugin or MCP server.

Remove `OTEL_LOG_TOOL_DETAILS` from the telemetry baseline unless your collector is approved to hold command text.
