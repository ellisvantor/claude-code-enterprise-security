# Sample SIEM detections

Three detections from *Securing Claude Code for Enterprises*, reproduced so a SIEM engineer can start from a working query rather than a blank page. Each is stated as a vendor-neutral pseudo-query over the Claude Code OpenTelemetry log-event attributes, plus one Splunk SPL and one KQL form, exactly as the book prints them. Adjust field names to your collector's mapping.

All three assume the managed telemetry baseline from `telemetry/managed-otel-baseline.json` and an ingest that stores the event name in a `body`-style field. Claude Code emits the raw stream only — baselining, correlation, and alerting are your backend's job.

## D1 — Permission mode escalated to a bypass-class mode

**What it detects.** A session transitioning into `bypassPermissions` or `dontAsk` — the two modes that remove or auto-deny the human approval step. These are the modes most governed fleets lock down, so any transition is worth an alert, and the trigger field distinguishes a keystroke from an SDK call.

**Event and fields.** `claude_code.permission_mode_changed`: `to_mode`, `user.email`, `trigger`, `app.version`.

```sql
event: permission_mode_changed
where to_mode IN ("bypassPermissions", "dontAsk")
```

```sql
index=cc_events event.name="claude_code.permission_mode_changed"
to_mode IN ("bypassPermissions","dontAsk")
| stats count by user.email, to_mode, trigger, app.version
```

```kql
ClaudeCodeEventNames
| where name == "permission_mode_changed"
| where to_mode in ("bypassPermissions", "dontAsk")
| summarize Count = count() by user_email = tostring(user.email), to_mode
```

**Tuning.** Safe to alert on from day one in tiers that forbid the condition outright. If a CI population legitimately runs `dontAsk`, split by `app.entrypoint` or a lookup of CI users and drop those from paging.

## D3 — Policy and hook refusals

**What it detects.** Reject decisions whose source is `config` or `hook` — deny rules, managed policy, mode refusals, and hooks refusing calls. It is the evidence that the enforcement layers are firing, and the hunt list of what they stopped.

**Event and fields.** `claude_code.tool_decision`: `decision`, `source`, `tool_name`, `user.email`.

```sql
event: tool_decision
where decision == "reject" AND source IN ("config", "hook")
aggregate count by source, tool_name, user.email per day
```

```sql
index=cc_events event.name="claude_code.tool_decision"
decision="reject" source IN ("config","hook")
| stats count by source, tool_name, user.email
```

```kql
ClaudeCodeEventNames
| where name == "tool_decision"
| where decision == "reject" and source in ("config", "hook")
| summarize Count = count() by src = tostring(source), tool = tostring(tool_name)
```

**Tuning.** Review weekly rather than page on: a healthy fleet produces a steady rate, and the value is the trend and the hunt list, not single events. The source vocabulary does not say which configuration source matched, so treat spikes as a prompt to investigate, not an answer.

## D5 — Unapproved plugin provenance

**What it detects.** Plugin loads whose provenance is outside the managed pattern — a `user-local` or `community` scope, an enablement that came from a user install or a seed mount, or an install from a non-official marketplace. It turns the extension supply chain into a query.

**Event and fields.** `claude_code.plugin_loaded`: `plugin.scope`, `enabled_via`, `plugin_id_hash`, `user.email`.

```sql
event: plugin_loaded
where plugin.scope IN ("user-local", "community")
   OR enabled_via IN ("user-install", "seed-mount")
```

```sql
index=cc_events event.name="claude_code.plugin_loaded"
plugin.scope IN ("user-local","community") OR enabled_via IN ("user-install","seed-mount")
| stats dc(plugin_id_hash) as distinct_plugins by user.email
```

```kql
ClaudeCodeEventNames
| where name == "plugin_loaded"
| where plugin_scope in ("user-local", "community") or enabled_via in ("user-install", "seed-mount")
| summarize DistinctPlugins = dcount(plugin_id_hash) by user_email = tostring(user.email)
```

**Tuning.** Runs on the redacted stream — scope and hash fields flow without tool detail — so it works where content capture is not approved. Aggregate by `plugin_id_hash` before alerting: a shared org plugin appearing across many users is one event, not a hundred.

---

Ten detections, with tuning guidance and an incident-response playbook, are in the book: https://www.securingclaudecode.com/

Independent publication. Not affiliated with, sponsored by, or endorsed by Anthropic, PBC.
