# Mini-SIEM implementation plan

Incremental roadmap (builds on the current TCP + JSON design).

## Phase 1 — Complete (this PR / iteration)

| Item | Status |
|------|--------|
| Normalized event envelope + `make_event()` | Done (`shared/event_builder.py`) |
| Stricter `data` validation (`user`, `src_ip`, `service`, `message`) | Done (`shared/schema.py`) |
| Agent config JSON + `--config` | Done (`agent/config.py`, `agent/main.py`) |
| LAN/WAN server address + reconnect | Done (`server_host` / `reconnect_delay_seconds`) |
| Modular detection + registry | Done (`server/detection/*.py`, `registry.py`) |
| New rules: sudo abuse, suspicious login time, new IP/user, distributed BF | Done |
| Linux: successful SSH login parsing | Done |
| macOS collector (`log stream` + `system.log` fallback) | Done (starter) |
| Windows collector (`pywin32`, 4624/4625) | Done (starter) |
| Docs + setup script | Done (`README.md`, `scripts/setup_agent.sh`) |

## Phase 2 — Security & ops

1. **TLS on the agent socket** — same newline-delimited JSON; add `ssl` context + certs on server and agent config paths for `ca_cert`, `client_cert`, `client_key`.
2. **Agent authentication** — shared secret or mutual TLS; validate before `validate_event`.
3. **Structured logging** — replace `print` with `logging` + log levels on server and agent.
4. **Detection tuning** — move thresholds (`THRESHOLD`, `TIME_WINDOW`, night hours) to `server/config.yaml` or env.

## Phase 3 — Scale & durability

1. Replace JSON files with SQLite or PostgreSQL for events/alerts.
2. Multi-tenant agents (org id in `agent` block).
3. Rule engine DSL or Sigma-lite YAML instead of only Python modules.
4. Back-pressure: agent queues to disk when server is down.

## Suggested folder layout (current)

```
mini-siem/
  shared/
    schema.py           # Receiver validation
    event_builder.py   # Normalized event factory for all collectors
  agent/
    main.py            # CLI, TCP client, reconnect
    config.py
    config.example.json
    identity.py        # hostname / OS / IP resolution
    collector/
      __init__.py      # Dispatches by platform
      linux_auth.py
      macos_auth.py
      windows_auth.py
  server/
    receiver/
      socket_server.py
    detection/
      __init__.py
      registry.py      # Add rules here
      common.py
      ssh_bruteforce.py
      failed_password.py
      privilege_escalation.py
      sudo_abuse.py
      suspicious_login_time.py
      new_ip_for_user.py
      distributed_bruteforce.py
      rules.py         # Legacy re-exports
    storage/
    web/
  scripts/
    setup_agent.sh
```

## Adding a detection rule

1. Create `server/detection/my_rule.py` with `def detect_my_rule(event: dict) -> dict | None:`.
2. Import and append `detect_my_rule` to `ALL_DETECTORS` in `server/detection/registry.py`.
3. Return a dict with at least `alert_type`, `severity`, `timestamp`, `client_id` where applicable.

## Adding a new platform

1. Add `agent/collector/myos_auth.py` implementing `parse_auth_log(agent_info)` yielding dicts from `make_event(...)`.
2. Branch in `agent/collector/__init__.py::get_collector_module`.
