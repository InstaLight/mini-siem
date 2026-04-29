# Mini-SIEM

A small **SIEM-style** demo: OS agents tail authentication logs, send **newline-delimited JSON** over **TCP** to a Python server. The server stores events, runs **pluggable detection rules**, and exposes a **FastAPI** dashboard.

> **Note:** This is a learning / lab architecture. For production you would add TLS, stronger auth, durable storage, and hardened parsing.

## Architecture

```
┌─────────────┐   TCP :9001    ┌──────────────────────────────────┐
│ Linux/macOS │  JSON + \n     │  server.receiver.socket_server    │
│ Windows     │ ─────────────► │  validate → store_event            │
│ agent       │                │  run_detectors → store_alert       │
└─────────────┘                └───────────────┬──────────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    ▼                          ▼                          ▼
             events.json                alerts.json               FastAPI :8000
             (JSON list)                (JSON list)               dashboard / APIs
```

- **Envelope** (all platforms): `agent`, `event`, `data`, `raw` — see `shared/event_builder.py`.
- **Future TLS:** Same messages; wrap the socket with `ssl` without changing JSON.

## Repository layout

| Path | Role |
|------|------|
| `shared/schema.py` | Server-side validation (required keys on `agent`, `event`, `data`) |
| `shared/event_builder.py` | `make_event(...)` — consistent timestamps and `data` shape |
| `agent/` | Config, CLI, identity, collectors (`linux_auth`, `macos_auth`, `windows_auth`) |
| `server/receiver/` | TCP listener |
| `server/detection/` | One module per rule + `registry.py` to register them |
| `server/storage/` | JSON persistence + file helpers |
| `server/web/` | FastAPI + Jinja dashboard |

## Setup

### 1. Server (any machine reachable by agents)

```bash
cd /path/to/mini-siem
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Terminal A — ingest + detection
python3 -m server.receiver.socket_server

# Terminal B — web UI
python3 -m uvicorn server.web.main:app --reload --port 8000
```

The receiver binds `0.0.0.0:9001` by default so agents can connect over **LAN/WAN**. Open the firewall for TCP **9001** (and **8000** only if you need the dashboard remotely).

### 2. Agent configuration

```bash
./scripts/setup_agent.sh    # creates agent/config.json from example
```

Edit **`agent/config.json`**:

- `server_host` — IP or hostname of the SIEM host (not necessarily `127.0.0.1`).
- `server_port` — must match the receiver (default `9001`).
- `agent.id` — stable identifier per endpoint.

### 3. Run the agent

**Linux** (needs read access to `/var/log/auth.log`; often `sudo`):

```bash
sudo python3 -m agent.main --config agent/config.json
```

**macOS** (may need permissions for `log stream` or `/var/log/system.log`):

```bash
python3 -m agent.main --config agent/config.json
```

**Windows** (install **pywin32**, run **Administrator** so the Security log is readable):

```bash
pip install pywin32
python3 -m agent.main --config agent/config.json
```

### 4. Make targets

```bash
make server    # socket ingest
make web-ui    # FastAPI
make agent     # agent with default config path (adjust Makefile if needed)
make seed-demo # push varied dummy events to receiver for demos
make install-startup   # install OS-login startup for agent (macOS/Linux)
make uninstall-startup # remove OS-login startup service
```

## How detection works

1. Each normalized event is validated with `shared.schema.validate_event`.
2. The event is appended to `server/storage/events.json`.
3. `server.detection.registry.run_detectors` runs every registered function in `ALL_DETECTORS`.
4. Each non-`None` alert dict is appended to `server/storage/alerts.json`.
5. The web UI reads those JSON files (same schema as API responses).

**Built-in rule modules** (see `server/detection/`):

| Rule | Idea |
|------|------|
| `failed_password` | Each bad password / auth failure |
| `ssh_bruteforce` | Many failures from one IP in a short window |
| `distributed_bruteforce` | Many **different usernames** failed from one IP |
| `privilege_escalation` | Sudo command lines |
| `sudo_abuse` | Many sudo events for one user in a short window |
| `suspicious_login_time` | Successful login outside configured UTC night hours |
| `new_ip_for_user` | Successful login from a **new** IP for a user who already had history |

To add a rule: implement `detect_*` in a new file and append it to `ALL_DETECTORS` in `registry.py`.

## Normalized event schema

All collectors should output:

```json
{
  "agent": { "id", "hostname", "os", "ip" },
  "event": {
    "id": "<uuid>",
    "timestamp": "<ISO-8601 UTC>Z",
    "source": "<collector name>",
    "type": "<e.g. authentication_failure | successful_login | ...>",
    "severity": "<low|medium|high>"
  },
  "data": {
    "user": "",
    "src_ip": "",
    "service": "",
    "message": ""
  },
  "raw": "<original line or message>"
}
```

Optional extra keys (e.g. `command` for sudo) are allowed. Use `make_event()` so empty fields are filled consistently.

## Development notes

- **Reconnect:** The agent reconnects in a loop if the TCP session drops (`reconnect_delay_seconds` in config).
- **Clear alerts:** `POST /alerts/clear` (demo button on the dashboard) wipes `alerts.json`.
- **Windows:** First connection skips existing Security log backlog; only **new** records are forwarded.

## Real dashboard features

The dashboard at `/` now includes:

- A summary-first layout for non-technical audiences
- Plain-language warnings/activity labels
- Alerts + events views with bulk checkbox selection
- **Clear selected** for alerts and events independently
- Combined CSV export (`/export/combined.csv`)
- Response action controls (with dry-run enabled by default)
- Action audit history panel

## Demo data seeding

For demonstrations, seed realistic mixed activity directly through the normal TCP ingest path:

```bash
make seed-demo
```

Or run manually with options:

```bash
python3 scripts/seed_demo_data.py --host 127.0.0.1 --port 9001 --burst-multiplier 2
```

This generates varied event types to trigger multiple detectors:

- repeated auth failures (SSH brute-force signal),
- distributed username spray from one IP,
- successful login from a new IP,
- successful login during suspicious UTC hours,
- repeated privilege escalation (sudo abuse),
- incorrect password samples.

## Response action safety model (MVP)

- Allowed action types are explicitly allowlisted (`terminate_process`, `isolate_host`).
- Destructive actions default to `dry_run=true`.
- Every action request is recorded with:
  - action ID, requester, timestamps
  - targeted IDs
  - status + execution details
- `terminate_process` currently executes only on the local server host (PID-based MVP path).
- `isolate_host` is a placeholder response for future remote agent integration.

## OS-login startup automation

Install/remove startup services:

```bash
make install-startup
make uninstall-startup
```

Under the hood:

- **macOS:** installs `~/Library/LaunchAgents/com.mini-siem.agent.plist`
- **Linux:** installs `~/.config/systemd/user/mini-siem-agent.service`

Environment overrides (optional):

- `PYTHON_BIN` (default: `./venv/bin/python3`)
- `CONFIG_PATH` (default: `./agent/config.json`)

## API additions (final version)

- `GET /events` - returns enriched events (includes `event_id`)
- `GET /alerts` - returns enriched alerts (includes `alert_id`)
- `POST /events/clear-selected` - bulk clear selected events by `ids`
- `POST /alerts/clear-selected` - bulk clear selected alerts by `ids`
- `GET /export/combined.csv` - combined event+alert CSV download
- `GET /actions` - response action audit records
- `GET /actions/candidates` - actionable records + allowed action types
- `POST /actions/execute` - trigger guarded response action

## Final demo runbook

1. Start receiver: `make server`
2. Start web API/dashboard: `make web-ui`
3. Seed demonstration data: `make seed-demo`
4. Open dashboard: [http://localhost:8000](http://localhost:8000)
5. Walk non-technical viewers through:
   - top summary cards (overall activity and risk),
   - **Warnings** tab (human-readable warning list),
   - **Activity Log** tab (underlying event stream),
   - **Response History** (what response steps were run).
6. Verify interactive features:
   - select rows and run **clear selected** in each tab,
   - export CSV and inspect both `record_kind=event` and `record_kind=alert` rows,
   - execute a dry-run response action and confirm it appears in action history.

## License / status

Educational / demo quality — extend as needed for your environment.
