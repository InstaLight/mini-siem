# Mini-SIEM

A small **SIEM-style** project: OS agents tail authentication logs, send **newline-delimited JSON** over **TCP** to a Python server. The server stores events, runs **pluggable detection rules**, and exposes a **FastAPI** dashboard.

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
make seed-data # push varied sample events to receiver
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


## Dashboard features

The dashboard at [http://localhost:8000/](http://localhost:8000/) is a server-rendered Jinja2 UI with vanilla-JS live polling (5-10s).

Top-level pages:

- **Overview (`/`)** - summary cards, severity donut, activity-over-time timeline, latest warnings & activity previews, agents mini-table. Auto-refreshes live.
- **Warnings (`/warnings`)** - filterable table (free-text search, user, source IP, type, time window, severity chips), bulk clear, bulk response actions, per-tab CSV. Click a row to drill into `/warnings/{alert_id}`.
- **Warning detail (`/warnings/{alert_id}`)** - full fields, related activity (same user / IP / agent), and one-click response buttons (Block IP, Isolate Host, Clear, or any other allowed action with a reason).
- **Activity (`/activity`)** - same pattern for raw events + `/activity/{event_id}` detail.
- **Agents (`/agents`)** - derived from the event stream (last seen, event count, OS, IP). Isolate / release buttons per agent.
- **Responses (`/responses`)** - full audit history of every response action (filters by status/type, expandable per-row JSON, CSV export).
- **Blocklist (`/blocklist`)** - manage blocked IPs + quarantined agents: add, remove, view reason & added-by.

Legacy URLs `/health`, `/issues`, `/actions`, `/admin` redirect to the new pages so old links keep working.

## Response actions

`ALLOWED_ACTIONS`:

| Action | What actually happens |
|--------|----------------------|
| `block_ip` | Writes the IP to `server/storage/blocklist.json`. The TCP receiver drops all future events whose `data.src_ip` matches. |
| `unblock_ip` | Removes the IP from the blocklist (receiver resumes accepting its events). |
| `isolate_host` | Writes the agent id to `server/storage/quarantine.json`. The receiver still accepts the agent's events but flags them with `quarantined: true` AND raises a new `quarantined_host_activity` high-severity warning for each one. |
| `release_quarantine` | Removes the agent from quarantine (events stop being flagged/escalated). |
| `terminate_process` | Local `kill -9` against any numeric PIDs in `target_ids` (MVP; same behavior as before). |

Every action call stores a record in `server/storage/actions.json` with the requester, targets, status, dry-run flag, reason, and full details payload.

## OS-login startup automation

Install/remove startup services:

```bash
make install-startup
make uninstall-startup
```

Environment overrides (optional):

- `PYTHON_BIN` (default: `./venv/bin/python3`)
- `CONFIG_PATH` (default: `./agent/config.json`)

## HTTP API surface

JSON API used by the UI polling layer (5-10s intervals) and by any external script:

| Method / Path | Purpose |
|---------------|---------|
| `GET  /api/summary` | Totals, severity counts, connected agents, blocklist/quarantine sizes |
| `GET  /api/alerts?q=&severity=&user=&ip=&type=&since=&limit=` | Filterable warnings list |
| `GET  /api/alerts/{alert_id}` | Warning + related events |
| `GET  /api/events?...` | Filterable activity list (same query params) |
| `GET  /api/events/{event_id}` | Event + related events |
| `GET  /api/agents` | Agents derived from the event stream |
| `GET  /api/timeseries?window=60m&bucket=5m` | Activity-over-time buckets |
| `GET  /api/severity-breakdown` | Severity counts for the donut chart |
| `GET  /api/blocklist` | Blocked IPs + quarantined agents |
| `POST /api/blocklist` | Add a blocked IP `{ip, reason?, requested_by?}` |
| `DELETE /api/blocklist/{ip}` | Unblock an IP |
| `POST /api/quarantine` | Quarantine an agent `{agent_id, reason?, requested_by?}` |
| `DELETE /api/quarantine/{agent_id}` | Release an agent |
| `GET  /api/actions?limit=` | Action history (newest first) |
| `GET  /api/actions/candidates` | Allowed action types + alert/event candidates |
| `POST /api/actions/execute` | Run any allowed action |
| `POST /api/alerts/clear-selected` | Bulk clear `{ids: [...]}` |
| `POST /api/events/clear-selected` | Bulk clear `{ids: [...]}` |

Legacy-compatible endpoints (same contracts as before): `GET /events`, `GET /alerts`, `GET /actions/candidates`, `POST /actions/execute`, `POST /alerts/clear-selected`, `POST /events/clear-selected`, `POST /alerts/clear`.

CSV exports: `/export/combined.csv`, `/export/alerts.csv`, `/export/events.csv`, `/export/actions.csv`.

