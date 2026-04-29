#!/usr/bin/env sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT/venv/bin/python3}"
CONFIG_PATH="${CONFIG_PATH:-$ROOT/agent/config.json}"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "Python binary not executable: $PYTHON_BIN"
  exit 1
fi

if [ ! -f "$CONFIG_PATH" ]; then
  echo "Config not found: $CONFIG_PATH"
  exit 1
fi

case "$(uname -s)" in
  Darwin)
    mkdir -p "$HOME/Library/LaunchAgents"
    PLIST="$HOME/Library/LaunchAgents/com.mini-siem.agent.plist"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.mini-siem.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON_BIN</string>
    <string>-m</string>
    <string>agent.main</string>
    <string>--config</string>
    <string>$CONFIG_PATH</string>
  </array>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$ROOT/agent/agent-startup.log</string>
  <key>StandardErrorPath</key><string>$ROOT/agent/agent-startup.err</string>
</dict>
</plist>
EOF
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    echo "Installed LaunchAgent: $PLIST"
    ;;
  Linux)
    mkdir -p "$HOME/.config/systemd/user"
    SERVICE="$HOME/.config/systemd/user/mini-siem-agent.service"
    cat > "$SERVICE" <<EOF
[Unit]
Description=Mini-SIEM Agent
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
ExecStart=$PYTHON_BIN -m agent.main --config $CONFIG_PATH
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now mini-siem-agent.service
    echo "Installed user systemd service: $SERVICE"
    ;;
  *)
    echo "Unsupported OS for startup automation."
    exit 1
    ;;
esac
