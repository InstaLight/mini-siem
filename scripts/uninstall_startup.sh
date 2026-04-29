#!/usr/bin/env sh
set -eu

case "$(uname -s)" in
  Darwin)
    PLIST="$HOME/Library/LaunchAgents/com.mini-siem.agent.plist"
    if [ -f "$PLIST" ]; then
      launchctl unload "$PLIST" 2>/dev/null || true
      rm -f "$PLIST"
      echo "Removed LaunchAgent: $PLIST"
    else
      echo "LaunchAgent not installed."
    fi
    ;;
  Linux)
    SERVICE="$HOME/.config/systemd/user/mini-siem-agent.service"
    systemctl --user disable --now mini-siem-agent.service 2>/dev/null || true
    rm -f "$SERVICE"
    systemctl --user daemon-reload
    echo "Removed user systemd service."
    ;;
  *)
    echo "Unsupported OS for startup automation."
    exit 1
    ;;
esac
