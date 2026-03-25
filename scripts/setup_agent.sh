#!/usr/bin/env sh
# Copy example agent config next to your checkout; edit server_host before running.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ ! -f agent/config.json ]; then
  cp agent/config.example.json agent/config.json
  echo "Created agent/config.json — set server_host to your SIEM receiver IP."
else
  echo "agent/config.json already exists; not overwriting."
fi
