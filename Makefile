.PHONY: server agent web-ui install-startup uninstall-startup seed-demo seed-data

PYTHON ?= python3
VENV_PYTHON := ./venv/bin/python3
RUN_PYTHON := $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),$(PYTHON))

server:
	@echo "Starting SIEM server..."
	$(RUN_PYTHON) -m server.receiver.socket_server

agent:
	@echo "Starting SIEM agent (uses agent/config.json if present)..."
	sudo $(RUN_PYTHON) -m agent.main --config agent/config.json

web-ui:
	@echo "Starting Web-UI..."
	$(RUN_PYTHON) -m uvicorn server.web.main:app --reload --port 8000

install-startup:
	@echo "Installing OS-login startup service for agent..."
	./scripts/install_startup.sh

uninstall-startup:
	@echo "Removing OS-login startup service for agent..."
	./scripts/uninstall_startup.sh

seed-demo:
	@echo "Seeding demo events into receiver..."
	$(RUN_PYTHON) scripts/seed_demo_data.py --host 127.0.0.1 --port 9001

seed-data:
	@echo "Seeding sample events into receiver..."
	$(RUN_PYTHON) scripts/seed_demo_data.py --host 127.0.0.1 --port 9001
