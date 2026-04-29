.PHONY: server agent web-ui install-startup uninstall-startup seed-demo

server:
	@echo "Starting SIEM server..."
	python3 -m server.receiver.socket_server

agent:
	@echo "Starting SIEM agent (uses agent/config.json if present)..."
	sudo python3 -m agent.main --config agent/config.json

web-ui:
	@echo "Starting Web-UI..."
	python -m uvicorn server.web.main:app --reload --port 8000

install-startup:
	@echo "Installing OS-login startup service for agent..."
	./scripts/install_startup.sh

uninstall-startup:
	@echo "Removing OS-login startup service for agent..."
	./scripts/uninstall_startup.sh

seed-demo:
	@echo "Seeding demo events into receiver..."
	python3 scripts/seed_demo_data.py --host 127.0.0.1 --port 9001
