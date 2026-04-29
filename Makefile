.PHONY: server agent web-ui install-startup uninstall-startup

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
