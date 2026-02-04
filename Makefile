.PHONY: server agent

server:
	@echo "Starting SIEM server..."
	python3 -m server.receiver.socket_server

agent:
	@echo "Starting SIEM agent..."
	sudo python3 -m agent.main
