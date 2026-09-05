.PHONY: test sync up demo

sync:
	uv sync

test:
	uv run pytest -q

up:
	docker compose -f deploy/compose.yaml up --build

demo:
	./demo/run-demo.sh
