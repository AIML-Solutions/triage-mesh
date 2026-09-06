.PHONY: test sync up demo netpol cluster-up cluster-deploy cluster-test cluster-demo cluster-down

sync:
	uv sync

test:
	uv run pytest -q

up:
	docker compose -f deploy/compose.yaml up --build

demo:
	./demo/run-demo.sh

netpol:
	uv run python scripts/gen_networkpolicies.py

cluster-up:
	kind create cluster --config deploy/kind-config.yaml
	kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/calico.yaml
	kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s

cluster-deploy:
	docker build -t triage-mesh:0.2.0 .
	kind load docker-image triage-mesh:0.2.0 --name triage-mesh
	helm upgrade --install triage-mesh deploy/chart
	kubectl rollout status deployment --timeout=300s -l 'app in (orchestrator,scanner,intel,assessor,mcp-repo-reader,mcp-vuln-intel,mcp-report-writer)' 2>/dev/null || \
		for d in orchestrator scanner intel assessor mcp-repo-reader mcp-vuln-intel mcp-report-writer; do kubectl rollout status deployment/$$d --timeout=300s; done

cluster-test:
	./scripts/cluster-conformance.sh

cluster-demo: cluster-up cluster-deploy cluster-test

cluster-down:
	kind delete cluster --name triage-mesh
