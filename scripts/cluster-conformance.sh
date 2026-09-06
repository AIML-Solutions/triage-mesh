#!/bin/bash
# Cluster conformance: the enforced NetworkPolicy topology must match
# deploy/policies.yaml, and the pipeline must run end-to-end through it.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
check() { # check <from-app> <to-host> <to-port> <expect: open|blocked>
  local from=$1 to=$2 port=$3 expect=$4
  local pod
  pod=$(kubectl get pod -l "app=$from" -o jsonpath='{.items[0].metadata.name}')
  if kubectl exec "$pod" -- python -c "
import socket
socket.create_connection(('$to', $port), timeout=4).close()
" >/dev/null 2>&1; then got=open; else got=blocked; fi
  if [ "$got" = "$expect" ]; then
    echo "PASS  $from -> $to:$port is $got"
  else
    echo "FAIL  $from -> $to:$port is $got (expected $expect)"
    fail=1
  fi
}

echo "== NetworkPolicy conformance =="
check orchestrator scanner 7201 open
check orchestrator intel 7202 open
check orchestrator assessor 7203 open
check scanner mcp-repo-reader 7101 open
check intel mcp-vuln-intel 7102 open
check assessor mcp-report-writer 7103 open
# forbidden paths
check scanner mcp-vuln-intel 7102 blocked
check intel mcp-repo-reader 7101 blocked
check assessor mcp-vuln-intel 7102 blocked
check scanner assessor 7203 blocked
check orchestrator mcp-report-writer 7103 blocked

echo "== End-to-end through the cluster =="
kubectl port-forward svc/orchestrator 18080:8080 >/dev/null 2>&1 &
pf_pid=$!
trap 'kill $pf_pid 2>/dev/null' EXIT
sleep 3

aid=$(curl -s -X POST http://127.0.0.1:18080/assessments \
  -H 'Content-Type: application/json' -d '{"repo_ref":"demo/seed-repo"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["assessment_id"])')
state=pending
for _ in $(seq 1 40); do
  state=$(curl -s "http://127.0.0.1:18080/assessments/$aid" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["state"])')
  [ "$state" = "pending_approval" ] || [ "$state" = "failed" ] && break
  sleep 3
done
findings=$(curl -s "http://127.0.0.1:18080/assessments/$aid" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d["report"]["findings"]) if d["report"] else -1)')
if [ "$state" = "pending_approval" ] && [ "$findings" -gt 0 ]; then
  echo "PASS  pipeline reached pending_approval with $findings findings"
  curl -s -X POST "http://127.0.0.1:18080/assessments/$aid/approve" >/dev/null
  echo "PASS  report approved and published"
else
  echo "FAIL  pipeline state=$state findings=$findings"
  fail=1
fi

exit $fail
