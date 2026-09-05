#!/bin/bash
# One-command demo: assess the seed repo, print findings, approve, publish.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose -f deploy/compose.yaml up -d --build
trap 'echo; echo "(mesh left running — stop with: docker compose -f deploy/compose.yaml down)"' EXIT

echo "waiting for orchestrator..."
for _ in $(seq 1 30); do
  curl -sf http://127.0.0.1:8080/docs >/dev/null 2>&1 && break
  sleep 2
done

AID=$(curl -s -X POST http://127.0.0.1:8080/assessments \
  -H 'Content-Type: application/json' -d '{"repo_ref":"demo/seed-repo"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["assessment_id"])')
echo "assessment: $AID"

STATE=pending
for _ in $(seq 1 60); do
  STATE=$(curl -s "http://127.0.0.1:8080/assessments/$AID" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["state"])')
  printf '\r  state: %-20s' "$STATE"
  [ "$STATE" = "pending_approval" ] || [ "$STATE" = "failed" ] && break
  sleep 2
done
echo

curl -s "http://127.0.0.1:8080/assessments/$AID" | python3 -c '
import sys, json
d = json.load(sys.stdin)
r = d["report"]
if r is None:
    raise SystemExit(f"assessment failed: {d[\"error\"]}")
print(f"\n{len(r[\"findings\"])} findings (partial={r[\"partial\"]}):")
for f in r["findings"]:
    p = f["package"]
    print(f'"'"'  {p["name"]}=={p["version"]}: {f["advisory_id"]} [{f["severity"]}] -> {f["recommended_action"]}'"'"')
print(f"\nsummary: {r[\"summary\"]}")
'

echo
read -r -p "approve and publish this report? [y/N] " answer
if [ "${answer,,}" = "y" ]; then
  curl -s -X POST "http://127.0.0.1:8080/assessments/$AID/approve"; echo
else
  echo "left pending approval."
fi
