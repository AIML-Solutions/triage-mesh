#!/bin/bash
# One-command demo: assess the seed repo, print findings, approve, publish.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose -f deploy/compose.yaml up -d --build
trap 'echo; echo "(mesh left running — stop with: docker compose -f deploy/compose.yaml down)"' EXIT

echo "waiting for the mesh..."
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

curl -s "http://127.0.0.1:8080/assessments/$AID" > /tmp/triage-mesh-demo.json
python3 - <<'PYEOF'
import json

data = json.load(open("/tmp/triage-mesh-demo.json"))
report = data["report"]
if report is None:
    raise SystemExit("assessment failed: " + str(data["error"]))
print(f"\n{len(report['findings'])} findings (partial={report['partial']}):")
for finding in report["findings"]:
    pkg = finding["package"]
    print(
        f"  {pkg['name']}=={pkg['version']}: {finding['advisory_id']} "
        f"[{finding['severity']}] -> {finding['recommended_action']}"
    )
print(f"\nsummary: {report['summary']}")
PYEOF

echo
read -r -p "approve and publish this report? [y/N] " answer
if [ "${answer,,}" = "y" ]; then
  curl -s -X POST "http://127.0.0.1:8080/assessments/$AID/approve"; echo
else
  echo "left pending approval."
fi
