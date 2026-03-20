#!/usr/bin/env bash
# nur — wartime + peacetime + threat modeling
set -e
cd "$(dirname "$0")/.."

type_cmd() {
    echo ""; echo -n "$ "
    echo "$1" | while IFS= read -r -n1 char; do echo -n "$char"; sleep 0.03; done
    echo ""; sleep 0.3; eval "$1"; sleep 1
}
narrate() { echo "  $1"; sleep 0.8; }
bold() { echo ""; echo "  >>> $1"; sleep 1.2; }
divider() { echo ""; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  $1"; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; sleep 2; }

clear
echo ""
echo "  ┌───────────────────────────────────────────────────────┐"
echo "  │   nur — light on what your industry knows             │"
echo "  │   live: nur.saramena.us                               │"
echo "  │   37 feeds · 36 vendors · 575 tests                  │"
echo "  └───────────────────────────────────────────────────────┘"
echo ""
sleep 3

divider "WARTIME — 2:17 AM, LockBit, hospital under attack"
narrate "IR team needs answers NOW."
bold "1. IOCs → campaign match"
type_cmd "nur report demo/ioc_bundle_2.json"
narrate "32 shared IOCs. LockBit confirmed. Actions prioritized."
sleep 2
bold "2. Attack map → detection gaps"
type_cmd "nur report demo/attack_map_lockbit.json"
narrate "7 gaps. T1490 critical. Deploy rules."
sleep 2
bold "3. Tool eval → real benchmarks"
type_cmd "nur report demo/eval_crowdstrike.json"
narrate "9.2 avg. 5 known gaps. Supplement, don't switch."
sleep 2

divider "PEACETIME — build a better stack"
bold "4. Market map"
type_cmd "nur market edr"
sleep 2
bold "5. Vendor comparison"
type_cmd "nur search compare crowdstrike sentinelone"
sleep 2

divider "THREAT MODEL — threatcl compatible"
bold "6. Generate threat model for your stack"
type_cmd "nur threat-model --stack crowdstrike,splunk,okta --vertical healthcare"
sleep 3

divider "AI-NATIVE — JSON + HCL output"
type_cmd "nur threat-model --stack crowdstrike,splunk --hcl | head -20"
sleep 2

divider "TRUSTLESS — cryptographic proof chain"
narrate "Every submission → cryptographic receipt. Every aggregate → proof."
bold "7. Full trustless pipeline demo"
type_cmd "python demo/trustless_demo.py 2>&1 | head -60"
sleep 2
narrate "Commitment hashes, Merkle proofs, zero individual values stored."
sleep 1
bold "8. Verify a receipt"
narrate "POST /verify/receipt → valid: true"
sleep 1
bold "9. Verify an aggregate"
narrate "GET /verify/aggregate/CrowdStrike → proof + verification"
sleep 1
bold "10. Platform proof stats"
narrate "GET /proof/stats → merkle_root, total_contributions, unique_vendors"
sleep 2

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  WARTIME                PEACETIME              TRUSTLESS"
echo "  nur report iocs.json   nur market edr         Every submit → receipt"
echo "  nur report attack.json nur search compare X Y Every query → proof"
echo "  nur report eval.json   nur threat-map '...'   /verify/receipt"
echo "                                                 /verify/aggregate/{v}"
echo ""
echo "  Live: nur.saramena.us"
echo "  Code: github.com/manizzle/nur"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 5
