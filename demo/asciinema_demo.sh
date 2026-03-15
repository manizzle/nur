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
echo "  │   37 feeds · 36 vendors · 387 tests                  │"
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

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  WARTIME                PEACETIME              THREAT MODEL"
echo "  nur report iocs.json   nur market edr         nur threat-model"
echo "  nur report attack.json nur search compare X Y   --stack X,Y,Z"
echo "  nur report eval.json   nur threat-map '...'     --hcl > model.hcl"
echo ""
echo "  Live: nur.saramena.us"
echo "  Code: github.com/manizzle/nur"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 5
