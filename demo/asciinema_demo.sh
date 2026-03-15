#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  nur — wartime + peacetime, live server demo
#
#  Record: asciinema rec demo/nur-demo.cast -c "./demo/asciinema_demo.sh"
# ═══════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."

type_cmd() {
    echo ""
    echo -n "$ "
    echo "$1" | while IFS= read -r -n1 char; do
        echo -n "$char"
        sleep 0.03
    done
    echo ""
    sleep 0.3
    eval "$1"
    sleep 1
}

narrate() { echo "  $1"; sleep 0.8; }
bold() { echo ""; echo "  >>> $1"; sleep 1.2; }

divider() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    sleep 2
}

clear

echo ""
echo "  ┌───────────────────────────────────────────────────────┐"
echo "  │                                                       │"
echo "  │   nur — light on what your industry knows             │"
echo "  │                                                       │"
echo "  │   live: nur.saramena.us                               │"
echo "  │   37 data sources · 658,000+ IOCs · real feeds        │"
echo "  │                                                       │"
echo "  └───────────────────────────────────────────────────────┘"
echo ""
sleep 3

# ═══════════════════════════════════════════════════════════════
# WARTIME — you're under attack
# ═══════════════════════════════════════════════════════════════

divider "WARTIME — 2:17 AM, Ohio Children's Hospital, LockBit"

narrate "EHR encrypted. NICU monitors offline."
narrate "IR team pulled IOCs. They need answers NOW."
sleep 2

bold "1. Upload IOCs → am I alone?"

type_cmd "nur report demo/ioc_bundle_2.json"

narrate "16 shared IOCs. LockBit campaign confirmed."
narrate "Block C2 domains. Hunt for lateral movement."
sleep 3

bold "2. Upload attack map → what am I missing?"

type_cmd "nur report demo/attack_map_lockbit.json"

narrate "7 detection gaps. T1490 critical. Deploy rules NOW."
sleep 3

bold "3. Upload eval → should I switch tools?"

type_cmd "nur report demo/eval_crowdstrike.json"

narrate "9.2 — above average. 5 gaps. Supplement, don't switch."
sleep 2

# ═══════════════════════════════════════════════════════════════
# PEACETIME — build a better stack
# ═══════════════════════════════════════════════════════════════

divider "PEACETIME — next week, data for the board"

narrate "Incident handled. CISO needs to justify the next purchase."
sleep 1

bold "4. Who leads the market?"

type_cmd "nur market edr"

sleep 2

bold "5. How does our tool compare?"

type_cmd "nur search compare crowdstrike sentinelone"

narrate "Real data. Not vendor slides."
sleep 2

bold "6. Where are our gaps before the next attack?"

type_cmd "nur threat-map 'ransomware lateral movement' --tools crowdstrike,splunk"

narrate "Find gaps in peacetime. Close them before wartime."
sleep 3

# ═══════════════════════════════════════════════════════════════
# JSON — for automation
# ═══════════════════════════════════════════════════════════════

divider "AI-NATIVE — JSON for SOAR, agents, scripts"

type_cmd "nur report demo/ioc_bundle_2.json --json | python3 -m json.tool | head -15"

sleep 2

# ═══════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  WARTIME                        PEACETIME"
echo "  nur report iocs.json           nur market edr"
echo "  nur report attack.json         nur search compare X Y"
echo "  nur report eval.json           nur threat-map '...'"
echo ""
echo "  Your wartime IOCs help someone's peacetime planning."
echo "  Their peacetime eval helps your wartime response."
echo ""
echo "  Live: nur.saramena.us"
echo "  Code: github.com/manizzle/nur"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 5
