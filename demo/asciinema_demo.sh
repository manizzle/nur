#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  oombra — the hospital incident
#
#  Record: asciinema rec demo/oombra-demo.cast -c "./demo/asciinema_demo.sh"
#  Upload: asciinema upload demo/oombra-demo.cast
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
echo "  │   2:17 AM — Ohio Children's Hospital                  │"
echo "  │                                                       │"
echo "  │   EHR system encrypted. LockBit ransom note on        │"
echo "  │   every screen. NICU monitors offline.                │"
echo "  │                                                       │"
echo "  │   The IR team has IOCs and MITRE observations.        │"
echo "  │   They need to know: is anyone else seeing this?      │"
echo "  │   What are they missing? What should they do next?    │"
echo "  │                                                       │"
echo "  │   To get answers, they have to contribute.            │"
echo "  │                                                       │"
echo "  └───────────────────────────────────────────────────────┘"
echo ""
sleep 5

# ═══════════════════════════════════════════════════════════════
# Background: seed server with real data + other hospitals
# ═══════════════════════════════════════════════════════════════

narrate "The oombra platform already has contributions from 3 other hospitals"
narrate "and real IOCs scraped from ThreatFox, Feodo Tracker, and CISA KEV."
echo ""

python demo/scrape_real_intel.py demo/seed/ > /dev/null 2>&1
rm -f demo_asciinema.db
oombra serve --port 8765 --db sqlite+aiosqlite:///demo_asciinema.db > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2
for f in demo/seed/ioc_bundle_*.json demo/seed/attack_map_*.json demo/eval_crowdstrike.json demo/eval_sentinelone.json demo/eval_splunk.json demo/ioc_bundle_1.json demo/attack_map_apt28.json demo/attack_map_lockbit.json; do
    [ -f "$f" ] && oombra upload "$f" --api-url http://localhost:8765 --yes > /dev/null 2>&1
done

type_cmd "curl -s http://localhost:8765/stats | python3 -m json.tool"

narrate ""
narrate "Pennsylvania, West Virginia, and Michigan already contributed."
narrate "Ohio doesn't know any of this yet. They just got breached."
sleep 2

# ═══════════════════════════════════════════════════════════════
# SCENE 1: What the IR team found
# ═══════════════════════════════════════════════════════════════

divider "THE INCIDENT: What Ohio's IR team pulled from their network"

narrate "4 IOCs from the compromised EHR servers:"
narrate "  - lockbit-decryptor.onion.ws (C2 domain)"
narrate "  - a1b2c3...123456 (LockBit payload hash)"
narrate "  - 45.33.32.156 (attacker IP)"
narrate "  - lockbit-support@protonmail.com (ransom contact)"
narrate ""
narrate "They can't share this raw — HIPAA, internal network context."
narrate "But they NEED to know if this is part of something bigger."
sleep 2

# ═══════════════════════════════════════════════════════════════
# SCENE 2: Give IOCs → Get campaign match
# ═══════════════════════════════════════════════════════════════

divider "\"Are we the only ones getting hit?\""

narrate "One command. IOCs anonymized locally, then analyzed against"
narrate "what Pennsylvania, West Virginia, and Michigan contributed."
echo ""

type_cmd "oombra report demo/ioc_bundle_2.json --api-url http://localhost:8765"

narrate ""
bold "Campaign Match: Yes. 8 shared IOCs. LockBit healthcare campaign."
narrate "3 other hospitals saw the same C2 domain and attacker IP."
narrate "Ohio learned this in seconds — would take days through an ISAC."
sleep 3

# ═══════════════════════════════════════════════════════════════
# SCENE 3: Give attack map → Get detection gaps
# ═══════════════════════════════════════════════════════════════

divider "\"What is our CrowdStrike missing?\""

narrate "Ohio mapped the attack to MITRE ATT&CK. CrowdStrike caught T1486"
narrate "(encryption) but what else did it miss? Other hospitals know."
echo ""

type_cmd "oombra report demo/attack_map_lockbit.json --api-url http://localhost:8765"

narrate ""
bold "46% coverage. 7 detection gaps found."
narrate "T1490 (VSS deletion) — CRITICAL. CrowdStrike misses it."
narrate "T1021 (RDP lateral movement) — missed across all tools."
narrate "Ohio knows exactly what detection rules to deploy NOW."
sleep 3

# ═══════════════════════════════════════════════════════════════
# SCENE 4: Give eval → Get benchmarks
# ═══════════════════════════════════════════════════════════════

divider "\"Should we switch EDR vendors?\""

narrate "After the incident, Ohio's CISO needs data for the board."
echo ""

type_cmd "oombra report demo/eval_crowdstrike.json --api-url http://localhost:8765"

narrate ""
narrate "CrowdStrike 9.2 — at or above average. Don't switch."
narrate "But it has 5 known technique gaps from cross-org attack data."
narrate "Supplement with Sigma rules. Present this to the board."
sleep 3

# ═══════════════════════════════════════════════════════════════
# SCENE 5: The flywheel — next hospital gets a better report
# ═══════════════════════════════════════════════════════════════

divider "4:30 AM — West Virginia runs the same command. Better report."

narrate "Ohio's contribution just made West Virginia's report richer."
narrate "More IOCs to match. More technique data. Better actions."
narrate "Every hospital that contributes makes the next one safer."
echo ""

type_cmd "curl -s http://localhost:8765/query/techniques | python3 -m json.tool"

narrate "13 techniques tracked. Detection gaps visible across all tools."
sleep 2

# ── Cleanup ───────────────────────────────────────────────────
kill $SERVER_PID 2>/dev/null
rm -f demo_asciinema.db

# ═══════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  2:17 AM  Ohio gets hit. Fights alone."
echo "  2:18 AM  Runs: oombra report incident_iocs.json"
echo "           Gets: campaign match, 8 shared IOCs, LockBit confirmed"
echo "  2:19 AM  Runs: oombra report attack_map.json"
echo "           Gets: 7 detection gaps, T1490 is critical"
echo "  2:20 AM  Deploys detection rules. Closes the gaps."
echo "  4:30 AM  West Virginia gets hit. Runs oombra report."
echo "           Gets a BETTER report — because Ohio contributed."
echo ""
echo "  No contribution = no report. That's the deal."
echo ""
echo "  pip install oombra"
echo "  github.com/manizzle/oombra"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 5
