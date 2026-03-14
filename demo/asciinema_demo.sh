#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  oombra asciinema demo — designed for recording
#
#  To record:
#    brew install asciinema
#    cd /path/to/oombra
#    asciinema rec demo/oombra-demo.cast -c "./demo/asciinema_demo.sh"
#
#  To upload & get embeddable link:
#    asciinema upload demo/oombra-demo.cast
#
#  To embed in README (after uploading):
#    [![asciicast](https://asciinema.org/a/XXXX.svg)](https://asciinema.org/a/XXXX)
#
#  Or self-host with asciinema-player:
#    <div id="demo"></div>
#    <script src="https://cdn.jsdelivr.net/npm/asciinema-player@3.7/dist/bundle/asciinema-player.min.js"></script>
#    <script>AsciinemaPlayer.create('oombra-demo.cast', document.getElementById('demo'));</script>
# ═══════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."

# Simulated typing effect
type_cmd() {
    echo ""
    echo -n "$ "
    echo "$1" | while IFS= read -r -n1 char; do
        echo -n "$char"
        sleep 0.04
    done
    echo ""
    sleep 0.3
    eval "$1"
    sleep 1.5
}

section() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    sleep 2
}

clear

echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │                                                     │"
echo "  │   oombra — privacy-preserving threat intel sharing  │"
echo "  │                                                     │"
echo "  │   Anonymize locally. Share selectively.             │"
echo "  │   Contribute to the collective.                     │"
echo "  │                                                     │"
echo "  └─────────────────────────────────────────────────────┘"
echo ""
sleep 3

# ── 1. Show raw data ──────────────────────────────────────────────

section "1. Raw threat data — contains sensitive info"

type_cmd "cat demo/eval_crowdstrike.json | python3 -m json.tool | head -15"

echo ""
echo "  ⚠  Contains org details, internal context, free-text notes"
echo "  ⚠  Can't share this raw — reveals your security posture"
sleep 3

# ── 2. Preview anonymization ─────────────────────────────────────

section "2. oombra anonymizes LOCALLY — preview what would be sent"

type_cmd "oombra preview demo/eval_crowdstrike.json"

echo ""
echo "  ✓  PII stripped, context bucketed, IOCs hashed"
echo "  ✓  Nothing leaves your machine until you approve"
sleep 3

# ── 3. Attack map ─────────────────────────────────────────────────

section "3. Share attack maps — which tools caught what"

type_cmd "oombra preview demo/attack_map_apt28.json"
sleep 3

# ── 4. IOC bundle ─────────────────────────────────────────────────

section "4. IOC bundles — hashed locally, only fingerprints sent"

type_cmd "oombra preview demo/ioc_bundle_1.json"
sleep 3

# ── 5. Differential privacy ──────────────────────────────────────

section "5. Add differential privacy noise (epsilon=5.0)"

type_cmd "oombra preview demo/eval_crowdstrike.json --epsilon 5.0"

echo ""
echo "  ✓  Scores have calibrated Laplace noise"
echo "  ✓  Mathematical guarantee: bounded information leakage"
sleep 3

# ── 6. Attestation ───────────────────────────────────────────────

section "6. Cryptographic attestation — prove privacy was applied"

type_cmd "oombra attest demo/eval_crowdstrike.json"

echo ""
echo "  ✓  HMAC-linked CDI chain — break any step, chain fails"
echo "  ✓  VAP confirms zero PII patterns in output"
sleep 3

# ── 7. Server + upload ───────────────────────────────────────────

section "7. Start server, upload, query aggregated intelligence"

echo "$ oombra serve --port 8765 &"
oombra serve --port 8765 --db sqlite+aiosqlite:///demo_asciinema.db > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2
echo "  Server running on http://localhost:8765"
echo ""

# Upload silently
for f in demo/eval_crowdstrike.json demo/eval_sentinelone.json demo/eval_splunk.json demo/attack_map_apt28.json demo/ioc_bundle_1.json; do
    oombra upload "$f" --api-url http://localhost:8765 --yes > /dev/null 2>&1
done
echo "  Uploaded 5 contributions (3 evals, 1 attack map, 1 IOC bundle)"
sleep 1

type_cmd "curl -s http://localhost:8765/stats | python3 -m json.tool"

type_cmd "curl -s http://localhost:8765/query/category/edr | python3 -m json.tool"

type_cmd "curl -s http://localhost:8765/query/techniques | python3 -m json.tool"

echo ""
echo "  ✓  Only aggregates returned — no individual contribution exposed"

kill $SERVER_PID 2>/dev/null
rm -f demo_asciinema.db
sleep 2

# ── 8. Graph analysis ────────────────────────────────────────────

section "8. Threat graph — find campaign patterns"

type_cmd "oombra graph build demo/attack_map_apt28.json demo/ioc_bundle_1.json"
sleep 2

# ── 9. ZK proofs ─────────────────────────────────────────────────

section "9. Zero-knowledge proofs — prove validity without revealing content"

type_cmd "oombra prove demo/eval_crowdstrike.json"
sleep 2

# ── 10. Tests ─────────────────────────────────────────────────────

section "10. Full test suite — 233 tests"

type_cmd "python -m pytest oombra/tests/ -q --tb=no"
sleep 2

# ── Outro ─────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  oombra — 6 layers of privacy:"
echo ""
echo "    1. Regex PII/security scrubbing"
echo "    2. k-anonymity bucketing"
echo "    3. HMAC-keyed IOC hashing"
echo "    4. Differential privacy (Laplace noise)"
echo "    5. ADTC attestation chains + VAP"
echo "    6. Zero-knowledge validity proofs"
echo ""
echo "  + Private Set Intersection for IOC comparison"
echo "  + Secure aggregation for anonymous benchmarking"
echo "  + Federated learning for collaborative models"
echo "  + Federated graph intelligence for campaign detection"
echo ""
echo "  pip install oombra"
echo "  github.com/manizzle/oombra"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 5
