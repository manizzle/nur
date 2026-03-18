#!/usr/bin/env bash
# Record the trustless pipeline demo for the README GIF.
# Usage: asciinema rec demo/nur-demo.cast -c 'bash demo/record_trustless.sh' --cols 80 --rows 40
set -e
cd "$(dirname "$0")/.."

# Self-contained demo — runs Python inline, no external dependencies needed.
# Shows the complete trustless pipeline without truncation.

pause() { sleep "$1"; }
type_slow() {
    echo -n "$ "
    echo "$1" | while IFS= read -r -n1 char; do echo -n "$char"; sleep 0.025; done
    echo ""; sleep 0.2
}
section() { echo ""; echo "  ── $1 ──"; echo ""; pause 0.8; }

clear
echo ""
echo "  ┌──────────────────────────────────────────────────────────────────┐"
echo "  │  nur — trustless collective security intelligence               │"
echo "  │  commit · prove · discard · verify                              │"
echo "  │  37 feeds · 36 vendors · 575 tests                             │"
echo "  └──────────────────────────────────────────────────────────────────┘"
echo ""
pause 2

section "1. Submit eval → cryptographic receipt"
type_slow "python3 -c \"
from nur.server.proofs import ProofEngine, translate_eval, verify_receipt
engine = ProofEngine()
body = {'data': {'vendor': 'CrowdStrike', 'category': 'edr', 'overall_score': 9.2, 'detection_rate': 94.5, 'would_buy': True, 'notes': 'DROPPED by translator'}}
vendor, cat, values = translate_eval(body)
print(f'  Translated: vendor={vendor}, category={cat}')
print(f'  Values: {values}')
print(f'  Notes field: DROPPED (no free text in proof layer)')
receipt = engine.commit_contribution(vendor, cat, values)
print(f'  Receipt: {receipt.receipt_id}')
print(f'  Commitment: {receipt.commitment_hash[:40]}...')
print(f'  Merkle root: {receipt.merkle_root[:40]}...')
print(f'  Valid: {verify_receipt(receipt)}')
\""
pause 1.5

section "2. Submit attack map → histogram update"
type_slow "python3 -c \"
from nur.server.proofs import ProofEngine, translate_attack_map
engine = ProofEngine()
body = {'techniques': [
    {'technique_id': 'T1566', 'detected_by': ['CrowdStrike'], 'missed_by': ['SentinelOne']},
    {'technique_id': 'T1078', 'detected_by': ['Okta'], 'missed_by': ['CrowdStrike']},
    {'technique_id': 'T1490', 'detected_by': [], 'missed_by': ['CrowdStrike', 'SentinelOne']},
], 'severity': 'critical', 'remediation': [{'category': 'containment', 'effectiveness': 'stopped_attack'}]}
params = translate_attack_map(body)
receipt = engine.commit_attack_map(**params)
print(f'  Receipt: {receipt.receipt_id}')
print(f'  Techniques: {len(params[\"techniques\"])} committed')
print(f'  Severity: {params[\"severity\"]}')
print(f'  Remediation: category+effectiveness only (action text DROPPED)')
for t in engine.get_technique_frequency():
    print(f'  Histogram: {t[\"technique_id\"]}: {t[\"count\"]}x ({t[\"pct\"]}%)')
\""
pause 1.5

section "3. Verify aggregate proof"
type_slow "python3 -c \"
from nur.server.proofs import ProofEngine, verify_aggregate_proof
engine = ProofEngine()
for s in [9.2, 8.5, 8.8, 7.9, 9.0]:
    engine.commit_contribution('CrowdStrike', 'edr', {'overall_score': s})
proof = engine.prove_aggregate('CrowdStrike')
result = verify_aggregate_proof(proof, expected_root=engine.merkle_root)
print(f'  Vendor: CrowdStrike')
print(f'  Contributors: {proof.contributor_count}')
print(f'  Merkle root: {proof.merkle_root[:40]}...')
print(f'  Valid: {result[\"valid\"]}')
for check, passed in result['checks'].items():
    print(f'    {check}: {\"PASS\" if passed else \"FAIL\"}')
\""
pause 1.5

section "4. Blind category discovery"
type_slow "python3 -c \"
from nur.server.blind_categories import BlindCategoryDiscovery, hash_category
bcd = BlindCategoryDiscovery(discovery_threshold=3, reveal_quorum=2)
h = hash_category('DarkAngel', 'shared-salt')
print(f'  Hash: {h[:40]}...')
print(f'  (server sees ONLY the hash, never the name)')
for org in ['hospital-a', 'hospital-b', 'hospital-c']:
    r = bcd.propose_category(h, 'threat_actor', org)
    print(f'  {org} proposes: {r[\"status\"]} ({r[\"supporter_count\"]}/{r[\"threshold\"]})')
v1 = bcd.vote_reveal(h, 'DarkAngel', 'shared-salt', 'hospital-a')
print(f'  hospital-a reveals: {v1[\"status\"]}')
v2 = bcd.vote_reveal(h, 'DarkAngel', 'shared-salt', 'hospital-b')
print(f'  hospital-b reveals: {v2[\"status\"]} → {v2.get(\"revealed_name\", \"\")}')
print(f'  DarkAngel is now PUBLIC — aggregation begins')
\""
pause 1.5

section "5. What the server has vs cannot see"
echo "  STORED (server retains)              CANNOT SEE (discarded/opaque)"
echo "  ───────────────────────              ─────────────────────────────"
echo "  Commitment hashes (SHA-256)          Individual scores"
echo "  Running sums per vendor              Per-org attribution"
echo "  Technique frequency counters         Free-text notes"
echo "  Merkle tree                          Sigma rules, action strings"
echo "  Blind category hashes                Raw IOC values"
echo "  Revealed category names              Who proposed what (until reveal)"
echo ""
echo "  575 tests. Zero individual values. Math, not promises."
echo ""
pause 3

echo "  ──────────────────────────────────────────────────────────────────"
echo "  nur.saramena.us · github.com/manizzle/nur"
echo "  ──────────────────────────────────────────────────────────────────"
pause 3
