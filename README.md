<h1 align="center">nur</h1>

<p align="center"><strong>Peer-verified security intelligence — what your peers actually use, what they pay, and what stopped the attack. Anonymized, live, open source.</strong></p>

<p align="center">
  <img src="demo/nur-demo.gif?v=5" alt="nur demo" width="750" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-616_passing-2ed573" />
  <img src="https://img.shields.io/badge/sources-37_live-ff6b6b" />
  <img src="https://img.shields.io/badge/vendors-3000%2B_tracked-ffa502" />
  <img src="https://img.shields.io/badge/license-AGPL--3.0-1e90ff" />
</p>

---

## Two problems, one protocol

### For CISOs evaluating vendors

You spend months on vendor bakeoffs that reflect one org's experience. Gartner costs six figures and is pay-to-play. G2 reviews are gamed. So you DM peers on Signal hoping for truth — unscalable, unstructured, limited to whoever you happen to know.

**nur replaces Gartner with peer-verified vendor intelligence.** Submit an eval, get back what practitioners at similar orgs chose, what they paid, and whether they'd buy it again. One CISO told us: *"If this replaces even part of what I get from Gartner, it's already paid for itself"* — benchmarking against $70K/yr in advisory spend.

### For IR firms sharing intelligence

Every engagement produces intelligence that dies in a privileged report. You can't share learnings across incidents without risking attorney-client privilege waiver. So the same attacks keep succeeding because defenders can't learn from each other.

**nur is the only platform where IR firms can share intel from privileged engagements without waiving privilege.** The data transmitted is threat intelligence by construction — technique IDs, detection rates, remediation categories, hashed IOCs — not forensic report content. Your law firm's privilege chain is never touched. CISA 2015 provides explicit safe harbor, and our open source `verify_safe_harbor()` function provides programmatic proof that nothing privileged was shared.

---

## How it works

1. **Contribute** — rate a vendor, submit attack map data, or report IOCs. Via web form, CLI, or voice. 60 seconds.
2. **Aggregate** — nur commits your data, updates running sums, and discards individual values. The server never sees who contributed what.
3. **Query** — get back what peers across your vertical actually use, what they pay, and what stopped real attacks. Cryptographic receipts prove your data was counted.

> [nur.saramena.us](https://nur.saramena.us) — [contribute](https://nur.saramena.us/contribute) · [dashboard](https://nur.saramena.us/dashboard) · [docs](https://nur.saramena.us/guide) · [register](https://nur.saramena.us/register)

---

## Get started

```bash
pip install nur
nur init
nur register you@yourorg.com
nur eval --vendor crowdstrike        # submit a vendor evaluation
nur market edr                       # see what peers actually use
```

Or contribute via web — no CLI needed:
**[nur.saramena.us/contribute](https://nur.saramena.us/contribute)** — rate your security tool in 60 seconds

---

## What you can evaluate

```
Detection:    overall score, detection rate, false positives
Price:        annual cost, per-seat cost, contract length, discount
Support:      quality, escalation ease, SLA response time
Performance:  CPU overhead, memory, scan latency, deploy time
Decision:     chose this vendor?, main decision factor
```

All fields committed, aggregated, individual values discarded.

---

## Examples

**Evaluating tools?** Get real practitioner benchmarks, not vendor marketing.

```bash
$ nur eval --vendor crowdstrike       # price, support, detection, decision intel
$ nur market edr                      # vendor rankings from real practitioners
$ nur search compare crowdstrike sentinelone
$ nur threat-model --stack crowdstrike,splunk,okta --vertical energy
```

**Under attack?** Upload IOCs, get remediation steps that your peers actually used.

```bash
$ nur report lockbit_iocs.json
  Campaign Match: Yes
  Shared IOCs: 32
  [CRITICAL] Block matching network indicators at firewall and DNS

$ nur report lockbit_attack_map.json
  Coverage Score: 71%
  Detection Gaps: 3
  Best Remediation: containment (87% success rate)
```

---

## Regulatory compliance — built in, not bolted on

nur's anonymization engine meets federal de-identification standards:

- **HIPAA Safe Harbor (45 CFR §164.514(b))** — all 18 identifiers mapped and verified. `verify_safe_harbor()` provides programmatic proof.
- **GDPR Recital 26** — re-identification risk assessed across 4 vectors. Individual values are discarded; only aggregates are retained.
- **CISA 2015 safe harbor** — threat intelligence sharing is explicitly protected with liability shield and privilege non-waiver.
- **Attorney-client privilege safe** — IR firms contribute threat intel (technique IDs, detection rates, hashed IOCs), not forensic report content. Privilege chain is never touched.

The code is open source. The compliance is verifiable by anyone — not a vendor assertion.

Full analysis: [COMPLIANCE.md](COMPLIANCE.md) · [THREAT_MODEL.md](THREAT_MODEL.md)

---

## Architecture

<p align="center">
  <img src="demo/architecture.png?v=5" alt="nur trustless architecture" width="700" />
</p>

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed sequence diagram.

---

<details>
<summary>Technical details — how the protocol works</summary>

### Proof verification chain

```
Submit ──▶ Translate ──▶ Commit ──▶ Merkle ──▶ Receipt
               │             │          │          │
          drop text     running sum   proof    signature
               │             │          │          │
               └── DISCARD ──┘         ▼     Dice Chain
                              /verify/receipt    ▼
                              /verify/aggregate/{vendor}
                              /proof/stats
                              /proof/bdp-stats
```

Client independently hashes the translated payload before submission.
Receipt's `contribution_hash` is compared. Match = end-to-end verified
transformation chain (dice chain).

### Blind category discovery

New threat actors not in any database? Three orgs hash the same name independently → threshold met → vote to reveal → enters public taxonomy for aggregation. Server never sees the name until quorum agrees.

### Crypto primitives

| Primitive | Purpose |
|-----------|---------|
| Pedersen Commitments | Server can't alter values after receipt |
| Merkle Tree | Server can't add/remove contributions undetected |
| ZKP Range Proofs | Proves scores valid without revealing them |
| BDP Credibility | Behavior-based poisoning defense (QCA) |
| Dice Chain | Client-side hash matches server commitment end-to-end |
| Blind Category Discovery | Server can't learn category names until quorum |

### Security hardening

Work email required · keypair auth · signed requests · rate limiting · min-k enforcement · payload limits · AWS Secrets Manager

### CI/CD pipeline

| Stage | What |
|-------|------|
| Test | pytest across Python 3.11/3.12/3.13 with coverage reporting |
| Lint | ruff check on every push/PR |
| Security | bandit static analysis, Dependabot dependency scanning, Trivy container scanning |
| Build | Docker image → GitHub Container Registry |
| Deploy | Auto-deploy to production with health checks and automated rollback |

</details>

---

## Pricing

| | Community | Pro | Enterprise |
|---|---|---|---|
| **Price** | Free | $99/mo | $499/mo |
| Contribute + receipts | ✓ | ✓ | ✓ |
| Market maps + rankings | | ✓ | ✓ |
| Threat maps + simulation | | ✓ | ✓ |
| API + dashboard + RFP | | | ✓ |

---

## License

[AGPL-3.0](LICENSE) — free for open source. Commercial use requires a [separate license](mailto:murtaza@saramena.us). See [CLA.md](CLA.md).

Data: [CDLA-Permissive-2.0](DATA_LICENSE.md)
