<p align="center">
  <h1 align="center">oombra</h1>
  <p align="center"><strong>Share what you found. Get back what everyone else found.</strong></p>
</p>

<p align="center">
  <a href="https://asciinema.org/a/4ieKQiYhLiZlszBM" target="_blank"><img src="https://asciinema.org/a/4ieKQiYhLiZlszBM.svg" width="800" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-248%20passing-brightgreen" />
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-blue" />
</p>

---

## You can't get intelligence without giving intelligence.

You got breached. You pulled IOCs, mapped the kill chain, tested your tools. You want to know: is anyone else seeing this? What are they catching that I'm missing? What should I do next?

**oombra answers those questions — but only if you contribute your data.**

It's not charity. It's a trade. You give your anonymized incident data. You get back a personalized intelligence report: campaign matches, detection gaps, prioritized actions. The more orgs contribute, the better everyone's reports get.

No contribution = no report. That's the deal.

```bash
oombra report incident_iocs.json --api-url http://oombra-server:8000
```

```
  Analysis Report
  ══════════════════════════════════════════════════
  Campaign Match: Yes — 4 other healthcare orgs
  Shared IOCs: 12
  Threat Actor: LockBit

  Actions:
    [CRITICAL] Block C2 domains at firewall/DNS
    [CRITICAL] Deploy T1490 detection — your tools miss it, SentinelOne catches it
    [HIGH]     Hunt for RDP lateral movement (T1021)
    [MEDIUM]   Review VSS snapshot status — shadow copy deletion observed
```

**You gave IOCs. You got back a campaign match, detection gaps, and a to-do list.**

---

## Install

```bash
pip install -e ".[all,dev]"
```

---

## How It Works

### One command. Give data, get intelligence.

```bash
# You contribute your IOCs → you get campaign correlation + actions
oombra report incident_iocs.json --api-url http://oombra-server:8000

# You contribute your attack map → you get detection gaps + recommendations
oombra report lockbit_attack_map.json --api-url http://oombra-server:8000

# You contribute your tool eval → you get benchmarks + known gaps
oombra report our_crowdstrike_eval.json --api-url http://oombra-server:8000

# Machine-readable for AI agents
oombra report incident_iocs.json --api-url http://oombra-server:8000 --json
```

### Python (3 lines)

```python
from oombra import load_file, anonymize, submit

data  = load_file("incident_iocs.json")
clean = [anonymize(d) for d in data]
[submit(c, api_url="http://oombra-server:8000") for c in clean]
```

### What you give vs what you get

| You give | oombra anonymizes | You get back |
|----------|------------------|-------------|
| IOCs from your incident | HMAC-hashed with your org's key | "You match a campaign hitting 4 other orgs. Block these C2 domains." |
| MITRE ATT&CK observations | Notes scrubbed, org details removed | "Your tools miss T1490. SentinelOne catches it. Here's the detection rule." |
| Tool evaluation scores | DP noise added, context bucketed | "CrowdStrike scores 9.2 avg. Above average but has known gaps in VSS deletion." |

**The report only works because other orgs contributed too.** Your data makes the next person's report better. Their data made yours possible.

---

## The Hospital Scenario

It's 2AM. A children's hospital in Ohio gets hit with LockBit. EHR encrypted. Patient records locked. The IR team pulls IOCs and runs:

```bash
oombra report lockbit_iocs.json --api-url http://oombra-server:8000
```

The report comes back:

> **Campaign Match: Yes.** Your IOCs match indicators seen by 3 other healthcare orgs.
> **Detection Gap: T1490** (Inhibit System Recovery) — your tools miss it. SentinelOne catches it.
> **Action: Deploy vssadmin shadow delete detection rule. Priority: CRITICAL.**

Two hundred miles away, a trauma center in Pennsylvania ran the same command an hour ago. Their data is what made Ohio's report possible. And Ohio's contribution just made the next hospital's report even better.

The rural hospital in West Virginia — smallest budget, hit hardest — runs `oombra report` and gets real practitioner scores to justify their next tool purchase to the board. Not vendor marketing. Real data from real incidents.

**Without oombra:** Each hospital fights alone. Same attacker. Same gaps. Same outcome.
**With oombra:** They discover it's one campaign in minutes. They close the detection gap before the next hospital gets hit.

---

## What Happens to Your Data

Everything is anonymized **on your machine** before it touches the network.

| What you share | What oombra does | What leaves your machine |
|---------------|-----------------|------------------------|
| Raw IOCs | HMAC-SHA256 with your org's secret key | Only keyed fingerprints — can't be reversed |
| Attack observations | 4-pass PII/security scrubbing | Technique IDs + scrubbed notes — no org details |
| Org context | k-anonymity bucketing | `healthcare`, `1000-5000` — never your name |
| Tool scores | Calibrated Laplace noise | DP-noised values — can't pinpoint your exact score |
| Everything | ADTC attestation chain | Cryptographic proof all privacy steps were applied |

You review what leaves. You approve what's sent. The math proves nothing identifying gets through.

---

## Server

```bash
oombra serve --port 8000                    # SQLite (zero config)
oombra serve --db postgresql+asyncpg://...  # PostgreSQL
docker compose up                           # Docker
```

### API

| Endpoint | What it does |
|----------|-------------|
| `POST /analyze` | **The main endpoint.** Submit data, get intelligence report back. |
| `POST /contribute/ioc-bundle` | Submit IOCs (no report) |
| `POST /contribute/attack-map` | Submit attack map (no report) |
| `POST /contribute/submit` | Submit tool evaluation (no report) |
| `GET /query/techniques` | Top MITRE techniques across all contributors |
| `GET /query/category/{name}` | Aggregated tool scores in a category |
| `GET /query/vendor/{name}` | Aggregated scores for a vendor |
| `GET /stats` | Contribution counts |

API key auth: set `OOMBRA_API_KEY` env var. Min-k privacy: aggregates require 3+ contributors (configurable via `OOMBRA_MIN_K`).

---

## Privacy Guarantees

| Attack | Defense |
|--------|---------|
| IOC rainbow tables | HMAC-SHA256 with per-org secret key |
| IOC list exposure during comparison | ECDH Private Set Intersection |
| PII in submitted data | 4-pass regex scrubbing + Verifiable Absence Proof |
| Org identification | k-anonymity bucketing |
| Score inference | Differential privacy (Laplace noise) |
| Skipped anonymization | ADTC attestation chain |
| Data poisoning | Byzantine aggregation + ZKP range proofs |

Full analysis: [THREAT_MODEL.md](THREAT_MODEL.md)

---

## Demo

```bash
./demo/run_demo.sh    # Full hospital scenario
```

## Tests

```bash
pytest    # 248 tests across 11 files
```

---

## License

Apache 2.0
