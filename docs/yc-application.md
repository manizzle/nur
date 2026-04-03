# YC Application — nur (Summer 2026)

## Founders

### Who writes code, or does other technical work on your product? Was any of it done by a non-founder?

I write all the code. Solo founder — the entire platform (server, CLI, trustless protocol, 37 feed scrapers, 616 tests) was built with AI-assisted coding using Claude Code. No non-founder technical work.

### Are you looking for a cofounder?

Open to a technical cofounder with security industry GTM experience — someone who has sold to CISOs or run a security product. Not blocking on it.

## Company

### Company name

nur

### Describe what your company does in 50 characters or less

Anonymized peer intelligence for security teams

### Company URL

https://nur.saramena.us

### Product link

https://nur.saramena.us

### What is your company going to make?

nur helps security teams make better vendor decisions by showing them what their peers actually use, what it costs, and what works — all anonymized.

Security practitioners waste months on vendor evaluations with no systematic way to learn from peers. The status quo is ad hoc: Slack DMs, Gartner (pay-to-play), and internal bakeoffs that reflect one org's experience. ISACs are structurally failing — MS-ISAC just lost federal support, participation is in freefall.

nur fixes this with a give-to-get protocol. Connect your SIEM via webhook or submit evaluations through a web form. nur aggregates everything — vendor scores, pricing, detection rates, threat observations — and returns collective intelligence. You see what peers across your vertical actually use, what they pay, and what stopped real attacks.

The protocol makes contribution effortless and privacy mathematical. The server can't see individual data — it only stores aggregates. Contributors get cryptographic receipts. Consumers verify proofs. Federal law (CISA 2015) provides liability safe harbor.

Think Bloomberg Terminal for cybersecurity — where the community is worth more than the data. Bloomberg's most-used feature is chat between traders. nur's equivalent is the peer intelligence layer: a practitioner who contributed 30 vendor evals is more credible than a random Gartner analyst.

The wedge is vendor evaluation. The platform expands to incident response intelligence, threat data sharing, and cyber insurance underwriting — every domain where practitioners have data and peers need it.

### Where do you live now, and where would the company be based after YC?

San Francisco Bay Area, USA / San Francisco, USA

### Explain your decision regarding location

Already based in the Bay Area. Security vendor ecosystem, enterprise buyers, and YC network are all here. No relocation needed.

## Progress

### How far along are you?

Live at nur.saramena.us. Working product with: 616 tests passing, 37 live threat feeds scraping 658,000+ IOCs, 3,000+ vendors in evaluation taxonomy, full CLI (pip install nur), trustless cryptographic protocol (Pedersen commitments, Merkle trees, aggregate-only responses), behavioral anti-poisoning engine, invite-only referral system, Slack remediation notifications, vendor demo marketplace with profile pages.

Pre-revenue, pre-customers. Infrastructure-first build — now entering demand validation phase. In active pilot conversations with a security practitioner at PG&E through WWT (enterprise reseller), scoped at 90 days for vendor evaluation and org optimization decisions.

### How long have each of you been working on this? How much of that has been full-time?

Solo founder, ~4 weeks of building. The entire platform was built with AI-assisted coding (Claude Code). Currently alongside my role at Google — transitioning to full-time. This compression is the thesis: one person with AI can build what used to take a team of 20.

### What tech stack are you using, or planning to use, to build this product?

Python (FastAPI), PostgreSQL, Docker, GitHub Actions CI/CD. Cryptographic layer: Pedersen commitments, Merkle trees, differential privacy (custom implementation). 37 threat feed scrapers (Python). CLI distributed via pip. AI-assisted development: Claude Code (Anthropic) for ~90% of code generation. Deployed on cloud infrastructure with auto-rollback on failed deploys.

### Are people using your product?

No

### Do you have revenue?

No

### If you are applying with the same idea as a previous batch, did anything change?

First YC application. Previously interviewed at Alliance DAO. Since then: rewrote messaging to lead with value (vendor eval decision support) instead of crypto/protocol language. Hardened the protocol (IOC salt rotation, behavioral differential privacy). Added expanded vendor evaluation schema (price, support, detection, performance, decision intel). Entered active pilot conversations with PG&E through WWT.

### If you have already participated or committed to participate in an incubator, "accelerator" or "pre-accelerator" program, please tell us about it.

Interviewed at Alliance DAO (crypto accelerator). Did not join — decided nur's value proposition leads with security intelligence, not crypto infrastructure.

## Idea

### Why did you pick this idea to work on? Do you have domain expertise in this area?

I've spent 15 years in offensive security — staff hardware security engineer at Google breaking secure boot and firmware, before that Square's security team, Visa's mobile red team, and founding engineer at SourceDNA (YC S15, acquired by Apple). I also built ByteBack, a crypto hardware wallet recovery service where I physically break into locked Trezor/Ledger devices.

I've lived this problem on both sides. During incident response, I couldn't get peer intelligence — no scalable way to know if other orgs saw the same campaign or which tools caught it. During vendor evaluations, I wasted months on bakeoffs that reflected only our experience. When I asked peers how they evaluated tools, every single one said: "We did a bakeoff, but we have no idea if our results are typical."

The security industry has a fundamental information asymmetry: attackers share everything (tools, techniques, infrastructure), defenders share nothing. Not because they don't want to — because there's no easy, incentive-aligned way to do it. ISACs tried legal agreements. Threat intel platforms tried centralization. Both failed. nur makes contribution effortless (SIEM webhook, web form) and immediately rewarding (you get back aggregate peer intelligence the moment you contribute).

### Who are your competitors? What do you understand about your business that they don't?

Competitors:
- Gartner/Forrester ($50-100K/yr): Pay-to-play, vendor-biased, lagging. Not practitioner truth.
- G2/TrustRadius/PeerSpot: Reviews but no privacy, no aggregation, gameable. Anyone can leave a fake review.
- Filigran ($102M raised): Open-source threat intel. No anonymized peer data aggregation — contributors can be identified. nur's protocol makes deanonymization mathematically impossible.
- Cyware (serves MTS-ISAC): Enterprise threat intel orchestration. Expensive, centralized trust model. nur is open source and protocol-native.
- ISACs (FS-ISAC, E-ISAC): Structurally failing. Hub-and-spoke model, stale PDF reports, declining participation. MS-ISAC just lost federal support.
- Informal Slack/Signal groups: Work but don't scale. No privacy guarantees. Depends on who you know.

What we understand: the sharing problem isn't a technology problem or a legal problem — it's an incentive and effort problem. Everyone focused on building trust through legal agreements (ISACs) or centralized platforms (Cyware). We make contribution effortless (connect your SIEM, data flows automatically) and immediately rewarding (you see peer intelligence the moment you contribute). The cryptographic protocol is the moat underneath — but the hook is the value, not the math.

### How do or will you make money?

Three tiers:
- Community (free): Contribute data, get basic intelligence. This is the data acquisition engine.
- Pro ($99/mo): Vendor comparison matrices, threat coverage analysis, decision memos, market maps.
- Enterprise ($499/mo): API access, vendor intelligence dashboard, compliance reports, RFP generation, priority support.

Additionally, vendors pay for featured listings, verified badges, and lead generation ($2-5K/mo) — the G2 model but with cryptographically verified practitioner data.

Long-term: nur is a data marketplace. Free to contribute (supply side), monetize the demand side (intelligence products, professional services, cyber insurance underwriting data). At scale, the cross-vendor intelligence data is worth more to buyers than any single vendor's own analytics.

### Which category best applies to your company?

B2B / Security

### Other ideas you considered

- ByteBack (getbyteback.com): Crypto hardware wallet recovery service. Already operating — I physically break into locked Trezor/Ledger wallets using hardware security skills from my day job. Revenue-generating but services business, not a scalable product.
- ISAC-as-a-service: Modern infrastructure to replace failing ISACs. Decided this is a feature of nur, not a separate company — and the sales cycle to ISACs is too long for early stage.
- Cyber insurance underwriting platform: Use anonymized security data to help insurers price policies using real practitioner data instead of questionnaires. Decided this is a downstream use case of nur's data, not the wedge.

## Equity

### Have you formed ANY legal entity yet?

_TODO: Answer this_

### Have you taken any investment yet?

_TODO: Answer this_

### Are you currently fundraising?

_TODO: Answer this_

## Curious

### What convinced you to apply to Y Combinator?

Two things. First, I was founding engineer at SourceDNA (YC S15, acquired by Apple) — I saw firsthand how YC batch pressure and the partner network accelerated everything. I need that pressure again: I've built too much infrastructure and not enough customer validation. YC would force me to stop building and start selling.

Second, the network. My first 10 design partners need to be security directors at critical infrastructure orgs — energy, water, transportation. YC's network gets me in those rooms faster than cold outreach.

### How did you hear about Y Combinator?

Former colleague at SourceDNA (YC S15). Also referred by Tariq Patanam (Alliance DAO).

## Batch Preference

Summer 2026

## Still Needed

- [ ] Founder video (1 minute, introducing yourself)
- [ ] Demo video (optional, 3 min max, shows how product works)
- [ ] Coding agent session export (optional, .md or .txt)
- [ ] Answer equity questions (legal entity, investment, fundraising)
- [ ] Login credentials if product requires auth
