# TODOS

## P1 — Launch Blockers

### Legal: CISA 2015 Opinion Letter
**What:** Find a cyber law attorney and get a formal legal opinion letter confirming nur's data qualifies as "cyber threat indicators" under CISA 2015.
**Why:** Every enterprise customer conversation ends with "run this by legal." Without the opinion letter, their lawyer does the analysis from scratch and defaults to "no." With it, their lawyer calls your lawyer and gets a 2-page "this is fine."
**Budget:** ~$2-5K one-time
**Action items:**
- [ ] Contact 2-3 cyber law firms (Venable, Morrison Foerster, Cadwalader, or solo cyber law practitioner)
- [ ] Send them COMPLIANCE.md + translate_eval/translate_attack_map code showing what's stripped
- [ ] Get opinion letter covering: CISA 2015 applicability, CIRCIA non-triggering, NERC CIP non-triggering, SEC 8-K non-triggering
- [ ] Get Terms of Service + Privacy Policy drafted (~$1-2K additional)
- [ ] CISA 2015 expires September 2026 — monitor reauthorization
**Depends on:** Nothing — can start today
**Priority:** P1 — blocks enterprise conversations

### Legal: Terms of Service + Privacy Policy
**What:** ToS + Privacy Policy pages for nur.saramena.us
**Why:** No enterprise will use a platform without these. Also needed for GDPR if EU users contribute.
**Budget:** ~$1-2K (lawyer review of template)
**Action items:**
- [ ] Draft ToS covering AGPL licensing, data contribution terms, acceptable use
- [ ] Draft Privacy Policy covering what data is collected (hashed API keys, aggregate behavioral profiles), retention, GDPR
- [ ] Draft DPA template for Enterprise customers
- [ ] Add /terms and /privacy pages to the site
**Depends on:** Lawyer engagement from above
**Priority:** P1

---

## P1 — Product: First Customer

### Direct Outreach to Contact
**What:** Reach out to specific critical infrastructure contact with a 15-minute demo offer.
**Why:** One real conversation > 100 LinkedIn posts. The product is ready. The bottleneck is the founder, not the code.
**Action items:**
- [ ] Message: "I built something that lets security teams share vendor evaluations and attack data without revealing who they are — math, not promises. I'd love 15 minutes to show you."
- [ ] Have the 5-minute CLI demo ready (demo/demo.sh)
- [ ] Have COMPLIANCE.md ready for their legal team
**Depends on:** Nothing — can do today
**Priority:** P1

---

## P2 — Product Features

### Invite-Only / Referral System
**What:** Add invite codes so existing users can invite peers. Limits spam, builds community organically.
**Why:** Solves two problems: (1) anti-spam without heavy auth friction, (2) builds community through trust chains — security people trust referrals from peers.
**How it works:**
- Each registered user gets 3-5 invite codes
- New users need an invite code OR a work email to register
- Invite chains are tracked (who invited whom) for community growth metrics
- Invited users inherit a small credibility boost in BDP (their inviter vouched for them)
**Effort:** M (human: ~1 week / CC: ~30 min)
**Depends on:** Nothing
**Priority:** P2

### Web-Based Eval Form
**What:** A /contribute page on the website where non-security people can submit vendor evals without installing the CLI.
**Why:** Yushea has interested people who aren't going to install a CLI. Procurement teams, IT managers, MSP operators know pricing and support quality but won't use terminal tools.
**How it works:**
- User enters work email → magic link → logged in with API key in cookie
- Fill out eval form (vendor, scores, pricing, support, decision)
- Submit → hits POST /contribute/submit with API key
- Get receipt back
**Effort:** M (human: ~1 week / CC: ~30 min)
**Depends on:** Nothing — existing email verification flow supports this
**Priority:** P2

### Vendor Demo Marketplace
**What:** Vendor profile pages at /vendor/{name} showing practitioner aggregate scores + vendor-submitted demo videos.
**Why:** Creates a complete evaluation experience — truth layer (anonymous scores) + marketing layer (vendor demos). Revenue model: vendors pay for featured listings, lead gen metrics.
**Tiers:**
- Free listing: name + category + practitioner scores (already exists in aggregates)
- Demo listing: upload demo video/link + product description ($0 — want adoption)
- Featured: pinned in category, highlighted in comparisons ($2-5K/mo)
- Lead gen: anonymized interest metrics ("47 orgs watched your demo") (enterprise pricing)
**Effort:** L (human: ~2 weeks / CC: ~2 hours)
**Depends on:** Some eval data in the system first
**Priority:** P2

### PIR (Private Information Retrieval) for Queries
**What:** Allow users to query aggregates without the server knowing what they queried.
**Why:** Nate Lawson suggested this. Strengthens privacy story. Currently BDP tracks queries (conflicts with PIR).
**Sweet spot:** Use PIR for sensitive queries (which vendor you're evaluating) and BDP for general behavioral patterns (contribution types, integration sources). Poisoner detection still works because it's based on contribution behavior, not query behavior.
**Effort:** XL (human: ~2 months / CC: ~2 weeks) — real cryptographic PIR is complex
**Depends on:** Research into practical PIR implementations (SealPIR, SimplePIR)
**Priority:** P3 — nice to have, not launch blocking

### ADTC → ProofEngine Dice Chain Link
**What:** Wire the client-side ADTC (Attested Data Transformation Chain) to the server-side ProofEngine so there's an end-to-end cryptographic chain from raw data to final aggregate.
**Why:** Travis's "data dice chains" concept. Proves every transformation step was honest.
**How:** Client's last ADTC hash must match the server's contribution_hash in the receipt. If they match, the chain is verified end-to-end.
**Effort:** S (human: ~2 days / CC: ~30 min) — most of the code exists
**Depends on:** Nothing
**Priority:** P2

### Blind Token Payment System
**What:** Privacy Pass-style blind tokens for anonymous payment. Payment proxy issues tokens, nur server redeems without knowing who bought them.
**Why:** Strengthens trustless promise — even billing doesn't reveal identity.
**Effort:** L (human: ~3 weeks / CC: ~6 hours)
**Depends on:** Having paying customers first (premature until then)
**Priority:** P3

### Server-Side Build Attestation
**What:** Reproducible Docker builds or TEE (Nitro Enclaves) so anyone can verify the server code matches the source.
**Why:** Travis's concern: "so you know I haven't backdoored the server."
**Effort:** M for reproducible builds, XL for TEE
**Depends on:** Nothing for reproducible builds
**Priority:** P2

---

## P3 — Future

### ECDH PSI for Secure Threat Matching
**What:** Replace SHA-256 IOC hashing with Elliptic-Curve Diffie-Hellman Private Set Intersection.
**Why:** SHA-256 of IPv4 addresses is rainbow-table-attackable (only 2^32 possible IPs). ECDH PSI is mathematically secure.
**Effort:** XL
**Priority:** P3

### Shamir's Secret Sharing for Aggregation
**What:** Shred data into fragments so no single server holds raw information.
**Why:** Part of the full cryptographic pipeline (ZKP + SSS + Pedersen).
**Effort:** XL
**Priority:** P3

---

## Completed

- [x] Trustless pipeline integration (575→591 tests) — v0.19
- [x] Blind category discovery — v0.19
- [x] Public taxonomy (NIST/D3FEND/RE&CT) — v0.19
- [x] BDP behavioral profile tracking — v0.19
- [x] Expanded eval schema (price, support, performance, decision) — v0.19
- [x] COMPLIANCE.md — legal-ready regulatory analysis — v0.19
- [x] AGPL-3.0 + CLA dual licensing — v0.19
- [x] Site redesign (modern dark theme, Inter font) — v0.19
- [x] Server stability (health checks, watchdog, memory limits) — v0.19
- [x] Streamlined README (334→131 lines) — v0.19
- [x] Mermaid architecture diagram — v0.19
- [x] Narrated demo (demo/demo.sh) — v0.19
