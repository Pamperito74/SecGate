# Roadmap — Lucen + SecGate

> ⚠️ **LEGACY DOC — Lucen-era (2026-04-22).**
> "Lucen" was renamed to **LuxScope**. SecGate is now maintenance-only legacy track; enterprise tier deferred to Year 2 (post-1k LuxScope paying users).
> Current truth: `../../docs/ROADMAP.md` (Stelnyx-root) + LuxScope epic [#286](https://github.com/Stelnyx/LuxScope/issues/286).
> Kept for historical reference; do not act on it.

---

**Last updated:** 2026-04-22
**Strategy reference:** `docs/business-analysis.md`

---

## Product Direction

**Two products. One umbrella ("Dark code illumination"). Sequential build.**

| Product | Audience | Status | Priority |
|---------|----------|--------|----------|
| **Lucen** | Vibe coders, indie hackers, agencies | v0.0.0 — pre-build | **Build now** |
| **SecGate** | Series A startups pursuing SOC 2 | Working CLI prototype | Year 2 enterprise tier |

**North star:** *"Fastest way in the world to understand a codebase."*

Every feature must serve this. Cut anything that doesn't.

---

## Sequencing Logic

Lucen ships first because:
- Faster time to revenue (1–3 months vs 6–12)
- Self-serve viral distribution (no sales motion needed)
- Lower price point = lower buyer friction
- SecGate becomes natural enterprise upgrade path once Lucen has install base

SecGate stays alive as enterprise extension — not killed, just deferred.

---

## Phase 0 — Validation (1 week)

**Stop building until done.** Talk to 10 vibe coders.

- DM 50 indie hackers on Twitter/X — Cursor, Lovable, v0, Bolt users
- Post in r/SideProject + Cursor Discord asking 15-min calls
- Offer $20 Amazon gift card per call to filter serious responses
- Show mockup or 60-second demo video — no real product needed

**One question:**
> "If you could paste your repo URL and get architecture map + plain-English summary + risk overview in 60 seconds — what would you pay per month?"

**Then:**
> "What would make this a 'must have' vs 'nice to have'?"

**Capture:**
- Pricing intent
- Pressure events (investor, contractor, acquirer, audit)
- One-shot vs subscription preference
- Platform integrations requested

**Exit criteria:** 10 calls done. Pricing tiers validated or revised.

---

## Phase 0.5 — Manual Reports (Days 1–30)

**THIS is real validation.** Cards swiped, money in. Do things that don't scale.

**Goal:** 10 paid reports in first 30 days. Cash > strategy decks.

### Day 1–7: Free Pilot

DM 50 founders/week using validated script:

```
Hey — quick question.

If you had to explain your codebase to an investor tomorrow, could you?

I built a tool that turns any repo into a 1-page breakdown
(architecture, risks, what to fix first).

Want me to run yours? First one free.
```

Channels: Twitter/X, Reddit DMs, Cursor Discord, Lovable community, indie hacker forums.

Deliver 5 free reports. Capture testimonials + improvement signal.

### Day 8–14: First Paid

Charge $79 onboarding / $199 investor reports. Stripe Payment Link. No platform needed.

Run scans manually using internal CLI (already built — this is what CLI is for now).

### Day 15–30: Public Seeding

Post real outputs publicly:

> "I analyzed 10 indie SaaS repos. Here's what I found:"

Channels: Reddit (r/SideProject, r/IndieDev, r/cursor), Twitter/X threads, Hacker News.

Drives inbound. Inbound = warmest leads = highest conversion.

### Manual Report Spec

Universal sections (all tiers):
1. **TL;DR** — 3 bullets
2. **Architecture map** — Mermaid diagram
3. **Tech stack** — languages, frameworks, deps
4. **Top 5 risks** — brutal honesty
5. **What to read first** — file priority list
6. **Production readiness verdict** — yes/no/conditional

Tier-specific (see `docs/business-analysis.md` for full spec).

### Pricing (validated, do NOT discount)

| Tier | Price | Manual time | $/hr |
|------|-------|-------------|------|
| Onboarding Handoff | $79 | 1 hr | $79/hr |
| Investor Diligence | $199 | 2 hr | $99/hr |
| M&A Due Diligence | $499 | 4 hr | $124/hr |
| Acquisition Handoff | $999 | 6 hr | $166/hr |

**Brutal honesty rule:** if code is bad, say so. Sugar-coated reports = no referrals.

**Exit criteria:**
- 10 paid reports delivered
- 3 testimonials captured
- Repeated request patterns identified (= what to automate first)

---

## Phase 1 — Wow Demo (2 weekends)

Public, free, hosted. **This is the marketing engine.**

- Paste GitHub URL → 30 seconds → architecture map + plain English summary + risk overview
- Tweet-able output (clean visual, shareable image)
- Single page web app
- Free GitHub OAuth, no signup needed for first scan
- Watermark on shared output → drives signups

**Stack suggestion:** Next.js + tree-sitter wasm + Claude Haiku for explanations.

**Goal:** generate first viral wave. Capture emails. Build wait-list.

---

## Phase 2 — Lucen Core Engine (4–6 weeks)

The actual product foundation.

- Tree-sitter parser pool (TypeScript, JavaScript, Python first — covers 80% of vibe coder repos)
- SQLite index schema:
  - symbols, files, calls, imports, exports, summaries
  - git commit metadata
  - human annotations
- CLI commands:
  - `lucen analyze` — index a repo
  - `lucen explain <symbol|file|module>` — plain English
  - `lucen ask "<question>"` — RAG over index
  - `lucen graph <symbol>` — call graph output
  - `lucen risks` — heuristic risk flags (untyped exports, large functions, no tests, etc.)
- Local-only. Zero cloud calls.
- `.lucen/` folder layout:
  ```
  .lucen/
    index.db        # gitignored — local cache
    config.json     # committed — team shares config
    summary.md      # committed — onboarding doc
  ```

**Exit criteria:** can index any TS/JS/Python repo under 100k LOC in <60s on M1 laptop.

---

## Phase 3 — MCP + IDE Extension (2 weeks)

**Distribution velocity grab. Race vs Cursor native.**

- MCP server exposing tools to Cursor / Claude Code:
  - `search_symbols`, `call_graph`, `explain_module`, `risks_for_path`, `file_summary`
- VSCode extension wrapping CLI
- One-command install: `npx lucen install-mcp`
- Templates for Cursor `.cursor/mcp.json`
- Distribution focus: developer-facing posts, MCP catalog listings

**Exit criteria:** working MCP install in <60 seconds, 100+ installs in week one.

---

## Phase 4 — Hosted Web App + Cloud Sync (4 weeks)

**Paid tier launch.** Subscription billing live.

- Hosted web app (paste GitHub URL or upload .lucen/ archive)
- GitHub OAuth + connect repo
- Cloud index sync (raw code never stored — only symbols/calls/summaries/embeddings)
- AI explanations metered (Claude Haiku 4.5 default)
- PDF / HTML export (architecture diagram, module summaries, risk overview)
- Stripe integration
- **Pricing tiers live:**
  - Solo $19/mo — "Understand any repo instantly"
  - Pro $49/mo — "Ship faster with AI insights"
  - Team $149/mo — "Shared code intelligence for your team"
  - Agency $399/mo — "Multi-client codebase intelligence" **(white-label exports — mandatory or agencies churn)**

**Exit criteria:** 50 paying users, Stripe + dashboard live, churn measurable.

---

## Phase 4.5 — One-Shot Report Tier (1 week, parallel with Phase 4)

**Validated 25% of revenue. Pressure-event buyers refuse subscriptions.**

| Report | Price | Use case |
|--------|-------|----------|
| **Onboarding Handoff** | $79 | Hand to new contractor/dev |
| **Investor Diligence** | $199 | Tech overview for fundraise |
| **M&A Due Diligence** | $499 | Buyer-ready codebase health |
| **Acquisition Handoff** | $999 | Full architecture + deps + risks bundle |

Implementation:
- One-time Stripe checkout, no account required
- Email-delivered PDF
- Branded templates per tier
- Built on top of Phase 4 export engine

**Distribution:** sell to M&A brokers, investor newsletters, agency directories.

**Exit criteria:** 5 paid reports in first month.

---

## Phase 5 — GitHub App + Slack Bot + Weekly Auto-Reports (3 weeks)

**Team-champion conversion trigger (validated 2/20).**

- GitHub App: auto-reindex on push, webhook integration
- Slack bot:
  - Post findings to team channel
  - Reply to "@lucen explain X" queries
  - Approve via emoji reaction
- Weekly auto-report email:
  - What changed this week
  - New risks introduced
  - Team activity summary

**Exit criteria:** 20 teams using Slack bot, weekly report sent.

---

## Phase 6 — Platform Integrations (2 weeks)

**Validated request from Lovable/Replit/Cursor users (3/20).**

- One-click connect from Lovable projects
- Replit deploy hook integration
- Cursor sidebar deep-link
- Bolt.new project import

**Why:** non-technical founders won't run CLI. Reduce friction to zero.

**Exit criteria:** integrations live for 2+ platforms, conversion rate from those funnels measurable.

---

## Phase 7 — Compliance Bridge + SecGate Enterprise (year 2)

**Only after Lucen has 1,000+ paying users.**

### Compliance Bridge — $799/mo
- Agency tier features
- SOC 2 / SOC 1 / HIPAA control mapping
- Auditor-friendly PDF templates
- Static control-to-finding JSON mapping
- Bridge tier between Agency and full Enterprise

### SecGate Enterprise — Custom $2k+/mo
- Full evidence workflow (review, approve, sign-off, export)
- Persistent attributed evidence store (user + repo + git hash + timestamp)
- Vanta / Drata integration (push approved findings as evidence)
- BAA signing for HIPAA buyers
- On-prem deploy option
- Polyglot scan support (Elixir, Rust, .NET via Lucen tree-sitter)

**Prerequisite:** hire someone with first-hand SOC 2 audit experience.

---

## API Layer (continuous, ships with Phase 4)

**Lucen as infrastructure, not product.**

- REST API exposing index queries
- Pricing: $0.002/query + $0.10/repo indexed
- Targets: CI/CD pipelines, agencies, automation
- Webhook notifications on reindex
- API keys, rate limits, usage dashboard

---

## Distribution Plan

### First 100 Customers (Phase 0.5 — Manual)

| Channel | Effort | Why |
|---------|--------|-----|
| **Direct DM** (validated script) | 50/week, manual | Highest ROI. Closes warmest leads. |
| **Public report seeding** | "I analyzed 10 indie SaaS repos…" | Drives inbound, builds reputation |
| **Reddit organic posts** | r/SideProject, r/IndieDev, r/cursor, r/ChatGPTCoding, r/nocode | Free distribution to ICP |
| **Twitter/X build-in-public** | Daily | Audience compounds |

### Customers 101+ (Phase 4+ — Self-Serve)

| Channel | Phase | Effort |
|---------|-------|--------|
| Product Hunt launch | Phase 4 | Coordinated with email list |
| AppSumo LTD ($59) | Phase 4 + 1 month | 1,000 paying users target |
| YouTube tutorials | Phase 2 onward | "I made AI explain my AI code" |
| Cursor Discord + Lovable community | Phase 3 onward | Organic engagement |
| Dev.to / Hashnode | Phase 2 onward | Technical write-ups |
| Creator partnerships | Phase 4 onward | Free Pro tier + affiliate |

---

## Defense Plan vs Platform Bundling

**Risk:** Cursor / GitHub / Claude Code ship "explain my codebase" natively in 6–12 months.

**Defenses to build NOW:**

| Defense | Phase | Status |
|---------|-------|--------|
| Polyglot beyond what they ship (Elixir, Rust, .NET, Erlang) | Phase 2 → Phase 7 | Roadmap |
| M&A / due diligence niche they won't bother with | Phase 4.5 | Built |
| Brand recognition in vibe-coder community | Phase 0 onward | Continuous |
| Index format `.lucen/` adoption (other tools read it) | Phase 5+ | Open spec needed |
| One-shot report tier (different unit economics) | Phase 4.5 | Built |
| Aggregated AI-code patterns (data network effect) | Year 2 | Future |

---

## 12-Month Revenue Targets

| Month | Free users | Subscription MRR | Report MRR | **Total MRR** |
|-------|-----------|------------------|------------|---------------|
| 3 | 500 | $1,113 | $856 | **$1,969** |
| 6 | 2,000 | $6,672 | $4,395 | **$11,067** |
| 12 | 8,000 | $28,836 | $13,310 | **$42,146** |

**Floor (no viral hit):** $5–12k MRR.
**Ceiling (Product Hunt + AppSumo + viral moment):** $42k MRR ($506k ARR).

---

## SecGate (Legacy Track)

SecGate continues as standalone OSS CLI under existing repo.

| Phase | Status |
|-------|--------|
| Stabilize current scanner orchestration | Maintenance only |
| Position as input layer for Lucen + future Enterprise | Reposition README |
| Defer compliance workflow build | Until Phase 7 |

**Do not pour new effort into SecGate-only features** until Lucen reaches 1,000 paying users. SecGate becomes the enterprise tier on top of Lucen — not a separate product motion.

---

## Delivery Principle

1. **Charge before build.** Phase 0.5 manual reports = real validation. Cards swiped, money in.
2. **Do things that don't scale first.** Paste repo, run manually, hand-deliver PDF. Charge $79–$999.
3. **Free CLI = distribution, never charged.**
4. **Cloud sync + AI + exports = subscription product.**
5. **One-shot reports = pressure-event capture. 60–80% of early revenue.**
6. **MCP velocity = race vs Cursor native shipping.**
7. **White-label = day-one mandatory for Agency tier.**
8. **SecGate Enterprise comes after Lucen wins, not before.**
9. **Brutal honesty in reports > sugar-coated filler.** Reputation = referrals.

---

## Cut From Roadmap (was in scope, now removed)

- Documentation generation as standalone product (different buyer, distraction)
- Per-scan / per-API-call pricing (race to zero with incumbents)
- SOC 2 evidence workflow as Phase 1 (premature — wrong buyer for current state)
- "AI SOC Engine" branding for SecGate (marketing language, no LLM in code)
- Whitepaper generation as standalone feature (subset of report tier now)
