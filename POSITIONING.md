# Quell - Positioning & Monetisation Plan

*Last updated: 2026-04-09*

## One-line pitch

**Quell is the last line of defence before your API keys hit Claude, Copilot, or Cursor.**

Not another secret scanner. Not another CI gate. A point-of-use interceptor that lives where the leak actually happens: the moment a developer copies, pastes, or types into an AI chat.

## The problem, sharpened

Existing tools (GitGuardian, TruffleHog, Gitleaks) catch secrets at commit time or after they land in a repo. By then, if the developer pasted that secret into Cursor or Copilot Chat an hour earlier, the key is already on someone else's GPU. The attack surface has moved upstream from git, and nobody is defending it.

Quell sits at that exact point: clipboard, chat panel, editor save. It is the only tool designed for the vibe-coder workflow where "paste my .env and ask why it's broken" is a normal Tuesday.

## Who it's for

**Primary**: Solo developers and small teams using AI-first IDEs (Cursor, Windsurf, Antigravity, Copilot Chat). They don't have a security team. They know they shouldn't paste secrets. They do it anyway because the friction of redacting by hand is too high.

**Secondary**: Indie hackers and vibe coders shipping side projects on Vercel/Supabase/Railway. Their threat model isn't a determined attacker, it's "I leaked a Stripe live key into a chat transcript that Anthropic may retain for 30 days".

**Tertiary (paid tier)**: Small security-conscious teams (3-20 devs) in regulated-ish industries (fintech, healthtech) who want an auditable record that developers didn't leak PII or credentials into third-party AI.

## Why the current numbers are low

OpenVSX 484 / 7 and Marketplace 65 in 30 days are not a product-quality signal. They are a distribution signal. The extension:

- Has no screenshots on the marketplace listing (the README has a commented-out screenshot block)
- Has not been launched anywhere (no HN, no Reddit, no Product Hunt, no dev.to post)
- Has no SEO footprint (nothing links to github.com/sonofg0tham/Quell)
- Is not in any "awesome-list" yet
- Has no social proof (no testimonials, no review count)

Fix those and the numbers move. The product itself is in good enough shape to support a launch *after* round one fixes ship.

## Free vs Paid split

### Quell (Free, MIT, forever)

The entire current feature set stays free. Do not cripple the free tier to create artificial scarcity.

- Core `SecretScanner` with 75+ regex patterns
- Shannon entropy analysis
- OS Keychain storage via VSCode SecretStorage
- Sidebar dashboard
- AI Indexing Shield (`.cursorignore` etc.)
- Sanitised Paste / Copy Redacted
- Chat participant (`@quell`)
- Save warnings, inline diagnostics, Quick Fix
- Walkthrough / onboarding

The free tier is the marketing. Do not touch it.

### Quell Pro (one-off or subscription, £3-5/mo or £30 one-off)

Features that provide ongoing value or target teams:

1. **Pattern Packs** - Curated, regularly-updated pattern libraries for specific stacks: FinTech Pack (Plaid, Stripe Connect, bank SWIFT, Adyen, Wise), Healthcare Pack (HL7, FHIR bearer tokens, Epic MyChart OAuth), Web3 Pack (Infura, Alchemy, WalletConnect, private keys with checksum detection). Subscribers get auto-updates when new key formats appear.
2. **Policy Files** - `.quellrc` support for org-wide rules: mandatory redaction on specific file globs, custom placeholder formats, per-project whitelists, commit-hook enforcement.
3. **Audit Log Export** - CSV/JSON export of every redaction event (file, type, timestamp, no values). Sellable to anyone who has to fill in a compliance questionnaire.
4. **Custom Entropy Profiles** - Tuned thresholds per file type (more aggressive in `.env`, relaxed in test files).
5. **Priority Support** - Named email, 48-hour response SLA.

### Quell CLI / GitHub Action (Free for public repos, £5/mo per private repo)

A standalone binary built from the extracted `@sonofgotham/quell-scanner` package. Same engine, different distribution.

- `quell scan` on any directory
- GitHub Action: `uses: sonofg0tham/quell-action@v1` in a workflow
- Gate PRs on secret detection before merge
- Free for open source, paid per private repo

This is the highest-leverage paid surface because the code is already 90% written (it's just the scanner class) and it reaches developers who never install VSCode extensions.

### Quell Desktop (future, £10 one-off)

A native clipboard daemon for Windows/macOS that hooks the OS clipboard outside any IDE. Works with Cursor, Windsurf, ChatGPT in a browser, Claude Desktop, anywhere. Solves the problem that VSCode extensions can't reach.

Defer until Pro has paying users.

## Go-to-market (12-week plan)

### Weeks 1-2: Fix and polish
- Ship round-one bug fixes (see `FIX_PROMPTS/round-1.md`)
- Add 3 screenshots to README and marketplace listing
- Clean repo (drop old `.vsix` files, pick one lockfile)
- Add CodeQL workflow - "security tool scans itself" is a credibility badge
- Add CONTRIBUTING.md and issue templates

### Weeks 3-4: Extract the engine
- Create `@sonofgotham/quell-scanner` npm package from `src/SecretScanner.ts`
- Ship v1.0 to npm
- Refactor extension to depend on it
- Build CLI wrapper: `npx @sonofgotham/quell-scanner ./src`

### Weeks 5-6: CI surface
- Build GitHub Action using the npm package
- Publish to Marketplace
- Dogfood it on the Quell repo itself

### Weeks 7-8: Launch
- Write a launch post: "I'm a vibe coder pivoting into AppSec. I built Quell because I kept pasting my .env into Claude by accident."
- Post to: Hacker News (Show HN), r/cursor, r/LocalLLaMA, r/devops, dev.to, Product Hunt
- Submit to awesome-vscode, awesome-appsec, awesome-cursor
- Reach out to 5 AI-coding YouTubers with a 60-second demo

### Weeks 9-12: Pro
- Stand up Lemon Squeezy or Stripe checkout (one-off licences avoid subscription infra)
- Build the first Pattern Pack (FinTech)
- Ship `quell.proLicenseKey` setting that unlocks pro features
- Write the launch post for Pro once there are 500+ free users

## Strategic bets

1. **The scanner is the product. Everything else is a UI.** Extracting it into a standalone package unlocks every other surface (CLI, Action, Desktop). Do this before building new features.
2. **Point-of-use is the moat.** Don't compete with GitGuardian on scan quality. Compete on "it stops the leak before it happens, not after".
3. **Vibe-coder positioning is underserved.** Existing AppSec tools are pitched at security engineers. Quell is pitched at the developer who ships on Vercel and doesn't know what a VPC is. That's a much bigger audience and nobody else is talking to them.
4. **Free tier is marketing, not charity.** The extension is the storefront. Every free user is a potential Pro conversion, a GitHub star, and a word-of-mouth channel.
5. **Portfolio value compounds.** Even if Pro never earns a penny, shipping a standalone scanner package, a GitHub Action, CodeQL-gated CI, and a public launch post is the exact CV that AppSec hiring managers want to see. Monetisation and career pivot pull in the same direction.

## Success metrics (end of 12 weeks)

- 2,000+ total installs across Marketplace + OpenVSX (from ~550 today)
- 100+ GitHub stars (check current baseline first)
- 50+ npm weekly downloads of `@sonofgotham/quell-scanner`
- 5+ GitHub repos using the Action
- 1 paying Pro user (proof of concept, not revenue target)
- A launch post with 50+ upvotes somewhere
