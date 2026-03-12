# Security Policy

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in Quell, please report it responsibly via **GitHub's private vulnerability reporting**:

1. Go to the [Security tab](https://github.com/craigmccart/Quell/security)
2. Click **"Report a vulnerability"**
3. Describe the issue in detail

You can also email directly at the address listed on the GitHub profile.

We aim to respond within **48 hours** and will keep you updated throughout the fix process. We appreciate responsible disclosure.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Active support |
| 1.x     | ❌ No longer maintained |

---

## Security Design Principles

Quell is built with a security-first architecture. The following principles are non-negotiable and any contribution that violates them will be rejected:

### 🔒 100% Offline
Quell makes **zero network calls**. No telemetry, no analytics, no external API calls of any kind. All secret detection runs entirely on your local machine.

**Any PR that introduces network calls will be immediately closed.**

### 🔑 Secrets Never Leave the Machine
Detected secrets are stored exclusively in VS Code's `SecretStorage` API, which maps to your OS Keychain (Windows Credential Manager / macOS Keychain / libsecret on Linux). They are never written to disk in plaintext and never transmitted anywhere.

### 🧪 Test Fixtures Are Not Real Credentials
The `playground/.env` and `src/test/SecretScanner.test.ts` files contain fake, clearly-example credentials for testing purposes only. They follow official documentation formats (e.g. AWS's own example key `AKIAIOSFODNN7EXAMPLE`) and have no real access to any systems.

---

## Contribution Security Requirements

All contributors must adhere to the following:

### Before Submitting a PR
1. **Run Quell on your own changes** — use `Ctrl+Shift+C` (Copy Redacted) or scan the workspace
2. **No real credentials** — test fixtures must use obviously fake values (e.g. `sk_test_EXAMPLE`, not a real key)
3. **No new runtime dependencies** that have network access or broad file system access
4. **All new regex patterns** must include corresponding unit tests in `SecretScanner.test.ts`
5. **`npm run compile`** must pass cleanly with zero TypeScript errors
6. **`npm test`** must pass with all existing test cases still passing

### What We Review in Every PR
- All changes to `SecretScanner.ts` (detection logic) — reviewed carefully for false positives and bypasses
- All changes to `extension.ts` (clipboard, file operations) — reviewed for data leakage risks
- All changes to `package.json` — new dependencies are scrutinised
- All changes to `.github/` workflow files — reviewed for supply chain risks

### Branch Protection
The `main` branch requires:
- At least **1 approving review** before merge
- All status checks to pass
- No force pushes

---

## Dependency Management

Dependencies are kept minimal by design. We use [Dependabot](.github/dependabot.yml) to automatically open PRs for dependency updates on a weekly basis.

When reviewing Dependabot PRs:
- Check the changelog for the updated package
- Verify no new permissions or network capabilities have been introduced
- Run `npm test` to confirm nothing is broken

---

## Scope

The following are **in scope** for vulnerability reports:

- Secret detection bypasses (a malformed key that Quell fails to catch)
- False negative patterns (real credentials that regularly evade detection)
- Data exfiltration risks (anything that could send data off the machine)
- Privilege escalation via the VS Code extension host

The following are **out of scope**:

- False positives (non-secrets being flagged) — report as a regular GitHub issue
- Feature requests — open a regular GitHub issue
- Vulnerabilities in VS Code itself or third-party IDEs

---

## Acknowledgements

We thank all security researchers who responsibly disclose issues. Significant findings will be credited in the changelog unless you prefer to remain anonymous.
