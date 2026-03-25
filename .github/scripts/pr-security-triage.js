#!/usr/bin/env node
/**
 * Quell - PR & Security Triage
 * Triages open PRs and Dependabot security alerts using Gemini.
 *
 * Triggered by:
 *   - schedule (Mon/Fri): full run across all open PRs + alerts
 *   - pull_request_target: triage a single PR on open/update
 *   - dependabot_alert (created/reintroduced): create a tracking issue
 *
 * Required secrets: GEMINI_API_KEY
 * Required token permissions: contents:write, pull-requests:write, issues:write, security-events:read
 */

const GEMINI_MODEL = 'gemini-3.1-flash-lite-preview';

const GITHUB_TOKEN  = process.env.GITHUB_TOKEN;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const EVENT_NAME    = process.env.GITHUB_EVENT_NAME;
const PR_NUMBER     = process.env.PR_NUMBER ? parseInt(process.env.PR_NUMBER, 10) : null;
const [OWNER, REPO] = (process.env.GITHUB_REPOSITORY || '').split('/');

// ---------------------------------------------------------------------------
// GitHub API helper
// ---------------------------------------------------------------------------

async function gh(path, options = {}) {
  const res = await fetch(`https://api.github.com${path}`, {
    method: options.method || 'GET',
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (res.status === 204) return null;

  const data = await res.json();

  if (!res.ok) {
    throw new Error(`GitHub API [${options.method || 'GET'} ${path}]: ${res.status} - ${JSON.stringify(data?.message || data)}`);
  }

  return data;
}

// ---------------------------------------------------------------------------
// Gemini API helper
// ---------------------------------------------------------------------------

async function callGemini(prompt) {
  if (!GEMINI_API_KEY) {
    console.warn('GEMINI_API_KEY not set — returning placeholder analysis.');
    return 'AI analysis unavailable (no API key configured).';
  }

  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 1500 },
      }),
    }
  );

  const data = await res.json();

  if (!res.ok) {
    throw new Error(`Gemini API error: ${JSON.stringify(data?.error || data)}`);
  }

  return data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? 'No response returned by Gemini.';
}

// ---------------------------------------------------------------------------
// PR triage
// ---------------------------------------------------------------------------

async function getPRDiff(prNumber) {
  const res = await fetch(
    `https://api.github.com/repos/${OWNER}/${REPO}/pulls/${prNumber}`,
    {
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: 'application/vnd.github.v3.diff',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    }
  );

  if (!res.ok) return '(diff unavailable)';

  const text = await res.text();
  // Cap at 8 000 chars to stay within Gemini token limits
  return text.length > 8000 ? `${text.slice(0, 8000)}\n\n... (diff truncated at 8 000 chars)` : text;
}

async function triagePR(prNumber) {
  console.log(`\nTriaging PR #${prNumber}...`);

  const pr = await gh(`/repos/${OWNER}/${REPO}/pulls/${prNumber}`);

  if (!pr || pr.state !== 'open') {
    console.log(`PR #${prNumber} is not open, skipping.`);
    return;
  }

  const diff = await getPRDiff(prNumber);
  const isDepBot = pr.user?.login === 'dependabot[bot]';

  const prompt = `You are a security-aware code reviewer for Quell — a VSCode extension that intercepts AI chat prompts, detects secrets and credentials, and replaces them with safe placeholders before they leave the user's machine.

Triage the following pull request and respond using EXACTLY this format (keep headings, use plain text values):

## Summary
(1–2 sentences describing what the PR does)

## Security Concerns
(Bullet list of any XSS, injection, secret exposure, insecure dependency, regex bypass, or other issues — or write "None identified")

## Risk Level
LOW | MEDIUM | HIGH

## Auto-merge Safe
YES | NO
(For dependency bumps: YES only if patch or minor version, no known CVEs, no breaking changes. Always NO for code changes.)

## Recommendation
MERGE | REQUEST_CHANGES | NEEDS_REVIEW

---

PR #${prNumber}: ${pr.title}
Author: ${pr.user?.login}
Is Dependabot: ${isDepBot}
Description: ${pr.body?.slice(0, 500) || '(none)'}

Diff:
\`\`\`diff
${diff}
\`\`\``;

  const analysis = await callGemini(prompt);

  const autoMergeSafe  = /auto-merge safe[\s\S]*?YES/i.test(analysis);
  const riskIsLow      = /risk level[\s\S]*?LOW/i.test(analysis);
  const shouldMerge    = isDepBot && autoMergeSafe && riskIsLow;

  const autoMergeNote  = shouldMerge
    ? '\n\n> **Auto-merging:** Dependabot update assessed as low-risk and safe to merge automatically.'
    : '';

  // Post triage comment
  await gh(`/repos/${OWNER}/${REPO}/issues/${prNumber}/comments`, {
    method: 'POST',
    body: {
      body: `## 🤖 AI Triage Report\n\n${analysis}${autoMergeNote}\n\n---\n*Powered by Gemini (${GEMINI_MODEL}) · Quell Triage*`,
    },
  });

  console.log(`Posted triage comment on PR #${prNumber}`);

  // Auto-merge safe Dependabot dependency bumps
  if (shouldMerge) {
    try {
      await gh(`/repos/${OWNER}/${REPO}/pulls/${prNumber}/merge`, {
        method: 'PUT',
        body: {
          merge_method: 'merge',
          commit_title: `chore: merge PR #${prNumber} — ${pr.title}`,
        },
      });
      console.log(`Auto-merged PR #${prNumber}`);
    } catch (err) {
      console.warn(`Could not auto-merge PR #${prNumber}: ${err.message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Security alert triage — creates GitHub issues for open critical/high alerts
// ---------------------------------------------------------------------------

async function triageSecurityAlerts() {
  console.log('\nChecking open Dependabot security alerts (critical + high)...');

  let alerts = [];

  try {
    alerts = await gh(
      `/repos/${OWNER}/${REPO}/dependabot/alerts?state=open&severity=critical%2Chigh&per_page=30`
    );
  } catch (err) {
    console.warn(`Could not fetch Dependabot alerts (check security-events permission): ${err.message}`);
    return;
  }

  if (!Array.isArray(alerts) || alerts.length === 0) {
    console.log('No open critical/high Dependabot alerts found.');
    return;
  }

  console.log(`Found ${alerts.length} alert(s). Checking for existing tracking issues...`);

  // Fetch existing security-alert issues to avoid duplicates
  const existing = await gh(
    `/repos/${OWNER}/${REPO}/issues?labels=security-alert&state=open&per_page=100`
  );
  const existingTitles = new Set((existing || []).map(i => i.title));

  for (const alert of alerts) {
    const severity = (alert.security_advisory?.severity || 'unknown').toUpperCase();
    const pkg      = alert.dependency?.package?.name || 'unknown-package';
    const summary  = alert.security_advisory?.summary || pkg;
    const title    = `[Security] ${summary} (${severity})`;

    if (existingTitles.has(title)) {
      console.log(`Issue already exists for: ${title}`);
      continue;
    }

    const cveId       = alert.security_advisory?.cve_id   || 'N/A';
    const ghsaId      = alert.security_advisory?.ghsa_id  || 'N/A';
    const cvssScore   = alert.security_advisory?.cvss?.score;
    const fixedIn     = alert.security_vulnerability?.first_patched_version?.identifier;
    const vulnRange   = alert.security_vulnerability?.vulnerable_version_range || 'see advisory';
    const manifest    = alert.dependency?.manifest_path || 'unknown';
    const description = alert.security_advisory?.description?.slice(0, 1000) || 'See advisory link.';

    const body = `## Security Alert: ${summary}

| Field | Value |
|---|---|
| **Severity** | ${severity}${cvssScore ? ` (CVSS ${cvssScore})` : ''} |
| **Package** | \`${pkg}\` |
| **Vulnerable range** | ${vulnRange} |
| **Fixed in** | ${fixedIn ? `\`${fixedIn}\`` : 'No fix available yet'} |
| **CVE** | ${cveId} |
| **GHSA** | ${ghsaId} |
| **Manifest** | \`${manifest}\` |

### Description
${description}

### Action Required
${fixedIn
  ? `Upgrade \`${pkg}\` to \`${fixedIn}\` or later. Run \`npm update ${pkg}\` or update \`package.json\` directly.`
  : `No fix is available yet. Consider whether this package can be replaced or whether a mitigating control can be applied.`
}

[View Dependabot Alert](${alert.html_url})

---
*Auto-created by Quell PR & Security Triage · ${new Date().toISOString().split('T')[0]}*`;

    await gh(`/repos/${OWNER}/${REPO}/issues`, {
      method: 'POST',
      body: { title, body, labels: ['security-alert'] },
    });

    console.log(`Created tracking issue: ${title}`);
  }
}

// ---------------------------------------------------------------------------
// Scheduled full run — triage all open PRs + security alerts
// ---------------------------------------------------------------------------

async function scheduledRun() {
  console.log('Running scheduled triage (all open PRs + security alerts)...');

  const prs = await gh(`/repos/${OWNER}/${REPO}/pulls?state=open&per_page=30`);

  for (const pr of (prs || [])) {
    // Skip if we already posted a triage comment in the last 3 days
    const comments = await gh(
      `/repos/${OWNER}/${REPO}/issues/${pr.number}/comments?per_page=50`
    );

    const cutoff = Date.now() - 3 * 24 * 60 * 60 * 1000;
    const alreadyTriaged = (comments || []).some(
      c =>
        c.user?.login === 'github-actions[bot]' &&
        c.body?.includes('AI Triage Report') &&
        new Date(c.created_at).getTime() > cutoff
    );

    if (alreadyTriaged) {
      console.log(`PR #${pr.number} recently triaged — skipping.`);
    } else {
      await triagePR(pr.number);
    }
  }

  await triageSecurityAlerts();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main() {
  if (!GITHUB_TOKEN) throw new Error('GITHUB_TOKEN environment variable is required.');

  console.log(`Repo: ${OWNER}/${REPO} | Event: ${EVENT_NAME}`);

  switch (EVENT_NAME) {
    case 'pull_request_target':
    case 'pull_request':
      if (!PR_NUMBER) throw new Error('PR_NUMBER is required for pull_request events.');
      await triagePR(PR_NUMBER);
      break;

    case 'dependabot_alert':
      await triageSecurityAlerts();
      break;

    case 'schedule':
    default:
      await scheduledRun();
      break;
  }

  console.log('\nTriage complete.');
}

main().catch(err => {
  console.error('Triage script failed:', err.message);
  process.exit(1);
});
