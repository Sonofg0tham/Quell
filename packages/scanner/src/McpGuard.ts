// ─────────────────────────────────────────────
//  McpGuard — Model Context Protocol config auditing
//
//  MCP server configs are a first-rank credential leak source. Server install
//  instructions routinely tell you to paste an API token straight into the
//  config's `env` block, and those files get committed. They are also an
//  injection surface: a server's tool `description` is read by the model and
//  never by you, which is what makes tool poisoning work.
//
//  Detection is delegated, deliberately. SecretScanner already knows what a
//  credential looks like across 136 patterns plus entropy, and PromptGuard
//  already knows what an injected instruction looks like. A third, bespoke
//  "does this value look secret?" heuristic would mean a third false-positive
//  surface to tune, and config files are full of innocent version strings,
//  paths and flags that such a heuristic reliably mistakes for secrets. So this
//  module's job is purely structural: understand the shape of an MCP config,
//  pull out the parts that matter, and hand them to the engines already tuned
//  for the job.
//
//  Zero dependencies, no VS Code, same contract as the other engines.
// ─────────────────────────────────────────────

import { SecretScanner, ScannerConfig, DEFAULT_CONFIG } from './SecretScanner';
import { PromptGuard, GuardConfig, DEFAULT_GUARD_CONFIG } from './PromptGuard';

export type McpSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface McpFinding {
    type: string;
    severity: McpSeverity;
    /** Server the finding belongs to, when it can be attributed. */
    serverName?: string;
    /**
     * The config key that carried the problem — e.g. `env.GITHUB_TOKEN`.
     * The VALUE is never included. Quell's discipline is that a real secret
     * does not get copied into a finding, a log, or a report, and the module
     * whose whole purpose is finding secrets is the last place to break it.
     */
    key?: string;
    detail: string;
}

export interface McpScanResult {
    findings: McpFinding[];
    /** Number of servers understood. Zero on a parse failure. */
    serverCount: number;
    /** False when the document could not be parsed as an MCP config. */
    parsed: boolean;
    /** True when a bound was hit and the scan is therefore incomplete. */
    truncated: boolean;
}

export interface McpGuardConfig {
    scanner: ScannerConfig;
    guard: GuardConfig;
    /** Cap on description fields walked, to bound work on hostile input. */
    maxDescriptionSites: number;
    /** Cap on recursion depth when hunting for description fields. */
    maxWalkDepth: number;
}

export const DEFAULT_MCP_CONFIG: McpGuardConfig = {
    scanner: DEFAULT_CONFIG,
    guard: DEFAULT_GUARD_CONFIG,
    maxDescriptionSites: 500,
    maxWalkDepth: 32,
};

/**
 * A value that is ENTIRELY an indirection reference is the recommended pattern
 * and must never be flagged — flagging it would punish people for doing the
 * right thing.
 *
 * Anchored on purpose. Stripping references from anywhere inside a value would
 * quietly gut a real password that happens to contain a dollar sign followed by
 * letters, before it was ever scanned.
 */
const WHOLE_VALUE_INDIRECTION = /^\s*(?:\$\{[^}]{1,256}\}|\$[A-Za-z_][A-Za-z0-9_]{0,127}|%[A-Za-z_][A-Za-z0-9_]{0,127}%)\s*$/;

/** Blocks whose values are credential-shaped and worth scanning. */
const SCANNED_BLOCKS = ['env', 'headers', 'requestInit', 'auth'];

/** Keys whose string values are read by the model rather than by the user. */
const MODEL_FACING_KEY = /^(?:description|instructions?|prompt|summary|title)$/i;

export class McpGuard {

    /**
     * Recognises the real MCP config filenames across the tools that use them.
     * Handles both separators, because this ships on Windows.
     */
    public static isMcpConfigPath(filePath: string): boolean {
        if (typeof filePath !== 'string' || filePath.length === 0) { return false; }

        // A path ending in a separator names a directory, not a config file.
        if (/[\\/]\s*$/.test(filePath)) { return false; }

        const segments = filePath.replace(/\\/g, '/').split('/').filter(Boolean);
        const base = segments[segments.length - 1];
        if (!base) { return false; }

        const parent = segments.length >= 2 ? segments[segments.length - 2] : '';

        if (base === '.mcp.json' || base === 'mcp.json') { return true; }
        if (base === 'claude_desktop_config.json') { return true; }
        if (base === 'mcp_config.json' && (parent === '.windsurf' || parent === '.codeium')) { return true; }

        return false;
    }

    /**
     * Audits an MCP configuration document.
     *
     * Never throws. This runs inside an editor scan loop over files the user did
     * not vet, so malformed or hostile input must produce a finding rather than
     * an exception that kills the whole sweep.
     */
    public static scanConfig(jsonText: string, config: McpGuardConfig = DEFAULT_MCP_CONFIG): McpScanResult {
        const findings: McpFinding[] = [];
        const state = { sites: 0, truncated: false };

        // Guard the bounds themselves: a caller passing 0 or a negative must not
        // turn "scan nothing" into a crash.
        const maxSites = Math.max(1, config.maxDescriptionSites | 0);
        const maxDepth = Math.max(1, config.maxWalkDepth | 0);

        let doc: unknown;
        try {
            doc = JSON.parse(jsonText);
        } catch (err) {
            return {
                findings: [{
                    type: 'Unparseable MCP Config',
                    severity: 'low',
                    detail: `This file could not be parsed as JSON (${err instanceof Error ? err.message : 'parse error'}), so Quell could not audit it.`,
                }],
                serverCount: 0,
                parsed: false,
                truncated: false,
            };
        }

        const servers = this.extractServers(doc);
        if (servers === null) {
            return {
                findings: [{
                    type: 'Unrecognised MCP Config',
                    severity: 'low',
                    detail: 'No `mcpServers` or `servers` object was found, so this does not look like an MCP configuration.',
                }],
                serverCount: 0,
                parsed: false,
                truncated: false,
            };
        }

        for (const [serverName, rawServer] of servers) {
            if (!isRecord(rawServer)) { continue; }
            try {
                this.scanCredentialBlocks(serverName, rawServer, config, findings);
                this.scanInvocation(serverName, rawServer, config, findings);
                this.scanTransport(serverName, rawServer, findings);
                this.scanDescriptions(serverName, rawServer, config, findings, state, maxSites, maxDepth);
            } catch {
                // One malformed server must not abort the audit of the others.
                findings.push({
                    type: 'MCP Server Not Audited',
                    severity: 'low',
                    serverName,
                    detail: 'Quell could not finish auditing this server entry, so treat it as unverified.',
                });
            }
        }

        if (state.truncated) {
            findings.push({
                type: 'MCP Scan Truncated',
                severity: 'medium',
                detail:
                    'This config is deep or large enough that Quell stopped walking it before the end, so parts were ' +
                    'not audited. Structure that unusual is itself worth a look — treat the file as unverified.',
            });
        }

        return { findings, serverCount: servers.length, parsed: true, truncated: state.truncated };
    }

    // ── Structure ────────────────────────────

    /** Returns [name, server] pairs, or null when the document is not an MCP config. */
    private static extractServers(doc: unknown): Array<[string, unknown]> | null {
        if (!isRecord(doc)) { return null; }

        // `mcpServers` is the Claude Desktop / .mcp.json shape; `servers` is the VSCode shape.
        const block = isRecord(doc.mcpServers) ? doc.mcpServers
            : isRecord(doc.servers) ? doc.servers
                : null;

        if (!block) { return null; }
        return Object.entries(block);
    }

    // ── Credentials in env / headers ─────────

    private static scanCredentialBlocks(
        serverName: string,
        server: Record<string, unknown>,
        config: McpGuardConfig,
        findings: McpFinding[],
    ): void {
        for (const blockName of SCANNED_BLOCKS) {
            const block = server[blockName];
            if (!isRecord(block)) { continue; }

            for (const [key, value] of Object.entries(block)) {
                const text = coerceScannable(value);
                if (text === null) { continue; }
                if (WHOLE_VALUE_INDIRECTION.test(text)) { continue; }

                const types = this.detectSecretTypes(text, config.scanner);
                if (types.length === 0) { continue; }

                findings.push({
                    type: 'Hardcoded Credential in MCP Config',
                    severity: 'critical',
                    serverName,
                    key: `${blockName}.${key}`,
                    detail:
                        `A literal ${types.join(' / ')} is stored in this server's \`${blockName}\` block. ` +
                        `MCP configs get committed constantly — reference an environment variable instead of ` +
                        `pasting the value.`,
                });
            }
        }
    }

    /**
     * Credentials also travel as launch arguments — `--token ghp_...` is a
     * documented setup step for several popular servers — so `command` and
     * `args` need the same treatment as `env`. Scanning only `env` is the
     * single biggest blind spot in the obvious version of this module.
     */
    private static scanInvocation(
        serverName: string,
        server: Record<string, unknown>,
        config: McpGuardConfig,
        findings: McpFinding[],
    ): void {
        const parts: string[] = [];

        if (typeof server.command === 'string') { parts.push(server.command); }
        if (Array.isArray(server.args)) {
            for (const arg of server.args) {
                const text = coerceScannable(arg);
                if (text !== null && !WHOLE_VALUE_INDIRECTION.test(text)) { parts.push(text); }
            }
        }
        if (parts.length === 0) { return; }

        const types = this.detectSecretTypes(parts.join(' '), config.scanner);
        if (types.length === 0) { return; }

        findings.push({
            type: 'Hardcoded Credential in MCP Launch Arguments',
            severity: 'critical',
            serverName,
            key: 'args',
            detail:
                `A literal ${types.join(' / ')} is passed on this server's command line. Arguments show up in the ` +
                `process list, so every other process on the machine can read them, not just anyone opening the file.`,
        });
    }

    // ── Transport ────────────────────────────

    private static scanTransport(
        serverName: string,
        server: Record<string, unknown>,
        findings: McpFinding[],
    ): void {
        const url = typeof server.url === 'string' ? server.url
            : typeof server.endpoint === 'string' ? server.endpoint
                : null;
        if (!url) { return; }

        const host = parseHost(url);
        if (host === null) { return; }

        const local = isLoopbackHost(host);

        if (/^http:\/\//i.test(url.trim()) && !local) {
            findings.push({
                type: 'MCP Cleartext Transport',
                severity: 'high',
                serverName,
                key: 'url',
                detail:
                    'This server is reached over plain HTTP at a non-local host. Everything sent to it — file ' +
                    'contents, and any credentials in headers — crosses the network unencrypted.',
            });
        }

        if (!local) {
            findings.push({
                type: 'Remote MCP Server',
                severity: 'info',
                serverName,
                key: 'url',
                detail:
                    'This server runs remotely, so its operator sees whatever your assistant sends it, and its tool ' +
                    'definitions can change after you approved them. Worth knowing; not a defect in itself.',
            });
        }
    }

    // ── Tool descriptions (poisoning) ────────

    private static scanDescriptions(
        serverName: string,
        server: Record<string, unknown>,
        config: McpGuardConfig,
        findings: McpFinding[],
        state: { sites: number; truncated: boolean },
        maxSites: number,
        maxDepth: number,
    ): void {
        const seen = new Set<unknown>();

        const walk = (node: unknown, depth: number): void => {
            if (state.sites >= maxSites) { state.truncated = true; return; }
            if (depth > maxDepth) { state.truncated = true; return; }

            // JSON.parse cannot produce cycles, but this walker is cheap to make
            // safe and the guard costs nothing.
            if (typeof node === 'object' && node !== null) {
                if (seen.has(node)) { return; }
                seen.add(node);
            }

            if (Array.isArray(node)) {
                for (const child of node) { walk(child, depth + 1); }
                return;
            }
            if (!isRecord(node)) { return; }

            for (const [key, value] of Object.entries(node)) {
                if (typeof value === 'string' && MODEL_FACING_KEY.test(key)) {
                    if (state.sites >= maxSites) { state.truncated = true; return; }
                    state.sites++;

                    const { findings: injected } = PromptGuard.scan(value, config.guard);
                    for (const f of injected) {
                        if (f.severity !== 'critical' && f.severity !== 'high') { continue; }
                        findings.push({
                            type: 'MCP Tool Poisoning',
                            severity: f.severity,
                            serverName,
                            key,
                            detail:
                                `A \`${key}\` field on this server contains ${f.type.toLowerCase()}. Tool descriptions ` +
                                `are read by the model and never shown to you, which is exactly why they are used to ` +
                                `smuggle instructions. ${f.detail}` +
                                (f.decoded ? ` Hidden text decodes to: "${f.decoded.slice(0, 200)}"` : ''),
                        });
                    }
                } else {
                    walk(value, depth + 1);
                }
            }
        };

        walk(server, 0);
    }

    // ── Detection helper ─────────────────────

    /**
     * Returns the credential type names found in a value, or an empty array.
     * Only type NAMES leave this function, never the matched value.
     */
    private static detectSecretTypes(text: string, scannerConfig: ScannerConfig): string[] {
        try {
            const { secrets, detectedTypes } = SecretScanner.redact(text, scannerConfig);
            return secrets.size > 0 ? Array.from(detectedTypes) : [];
        } catch {
            // A scanner failure must not take the whole config audit down.
            return [];
        }
    }
}

// ── Local helpers ────────────────────────────

function isRecord(v: unknown): v is Record<string, unknown> {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Coerces a config value into something scannable. Credentials are not always
 * strings in the wild — people paste them as bare numbers, or wrap them in a
 * single-element array — and skipping non-strings would miss those entirely.
 */
function coerceScannable(value: unknown): string | null {
    if (typeof value === 'string') { return value; }
    if (typeof value === 'number' || typeof value === 'bigint') { return String(value); }
    if (Array.isArray(value)) {
        const parts = value.map(coerceScannable).filter((s): s is string => s !== null);
        return parts.length > 0 ? parts.join(' ') : null;
    }
    return null;
}

/** Extracts the host from a URL, with userinfo and port removed. */
function parseHost(url: string): string | null {
    const match = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i.exec(url.trim());
    if (!match) { return null; }

    let authority = match[1];
    const at = authority.lastIndexOf('@');
    if (at !== -1) { authority = authority.slice(at + 1); }

    if (authority.startsWith('[')) {
        const close = authority.indexOf(']');
        if (close !== -1) { return authority.slice(1, close).toLowerCase(); }
    }
    return authority.split(':')[0].toLowerCase() || null;
}

/**
 * True only for genuine loopback destinations.
 *
 * Matched exactly, never by prefix: `127.evil.com` and `127.0.0.1.evil.com` are
 * ordinary public hostnames that merely begin with those characters, and a
 * prefix test would quietly exempt an attacker's server from every transport
 * check.
 */
function isLoopbackHost(host: string): boolean {
    if (host === 'localhost' || host.endsWith('.localhost')) { return true; }
    if (host === '::1' || host === '0.0.0.0') { return true; }
    return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}
