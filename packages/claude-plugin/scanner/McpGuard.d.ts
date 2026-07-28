import { ScannerConfig } from './SecretScanner';
import { GuardConfig } from './PromptGuard';
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
export declare const DEFAULT_MCP_CONFIG: McpGuardConfig;
export declare class McpGuard {
    /**
     * Recognises the real MCP config filenames across the tools that use them.
     * Handles both separators, because this ships on Windows.
     */
    static isMcpConfigPath(filePath: string): boolean;
    /**
     * Audits an MCP configuration document.
     *
     * Never throws. This runs inside an editor scan loop over files the user did
     * not vet, so malformed or hostile input must produce a finding rather than
     * an exception that kills the whole sweep.
     */
    static scanConfig(jsonText: string, config?: McpGuardConfig): McpScanResult;
    /** Returns [name, server] pairs, or null when the document is not an MCP config. */
    private static extractServers;
    private static scanCredentialBlocks;
    /**
     * Credentials also travel as launch arguments — `--token ghp_...` is a
     * documented setup step for several popular servers — so `command` and
     * `args` need the same treatment as `env`. Scanning only `env` is the
     * single biggest blind spot in the obvious version of this module.
     */
    private static scanInvocation;
    private static scanTransport;
    private static scanDescriptions;
    /**
     * Returns the credential type names found in a value, or an empty array.
     * Only type NAMES leave this function, never the matched value.
     */
    private static detectSecretTypes;
}
//# sourceMappingURL=McpGuard.d.ts.map