import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  ShellToolsConfig,
  UnifiedPermissionConfig,
} from "./config-loader";
import {
  OWNER_ONLY_DIRECTORY_MODE,
  restrictExistingPathToOwner,
} from "./log-file-permissions";

export const EXTENSION_ID = "pi-permission-system";

export interface PermissionSystemExtensionConfig {
  debugLog: boolean;
  permissionReviewLog: boolean;
  yoloMode: boolean;
  /** Require a confirming second press of a decision hotkey in the inline TUI dialog. Defaults to true. */
  doublePressToConfirm: boolean;
  /** Additional directories to auto-allow for reads as Pi infrastructure. */
  piInfrastructureReadPaths?: string[];
  /** How long a subagent waits for the parent's answer to a forwarded ask, in ms. Defaults to 600000. */
  forwardingTimeoutMs?: number;
  /** Max rows a permission prompt renders before eliding its evidence. Defaults to 24. */
  promptMaxRows?: number;
  /** Max characters of any one field shown in a permission prompt. Defaults to 400. */
  promptFieldMaxWidth?: number;
  /** Max characters of any one value written to the permission review log. Defaults to 1000. */
  reviewLogFieldMaxWidth?: number;
  /**
   * Auto-deny an unanswered permission ask after this many milliseconds.
   * 0 disables the timeout. Defaults to DEFAULT_ASK_TIMEOUT_MS (10000).
   */
  askTimeoutMs?: number;
  /** Non-bash tools that carry shell semantics, keyed by tool name. */
  shellTools?: ShellToolsConfig;
  /** Ordered names of registered live-authority chain links to consult before the terminal authorizer. */
  authorizerChain?: string[];
  /**
   * Feature 3: secret detection in tool output. When enabled, tool results are
   * scanned for leaked secrets; `deny` redacts them in the result, `alert` only
   * logs. `patterns` extends the built-ins; `excludeTools` skips tools.
   */
  secretScan?: {
    enabled?: boolean;
    action?: "deny" | "alert";
    patterns?: string[];
    excludeTools?: string[];
  };
  /** Feature 6: session permission mode (default/acceptEdits/plan/bypassPermissions). */
  permissionMode?: "default" | "acceptEdits" | "plan" | "bypassPermissions";
  /** Feature 4: dry-run mode. */
  dryRun?: boolean;
}

/** Default for `askTimeoutMs`: auto-deny an unanswered ask after 10 seconds. */
export const DEFAULT_ASK_TIMEOUT_MS = 10000;

export const DEFAULT_EXTENSION_CONFIG: PermissionSystemExtensionConfig = {
  askTimeoutMs: DEFAULT_ASK_TIMEOUT_MS,
  debugLog: false,
  permissionReviewLog: true,
  yoloMode: false,
  doublePressToConfirm: true,
};

function resolveExtensionRoot(moduleUrl = import.meta.url): string {
  return join(dirname(fileURLToPath(moduleUrl)), "..");
}

export const EXTENSION_ROOT = resolveExtensionRoot();

const PERMISSION_POLICY_KEYS: ReadonlySet<string> = new Set([
  "defaultPolicy",
  "tools",
  "bash",
  "mcp",
  "skills",
  "special",
  "external_directory",
]);

export function detectMisplacedPermissionKeys(
  raw: Record<string, unknown>,
): string[] {
  return Object.keys(raw).filter((key) => PERMISSION_POLICY_KEYS.has(key));
}

export function normalizePermissionSystemConfig(
  raw: UnifiedPermissionConfig,
): PermissionSystemExtensionConfig {
  const result: PermissionSystemExtensionConfig = {
    debugLog: raw.debugLog === true,
    permissionReviewLog: raw.permissionReviewLog !== false,
    yoloMode: raw.yoloMode === true,
    doublePressToConfirm: raw.doublePressToConfirm !== false,
  };
  if (raw.piInfrastructureReadPaths !== undefined) {
    result.piInfrastructureReadPaths = raw.piInfrastructureReadPaths;
  }
  if (raw.forwardingTimeoutMs !== undefined) {
    result.forwardingTimeoutMs = raw.forwardingTimeoutMs;
  }
  if (raw.promptMaxRows !== undefined) {
    result.promptMaxRows = raw.promptMaxRows;
  }
  if (raw.promptFieldMaxWidth !== undefined) {
    result.promptFieldMaxWidth = raw.promptFieldMaxWidth;
  }
  if (raw.reviewLogFieldMaxWidth !== undefined) {
    result.reviewLogFieldMaxWidth = raw.reviewLogFieldMaxWidth;
  }
  // `toolInputPreviewMaxLength` / `toolTextSummaryMaxLength` are deliberately
  // absent: the schema and the merge still accept them so the deprecation
  // detector can see an operator's setting, but no runtime consumer may read
  // one (ADR 0011 §5, #745).
  if (raw.shellTools !== undefined) {
    result.shellTools = raw.shellTools;
  }
  if (raw.authorizerChain !== undefined) {
    result.authorizerChain = raw.authorizerChain;
  }
  return result;
}

export function isYoloModeEnabled(
  config: PermissionSystemExtensionConfig,
): boolean {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-conversion -- typed as boolean but may be undefined at runtime (untyped callers); Boolean() guards against that
  return Boolean(config.yoloMode);
}

export function ensurePermissionSystemLogsDirectory(
  logsDir: string,
): string | undefined {
  try {
    // `recursive` applies the mode to every directory this creates, so a fresh
    // install also gets an owner-only extension config dir. Directories that
    // already exist are untouched by `mkdirSync`, hence the explicit tighten.
    mkdirSync(logsDir, { recursive: true, mode: OWNER_ONLY_DIRECTORY_MODE });
    restrictExistingPathToOwner(logsDir, OWNER_ONLY_DIRECTORY_MODE);
    return undefined;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return `Failed to create permission-system log directory '${logsDir}': ${message}`;
  }
}
