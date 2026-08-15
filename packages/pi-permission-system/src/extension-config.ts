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
  /** Feature 4: dry-run / simulation mode — record would-be decisions, never enforce. */
  dryRun?: boolean;
  /** Additional directories to auto-allow for reads as Pi infrastructure. */
  piInfrastructureReadPaths?: string[];
  /** How long a subagent waits for the parent's answer to a forwarded ask, in ms. Defaults to 600000. */
  forwardingTimeoutMs?: number;
  /** Max length of the inline-JSON input preview shown in permission prompts. Defaults to 200. */
  toolInputPreviewMaxLength?: number;
  /** Max length of inline pattern/path summaries (grep/find/ls) in permission prompts. Defaults to 80. */
  toolTextSummaryMaxLength?: number;
  /**
   * Wrapper commands explicitly trusted to bypass the indirection-wrapper
   * deny floor. Only add entries you have deliberately vetted. Defaults to [].
   */
  wrapperAllowlist?: string[];
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
   * Model mechanism for the built-in 'model-judge' authorizer (feature 2): the
   * provider/model/instructions driving the deny-first typo-path reviewer. The
   * link is inert unless the mechanism is complete AND named in `authorizerChain`.
   */
  modelJudge?: {
    provider?: string;
    model?: string;
    instructions?: string;
    typoPatterns?: string[];
    timeoutMs?: number;
  };
  /**
   * Model mechanism for the 'command-safety-judge' authorizer: an allow-capable
   * LLM judge ruling on any `ask` (deny/suggest/allow/defer) at the model's top
   * reasoning level. Defaults to glm-5.2 (fallback deepseek-v4-pro), reasoning
   * 'max'. Inert unless named in `authorizerChain`.
   */
  commandSafetyJudge?: {
    provider?: string;
    model?: string;
    fallbackProvider?: string;
    fallbackModel?: string;
    reasoning?: "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
    instructions?: string;
    timeoutMs?: number;
  };
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
  /** Feature 5: deny-storm alerting — burst of denials within a window. */
  denyStorm?: {
    enabled?: boolean;
    maxDenials?: number;
    windowMs?: number;
  };
  /** Feature 6: session permission mode (default/acceptEdits/plan/bypassPermissions). */
  permissionMode?: "default" | "acceptEdits" | "plan" | "bypassPermissions";
}

/** Default for `askTimeoutMs`: auto-deny an unanswered ask after 3 seconds. */
export const DEFAULT_ASK_TIMEOUT_MS = 10000;

export const DEFAULT_EXTENSION_CONFIG: PermissionSystemExtensionConfig = {
  debugLog: false,
  permissionReviewLog: true,
  yoloMode: false,
  doublePressToConfirm: true,
  wrapperAllowlist: [],
  askTimeoutMs: DEFAULT_ASK_TIMEOUT_MS,
};

/**
 * Normalize `askTimeoutMs` on the plain-object path (m3, F8): the zod schema's
 * `min(0)` does not run here, so an out-of-range value would otherwise slip
 * through. A negative number falls back to the default — clamping it to 0
 * would silently *disable* the ask auto-deny timeout, the opposite of the
 * misconfigured intent — as does a non-finite or non-number value. 0 is legal
 * only when explicitly passed (timeout disabled).
 */
function normalizeAskTimeoutMs(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return DEFAULT_ASK_TIMEOUT_MS;
  }
  return Math.trunc(value);
}

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
    wrapperAllowlist: raw.wrapperAllowlist ?? [],
    askTimeoutMs: normalizeAskTimeoutMs(raw.askTimeoutMs),
  };
  if (raw.piInfrastructureReadPaths !== undefined) {
    result.piInfrastructureReadPaths = raw.piInfrastructureReadPaths;
  }
  if (raw.forwardingTimeoutMs !== undefined) {
    result.forwardingTimeoutMs = raw.forwardingTimeoutMs;
  }
  if (raw.toolInputPreviewMaxLength !== undefined) {
    result.toolInputPreviewMaxLength = raw.toolInputPreviewMaxLength;
  }
  if (raw.toolTextSummaryMaxLength !== undefined) {
    result.toolTextSummaryMaxLength = raw.toolTextSummaryMaxLength;
  }
  if (raw.shellTools !== undefined) {
    result.shellTools = raw.shellTools;
  }
  if (raw.authorizerChain !== undefined) {
    result.authorizerChain = raw.authorizerChain;
  }
  // Features 2-6 fields — must survive normalization or the features are dead.
  if (raw.dryRun !== undefined) {
    result.dryRun = raw.dryRun;
  }
  if (raw.permissionMode !== undefined) {
    result.permissionMode = raw.permissionMode;
  }
  if (raw.modelJudge !== undefined) {
    result.modelJudge = raw.modelJudge;
  }
  if (raw.commandSafetyJudge !== undefined) {
    result.commandSafetyJudge = raw.commandSafetyJudge;
  }
  if (raw.secretScan !== undefined) {
    result.secretScan = raw.secretScan;
  }
  if (raw.denyStorm !== undefined) {
    result.denyStorm = raw.denyStorm;
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
