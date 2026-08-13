import { appendFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import type { AgentLogger } from "agentic-logger";

// Feature 1 (AgenticLogger integration, project rule): mirror every review/debug
// entry to the unified AgenticLogger JSONL (<repo>/logs/agentic) so permission
// decisions join skill logs and are queryable by it.log-query. Defensive: a
// missing/broken SDK degrades to null and the extension keeps working.
const _require = createRequire(import.meta.url);
function createDefaultAgenticLogger(): AgentLogger | null {
  try {
    const logDir =
      process.env.AGENTIC_LOG_DIR ||
      join(homedir(), "wrk", "mySkills", "logs", "agentic");
    const { AgentLogger } = _require("agentic-logger") as {
      AgentLogger: new (opts: {
        program: string;
        command: string;
        logDir: string;
      }) => AgentLogger;
    };
    return new AgentLogger({
      program: "pi-permission-system",
      command: `pid${process.pid}`,
      logDir,
    });
  } catch {
    return null;
  }
}

import {
  EXTENSION_ID,
  type PermissionSystemExtensionConfig,
} from "./extension-config";
import {
  OWNER_ONLY_FILE_MODE,
  restrictExistingPathToOwner,
} from "./log-file-permissions";
import { isSensitiveLogKey, redactedJsonStringify } from "./log-redaction";

export interface PermissionSystemLogger {
  debug: (
    event: string,
    details?: Record<string, unknown>,
  ) => string | undefined;
  review: (
    event: string,
    details?: Record<string, unknown>,
  ) => string | undefined;
}

interface PermissionSystemLoggerOptions {
  getConfig: () => PermissionSystemExtensionConfig;
  debugLogPath: string;
  reviewLogPath: string;
  ensureLogsDirectory: () => string | undefined;
  /**
   * Feature 1 (AgenticLogger): injected for tests; production omits it and the
   * defensive createRequire-based default is used. null disables AgenticLogger.
   */
  agenticLogger?: AgentLogger | null;
}

export function createPermissionSystemLogger(
  options: PermissionSystemLoggerOptions,
): PermissionSystemLogger {
  const { debugLogPath, reviewLogPath, ensureLogsDirectory } = options;
  // Feature 1: AgenticLogger sink (injected for tests; default is defensive).
  const agentic =
    options.agenticLogger !== undefined
      ? options.agenticLogger
      : createDefaultAgenticLogger();
  // Per-session, so a log inherited from an earlier version is tightened once
  // rather than on every line. Lives in the closure because the factory is
  // re-invoked per session, unlike module scope, which now outlives one.
  const hardened = new Set<string>();

  const writeLine = (
    stream: "debug" | "review",
    path: string,
    event: string,
    details: Record<string, unknown>,
  ): string | undefined => {
    const directoryError = ensureLogsDirectory();
    if (directoryError) {
      return directoryError;
    }

    try {
      const line = redactedJsonStringify({
        timestamp: new Date().toISOString(),
        extension: EXTENSION_ID,
        stream,
        event,
        ...details,
      });
      if (!line) {
        return `Failed to write permission-system ${stream} log '${path}': event could not be serialized.`;
      }
      // Feature 1: also emit to AgenticLogger (unified structured log).
      const lg = agentic;
      if (lg) {
        try {
          const isError =
            /deny|block|error|fail/i.test(event) ||
            details.isError === true ||
            details.error !== undefined;
          const isWarn = !isError && /warn/i.test(event);
          const ctx: Record<string, unknown> = { stream, event };
          // Mirror the file sink's key-name redaction so a sensitive value
          // (apiKey/token/secret/password...) never lands raw in AgenticLogger.
          for (const [k, v] of Object.entries(details)) {
            ctx[k] = isSensitiveLogKey(k) ? "[redacted]" : v;
          }
          const msg = `${stream}:${event}`;
          if (isError) lg.error(msg, { module: "permission-system", ctx });
          else if (isWarn) lg.warn(msg, { module: "permission-system", ctx });
          else lg.info(msg, { module: "permission-system", ctx });
        } catch {
          // AgenticLogger must never break the permission-system.
        }
      }
      appendFileSync(path, `${line}\n`, {
        encoding: "utf-8",
        mode: OWNER_ONLY_FILE_MODE,
      });
      if (!hardened.has(path)) {
        hardened.add(path);
        restrictExistingPathToOwner(path, OWNER_ONLY_FILE_MODE);
      }
      return undefined;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return `Failed to write permission-system ${stream} log '${path}': ${message}`;
    }
  };

  const debug = (
    event: string,
    details: Record<string, unknown> = {},
  ): string | undefined => {
    if (!options.getConfig().debugLog) {
      return undefined;
    }

    return writeLine("debug", debugLogPath, event, details);
  };

  const review = (
    event: string,
    details: Record<string, unknown> = {},
  ): string | undefined => {
    if (!options.getConfig().permissionReviewLog) {
      return undefined;
    }

    return writeLine("review", reviewLogPath, event, details);
  };

  return { debug, review };
}
