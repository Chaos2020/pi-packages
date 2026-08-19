/**
 * Lazy AgenticLogger accessor (user-level rule: the logging subsystem goes
 * through AgenticLogger SDK). Defensive: a missing/broken SDK degrades to
 * null and the companion keeps working.
 */

import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";

interface MinimalAgentLogger {
  info(msg: string, extra?: unknown): unknown;
  warn(msg: string, extra?: unknown): unknown;
  error(msg: string, extra?: unknown): unknown;
}

const _require = createRequire(import.meta.url);

export function createAgenticLogger(
  logDirOverride?: string,
): MinimalAgentLogger | null {
  try {
    const logDir =
      logDirOverride ??
      process.env.AGENTIC_LOG_DIR ??
      join(homedir(), "wrk", "mySkills", "logs", "agentic");
    const { AgentLogger } = _require("agentic-logger") as {
      AgentLogger: new (opts: {
        program: string;
        command: string;
        logDir: string;
      }) => MinimalAgentLogger;
    };
    return new AgentLogger({
      program: "pi-permission-companion",
      command: `pid${process.pid}`,
      logDir,
    });
  } catch {
    return null;
  }
}
