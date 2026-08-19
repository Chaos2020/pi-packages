/**
 * pi-permission-companion — the fork's in-tree features externalized as a
 * standalone Pi extension built only on @gotgenes/pi-permission-system's
 * public seams (`registerAuthorizer`, event-bus broadcasts, `tool_result`).
 *
 * Each feature is inert unless the operator enables it in this package's own
 * config (`~/.pi/agent/extensions/pi-permission-companion/config.json`):
 *
 * - `commandSafetyJudge` — allow-capable LLM authorizer chain link,
 *   registered via `registerAuthorizer`; active only when named in
 *   pi-permission-system's `authorizerChain`.
 * - `secretScan` — scans `tool_result` text against builtin + custom secret
 *   patterns; `deny` mutates the tool result, `alert` only logs.
 * - `agenticMirror` — mirrors `permissions:decision` broadcasts to the
 *   unified AgenticLogger JSONL.
 * - `denyStorm` — sliding-window burst detector over enforced denials from
 *   `permissions:decision` broadcasts.
 *
 * The serena/MCP path-extractors from the fork are NOT here: they need the
 * gates to unwrap the `mcp` gateway call, which no public seam exposes —
 * they stay as an in-tree patch (Phase B).
 */

import { completeSimple as realCompleteSimple } from "@earendil-works/pi-ai";
import type {
  ExtensionAPI,
  SessionStartEvent,
  ToolResultEvent,
} from "@earendil-works/pi-coding-agent";
import {
  getPermissionsService,
  PERMISSIONS_DECISION_CHANNEL,
  PERMISSIONS_READY_CHANNEL,
} from "gigapie-permissions";

import { createAgenticLogger } from "./agentic-logger";
import {
  loadCompanionConfig,
  type CompanionConfig,
} from "./companion-config";
import { registerSerenaExtractors } from "./serena-extractors";
import {
  resolveCommandSafetyConfig,
} from "./command-safety-config";
import { createCommandSafetyJudge } from "./command-safety-judge";
import type { ModelRegistryLike } from "./command-safety-review";
import type { CompleteSimpleFn } from "./command-safety-review";
import { DenyStormMonitor } from "./deny-storm";
import {
  BUILTIN_SECRET_PATTERNS,
  compileSecretPatterns,
  scanForSecrets,
} from "./secret-scan-patterns";

const EXTENSION_ID = "pi-permission-companion";

interface MinimalModelRegistryHost {
  modelRegistry?: unknown;
}

export default function piPermissionCompanionExtension(
  pi: ExtensionAPI,
): void {
  const disposers: Array<() => void> = [];

  let config: CompanionConfig = {};
  const reload = (cwd: string): void => {
    const result = loadCompanionConfig(cwd);
    config = result.config;
    for (const issue of result.issues) {
      console.warn(
        `[${EXTENSION_ID}] config issue at ${issue.sourcePath ?? "(merged)"} — ${issue.path}: ${issue.message}`,
      );
    }
  };

  // ---- command-safety-judge (registerAuthorizer seam) --------------------
  let judgeRegistered = false;
  function tryRegisterJudge(ctx: MinimalModelRegistryHost): void {
    if (judgeRegistered) return;
    const judgeConfig = resolveCommandSafetyConfig(config.commandSafetyJudge);
    if (!judgeConfig) return;
    const service = getPermissionsService();
    if (!service) return;
    try {
      disposers.push(
        service.registerAuthorizer(
          "command-safety-judge",
          createCommandSafetyJudge({
            getConfig: () => judgeConfig,
            getRegistry: () => ctx.modelRegistry as ModelRegistryLike | undefined,
            // Structural projection of pi-ai's completeSimple (checked cast).
            completeSimple:
              realCompleteSimple as unknown as CompleteSimpleFn,
            getCwd: () => undefined,
          }),
        ),
      );
      judgeRegistered = true;
    } catch (error) {
      console.warn(
        `[${EXTENSION_ID}] command-safety-judge registration failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  // ---- secret-scan (tool_result hook, no permission-system seam needed) --
  function toolResultText(content: readonly unknown[]): string {
    return content
      .filter(
        (p): p is { type: "text"; text: string } =>
          typeof p === "object" &&
          p !== null &&
          "type" in p &&
          (p as { type?: unknown }).type === "text" &&
          typeof (p as { text?: unknown }).text === "string",
      )
      .map((p) => p.text)
      .join("\n");
  }

  // ---- observability: agentic mirror + deny-storm ------------------------
  const offDecision = pi.events.on(
    PERMISSIONS_DECISION_CHANNEL,
    (data) => onDecision(data as Parameters<typeof onDecision>[0]),
  );
  disposers.push(offDecision);

  const agentic = createAgenticLogger();

  function log(
    level: "info" | "warn" | "error",
    event: string,
    details: Record<string, unknown>,
  ): void {
    try {
      const fn = agentic?.[level];
      if (!fn) return;
      fn.call(agentic, event, { module: "permission-companion", ctx: details });
    } catch {
      // logging must never break the companion
    }
  }

  const storm = new DenyStormMonitor({
    enabled: () => config.denyStorm?.enabled === true,
    maxDenials: () => config.denyStorm?.maxDenials ?? 0,
    windowMs: () => config.denyStorm?.windowMs ?? 0,
    onAlert: (count) =>
      log("error", "permission_request.deny_storm", {
        count,
        hint: "an agent loop is being denied repeatedly — intervene",
      }),
  });

  function onDecision(event: {
    surface: string;
    value: string;
    result: "allow" | "deny";
    resolution: string;
    origin: string | null;
    agentName: string | null;
  }): void {
    if (config.agenticMirror?.enabled === true && agentic) {
      log(
        event.result === "deny" ? "warn" : "info",
        `permissions:decision:${event.result}`,
        { ...event },
      );
    }
    if (event.result === "deny") {
      storm.recordDenial();
    }
  }

  // ---- lifecycle ---------------------------------------------------------
  pi.on("session_start", (event: SessionStartEvent, ctx) => {
    reload(ctx.cwd);
    tryRegisterJudge(ctx);
  });

  pi.events.on(PERMISSIONS_READY_CHANNEL, () => {
    tryRegisterJudge({});
  });

  pi.on("tool_result", (event: ToolResultEvent) => {
    const sc = config.secretScan;
    if (!sc?.enabled) return undefined;
    if (sc.excludeTools?.includes(event.toolName)) return undefined;
    const text = toolResultText(event.content ?? []);
    if (!text) return undefined;
    const compiled = compileSecretPatterns([
      ...BUILTIN_SECRET_PATTERNS,
      ...(sc.patterns ?? []),
    ]);
    const hits = scanForSecrets(text, compiled);
    if (hits.length === 0) return undefined;
    log(
      sc.action === "alert" ? "error" : "info",
      "permission_request.secret_detected",
      {
        tool: event.toolName,
        count: hits.length,
        patterns: hits.map((h) => h.pattern),
        action: sc.action ?? "deny",
        isError: event.isError,
      },
    );
    if (sc.action === "alert") return undefined;
    // deny: replace the result text so the secret never reaches the model.
    return {
      content: [
        {
          type: "text",
          text: `Tool result withheld: ${hits.length} secret pattern(s) matched (${hits.map((h) => h.pattern).join(", ")}).`,
        },
      ],
      isError: true,
    };
  });

  pi.on("session_shutdown", () => {
    for (const dispose of disposers.splice(0)) {
      try {
        dispose();
      } catch {
        // best-effort teardown
      }
    }
    judgeRegistered = false;
  });

  // ---- serena path extractors (registerToolAccessExtractor seam) ---------
  disposers.push(registerSerenaExtractors(pi));
}
