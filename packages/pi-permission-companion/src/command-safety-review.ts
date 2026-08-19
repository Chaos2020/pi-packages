/**
 * The LLM call for the command-safety-judge: ask a smart model (at its highest
 * reasoning level) whether an `ask` operation is safe, and map its reply to a
 * four-state verdict (`allow` / `deny` / `suggest` / `defer`).
 *
 * Unlike the typo reviewer (`model-review.ts`), this slice is allow-capable and
 * reasons about the *whole operation* (command + path + tool + cause), not
 * just a path's spelling. It uses pi-ai's `completeSimple` so it can run at the
 * model's top `reasoning` level (e.g. `"max"`), and forces a single tool call
 * so the verdict arrives as structured `arguments` — no free-text parsing.
 *
 * Fail-safe throughout: an unparseable reply, an unrecognized verdict, a thrown
 * or timed-out call all resolve to `defer` (more prompting, never less). The
 * judge's hard pre-filter (sensitive paths, destructive ops) runs *before* this
 * call, so the model is only consulted on genuinely ambiguous `ask`s.
 */

import type { AuthorizerVerdict } from "gigapie-permissions";
import type { CommandSafetyJudgeConfig } from "./command-safety-config";

// ---- narrow structural projections of @earendil-works/pi-ai types ---------
// Intentionally narrower than the real types (mirrors model-review.ts): the
// judge reads only these fields. `completeSimple` is the seam that supports a
// `reasoning` level; `complete` does not.
export interface Model {
  id: string;
  providerId?: string;
}
export interface TextContent {
  type: "text";
  text: string;
}
export interface ToolCall {
  type: "toolCall";
  arguments: Record<string, unknown>;
}
export type AssistantContentPart = TextContent | ToolCall;
export interface AssistantMessage {
  content: AssistantContentPart[];
}
export interface Context {
  systemPrompt: string;
  tools: Tool[];
  messages: { role: string; content: string; timestamp: number }[];
}
export interface Tool {
  name: string;
  description: string;
  parameters: unknown;
}
export type ThinkingLevel = "minimal" | "low" | "medium" | "high" | "xhigh";

/**
 * Map a ReasoningLevel (which may include `"max"`) to the pi-ai ThinkingLevel
 * the `completeSimple` seam accepts. `"max"` collapses to `"xhigh"` (the seam's
 * top level); the model's own thinkingLevelMap maps the final value further.
 */
function toThinkingLevel(
  level: import("./command-safety-config").ReasoningLevel,
): ThinkingLevel {
  return level === "max" ? "xhigh" : level;
}
// ----------------------------------------------------------------------------

/**
 * The forced single tool: the model must report one of four verdicts. `reason`
 * names the harm (deny); `alternative` names a no-auth-needed path (suggest);
 * `risk` + `suggestion` inform the operator at a defer prompt.
 */
const VERDICT_TOOL: Tool = {
  name: "report_verdict",
  description:
    "Report the safety verdict for the operation. deny = harmful; suggest = a no-auth-needed alternative exists (refuse current, hand back the alternative); allow = safe to auto-approve; defer = genuinely uncertain, escalate to the human.",
  parameters: {
    type: "object",
    properties: {
      verdict: {
        type: "string",
        enum: ["deny", "suggest", "allow", "defer"],
        description:
          "deny=harmful; suggest=better no-auth way exists; allow=safe; defer=uncertain",
      },
      reason: {
        type: "string",
        description: "Why the operation is harmful (required when deny).",
      },
      alternative: {
        type: "string",
        description:
          "A no-auth-needed way to achieve the same goal (required when suggest).",
      },
      risk: {
        type: "string",
        description:
          "The potential harm, for the operator (required when defer).",
      },
      suggestion: {
        type: "string",
        description: "A recommended action for the operator (when defer).",
      },
    },
    required: ["verdict"],
  },
};

/**
 * The `completeSimple` seam — structurally pi-ai's export. Accepts a
 * `reasoning` level so the judge runs at the model's top thinking mode.
 */
export type CompleteSimpleFn = (
  model: Model,
  context: Context,
  options?: {
    signal?: AbortSignal;
    apiKey?: string;
    headers?: Record<string, string>;
    toolChoice?: string;
    reasoning?: ThinkingLevel;
  },
) => Promise<AssistantMessage>;

export type ResolvedRequestAuth =
  | { ok: true; apiKey?: string; headers?: Record<string, string> }
  | { ok: false; error: string };

export interface ModelRegistryLike {
  find(provider: string, modelId: string): Model | undefined;
  getApiKeyAndHeaders(model: Model): Promise<ResolvedRequestAuth>;
}

/** The operation context the model reasons about. */
export interface OperationContext {
  toolName?: string;
  command?: string;
  path?: string;
  cwd?: string;
  surface?: string;
  message: string;
  agentName?: string;
}

export interface ReviewInputs {
  op: OperationContext;
  config: CommandSafetyJudgeConfig;
  model: Model;
  completeSimple: CompleteSimpleFn;
  apiKey?: string;
  headers?: Record<string, string>;
}

export type DeferReason =
  | "no-tool-call"
  | "unrecognized-verdict"
  | "timeout"
  | "call-failed";

export interface ReviewOutcome {
  verdict: AuthorizerVerdict;
  deferReason?: DeferReason;
  latencyMs: number;
  rawReply?: string;
}

export async function reviewOperation(
  inputs: ReviewInputs,
): Promise<ReviewOutcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), inputs.config.timeoutMs);
  const startedAt = Date.now();
  try {
    const context: Context = {
      systemPrompt: inputs.config.instructions,
      tools: [VERDICT_TOOL],
      messages: [
        {
          role: "user",
          content: renderReviewPrompt(inputs.op),
          timestamp: Date.now(),
        },
      ],
    };
    const reply = await inputs.completeSimple(inputs.model, context, {
      signal: controller.signal,
      apiKey: inputs.apiKey,
      headers: inputs.headers,
      toolChoice: "any",
      reasoning: toThinkingLevel(inputs.config.reasoning),
    });
    return readToolCallOutcome(reply, Date.now() - startedAt);
  } catch {
    return {
      verdict: { kind: "defer" },
      deferReason: controller.signal.aborted ? "timeout" : "call-failed",
      latencyMs: Date.now() - startedAt,
    };
  } finally {
    clearTimeout(timer);
  }
}

function renderReviewPrompt(op: OperationContext): string {
  const lines = [
    "An operation is requesting authorization. Assess it.",
    "",
    `- tool: ${op.toolName ?? "(unknown)"}`,
  ];
  if (op.command) lines.push(`- command: ${op.command}`);
  if (op.path) lines.push(`- path: ${op.path}`);
  if (op.cwd) lines.push(`- working directory: ${op.cwd}`);
  if (op.surface) lines.push(`- gate surface: ${op.surface}`);
  if (op.agentName) lines.push(`- agent: ${op.agentName}`);
  lines.push(`- why it was flagged: ${op.message}`);
  lines.push("");
  lines.push(
    [
      "Decide in this order:",
      "1. deny — if the operation is harmful (data loss, secret leak, destructive overwrite, likely mistake); give `reason`.",
      "2. suggest — if a NO-AUTHORIZATION-NEEDED alternative achieves the same goal more simply/safely (e.g. use `read`/`grep`/`ls` which are pre-allowed, or serena MCP for code edits, or a temp dir instead of rm); refuse the current call and hand back `alternative`. Prefer this over defer whenever a clearly better way exists.",
      "3. allow — if the operation is safe and routine (read-only, temp files, the agent's own project files, common build/test/run commands).",
      "4. defer — only if genuinely uncertain AND no better no-auth way exists; give `risk` (the potential harm) and `suggestion` for the operator.",
    ].join("\n"),
  );
  lines.push("");
  lines.push("Call report_verdict.");
  return lines.join("\n");
}

function readToolCallOutcome(
  reply: AssistantMessage,
  latencyMs: number,
): ReviewOutcome {
  const call = reply.content.find(
    (part): part is ToolCall => part.type === "toolCall",
  );
  if (!call) {
    // Fallback for providers whose endpoint ignores `toolChoice`: parse a
    // verdict from free text. Anything unparseable still defers (fail-safe).
    const text = extractText(reply);
    const parsed = parseFreeTextVerdict(text);
    if (parsed) return { ...parsed, latencyMs, rawReply: text.slice(0, 500) };
    return {
      verdict: { kind: "defer" },
      deferReason: "no-tool-call",
      latencyMs,
      rawReply: text,
    };
  }
  const args = call.arguments;
  const rawReply = JSON.stringify(args);
  const verdict = mapVerdictArgs(args);
  if (verdict === undefined) {
    return {
      verdict: { kind: "defer" },
      deferReason: "unrecognized-verdict",
      latencyMs,
      rawReply,
    };
  }
  return { verdict, latencyMs, rawReply };
}

/** Map the tool-call `arguments` to an `AuthorizerVerdict`, or `undefined`. */
function mapVerdictArgs(
  args: Record<string, unknown>,
): AuthorizerVerdict | undefined {
  const v = typeof args.verdict === "string" ? args.verdict : undefined;
  switch (v) {
    case "allow":
      return { kind: "allow" };
    case "deny":
      return {
        kind: "deny",
        reason:
          strField(args, "reason") ?? "Flagged as harmful by the safety judge.",
      };
    case "suggest": {
      const alternative = strField(args, "alternative");
      if (!alternative) return undefined;
      return { kind: "suggest", alternative };
    }
    case "defer": {
      const risk = strField(args, "risk");
      const suggestion = strField(args, "suggestion");
      const note = [risk, suggestion]
        .filter((s): s is string => s !== undefined)
        .map((s, i) => (i === 0 ? `风险: ${s}` : `建议: ${s}`))
        .join("\n");
      return { kind: "defer", note: note || undefined };
    }
    default:
      return undefined;
  }
}

/** Parse a verdict from free text (toolChoice-ignoring providers). */
function parseFreeTextVerdict(
  text: string,
): { verdict: AuthorizerVerdict } | null {
  const m =
    /"verdict"\s*:\s*"(deny|suggest|allow|defer)"/i.exec(text) ??
    /verdict[\s:]+(deny|suggest|allow|defer)/i.exec(text);
  if (!m) return null;
  const kind = m[1].toLowerCase() as "deny" | "suggest" | "allow" | "defer";
  if (kind === "allow") return { verdict: { kind: "allow" } };
  if (kind === "deny") {
    const reason =
      /"reason"\s*:\s*"([^"]+)"/i.exec(text)?.[1] ??
      /reason[\s:]+["']?([^"';\n]{4,})/i.exec(text)?.[1];
    return { verdict: { kind: "deny", reason } };
  }
  if (kind === "suggest") {
    const alternative =
      /"alternative"\s*:\s*"([^"]+)"/i.exec(text)?.[1] ??
      /alternative[\s:]+["']?([^"';\n]{4,})/i.exec(text)?.[1];
    if (alternative) return { verdict: { kind: "suggest", alternative } };
    return null;
  }
  // defer
  const risk =
    /"risk"\s*:\s*"([^"]+)"/i.exec(text)?.[1] ??
    /risk[\s:]+["']?([^"';\n]{4,})/i.exec(text)?.[1];
  return { verdict: { kind: "defer", note: risk } };
}

function strField(
  args: Record<string, unknown>,
  key: string,
): string | undefined {
  const v = args[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function extractText(reply: AssistantMessage): string {
  return reply.content
    .filter((part): part is TextContent => part.type === "text")
    .map((part) => part.text)
    .join("");
}
