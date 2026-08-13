/**
 * The model call: ask a light model whether a candidate path is a typo, bounded
 * by `timeoutMs`, and map its reply to a `deny | defer` verdict.
 *
 * Fail-safe throughout — an unparseable reply, an unrecognized verdict, a
 * thrown or timed-out `complete`, all resolve to `defer` (more prompting,
 * never less). This slice never emits `allow`.
 *
 * Ported from pi-permission-model-judge (feature 2). The @earendil-works/pi-ai
 * types are redeclared as narrow structural projections below (that package is
 * not a dependency of the fork); the `complete` seam keeps the same shape.
 */

import type { AuthorizerVerdict } from "#src/authority/authorizer";
import type { ModelJudgeConfig } from "./config-schema";

/** The reason used for a deny when the model omits its own. */
export const GENERIC_TEACHING_REASON =
  "This looks like a mistyped path. Verify the correct location before retrying.";

// ---- narrow structural projections of @earendil-works/pi-ai types ---------
// Intentionally narrower than the real types: fields the reviewer does not
// read (ToolCall.id/name, ThinkingContent parts, optional systemPrompt) are
// omitted. The `complete` seam accepts these; do not extend the projections to
// match pi-ai without re-checking the runtime shapes.
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
// ----------------------------------------------------------------------------

/**
 * The single tool the model is forced to call. Forcing it (`toolChoice: "any"`)
 * removes free-text JSON parsing by construction — the verdict arrives as
 * structured `arguments`.
 */
const VERDICT_TOOL: Tool = {
  name: "report_verdict",
  description:
    "Report whether the path is a mistyped path to reject (deny) or should be deferred to the human (defer).",
  parameters: {
    type: "object",
    properties: {
      verdict: {
        type: "string",
        enum: ["deny", "defer"],
        description: "deny a mistyped path; defer anything else",
      },
      reason: {
        type: "string",
        description:
          "Why the path is wrong and the correct location (required when denying)",
      },
    },
    required: ["verdict"],
  },
};

/**
 * The injected model-completion seam — structurally the `complete` export of
 * `@earendil-works/pi-ai`. Injected so tests substitute a fake.
 */
export type CompleteFn = (
  model: Model,
  context: Context,
  options?: {
    signal?: AbortSignal;
    apiKey?: string;
    headers?: Record<string, string>;
    toolChoice?: string;
  },
) => Promise<AssistantMessage>;

export type ResolvedRequestAuth =
  | { ok: true; apiKey?: string; headers?: Record<string, string> }
  | { ok: false; error: string };

export interface ModelRegistryLike {
  find(provider: string, modelId: string): Model | undefined;
  getApiKeyAndHeaders(model: Model): Promise<ResolvedRequestAuth>;
}

export interface ReviewPathInputs {
  path: string;
  config: ModelJudgeConfig;
  model: Model;
  complete: CompleteFn;
  apiKey?: string;
  headers?: Record<string, string>;
}

export type ModelCallDeferReason =
  | "no-tool-call"
  | "non-deny-verdict"
  | "timeout"
  | "call-failed";

export interface ReviewOutcome {
  verdict: AuthorizerVerdict;
  deferReason?: ModelCallDeferReason;
  latencyMs: number;
  rawReply?: string;
}

export async function reviewPath(
  inputs: ReviewPathInputs,
): Promise<ReviewOutcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, inputs.config.timeoutMs);
  const startedAt = Date.now();
  try {
    const context: Context = {
      systemPrompt: inputs.config.instructions,
      tools: [VERDICT_TOOL],
      messages: [
        {
          role: "user",
          content: renderReviewPrompt(inputs.path),
          timestamp: Date.now(),
        },
      ],
    };
    const reply = await inputs.complete(inputs.model, context, {
      signal: controller.signal,
      apiKey: inputs.apiKey,
      headers: inputs.headers,
      toolChoice: "any",
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

function renderReviewPrompt(path: string): string {
  return [
    "A tool is about to access this path outside the working directory:",
    "",
    path,
    "",
    'Call report_verdict. Use verdict "deny" with a reason naming the correct location if this is a mistyped path; otherwise use verdict "defer".',
  ].join("\n");
}

function readToolCallOutcome(
  reply: AssistantMessage,
  latencyMs: number,
): ReviewOutcome {
  const call = reply.content.find(
    (part): part is ToolCall => part.type === "toolCall",
  );
  if (!call) {
    // Fallback for providers whose endpoint ignores `toolChoice` (e.g. the
    // openai-completions/google endpoints return free text): parse a verdict
    // from the text so the judge is not a silent no-op. Anything unparseable
    // still defers (fail-safe).
    const text = extractText(reply);
    const verdictMatch =
      /"verdict"\s*:\s*"(deny|defer)"/i.exec(text) ??
      /verdict[\s:]+(deny|defer)/i.exec(text);
    if (verdictMatch?.[1]?.toLowerCase() === "deny") {
      const reasonMatch =
        /"reason"\s*:\s*"([^"]+)"/i.exec(text) ??
        /reason[\s:]+["']?([^"';\n]{4,})/i.exec(text);
      return {
        verdict: {
          kind: "deny",
          reason: reasonMatch?.[1]?.trim() ?? GENERIC_TEACHING_REASON,
        },
        latencyMs,
        rawReply: text.slice(0, 500),
      };
    }
    return {
      verdict: { kind: "defer" },
      deferReason: "no-tool-call",
      latencyMs,
      rawReply: text,
    };
  }
  const args = call.arguments;
  const rawReply = JSON.stringify(args);
  if (args.verdict !== "deny") {
    return {
      verdict: { kind: "defer" },
      deferReason: "non-deny-verdict",
      latencyMs,
      rawReply,
    };
  }
  const reason =
    typeof args.reason === "string" && args.reason.length > 0
      ? args.reason
      : GENERIC_TEACHING_REASON;
  return { verdict: { kind: "deny", reason }, latencyMs, rawReply };
}

function extractText(reply: AssistantMessage): string {
  return reply.content
    .filter((part): part is TextContent => part.type === "text")
    .map((part) => part.text)
    .join("");
}
