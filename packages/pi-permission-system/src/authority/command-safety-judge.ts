/**
 * The `command-safety-judge` authorizer chain link: an allow-capable LLM judge
 * that rules on an `ask` with a four-state verdict (deny / suggest / allow /
 * defer), using a smart model at its top reasoning level.
 *
 * Registered under the name `"command-safety-judge"` and activated by naming it
 * in the `authorizerChain` config. It complements the deny-first typo reviewer
 * (`model-judge`): where that only ever denies typo paths on
 * `external_directory`, this judge reasons about *any* ask across all surfaces
 * and may allow, suggest a no-auth alternative, deny, or defer with a risk note.
 *
 * The bounded-delegation envelope still caps an `allow` on a deny-matched path
 * (#620 fine-grained), so the judge can auto-approve routine operations without
 * ever loosening a hard deny. Fail-safe: any error, timeout, or unparseable
 * model reply defers to the human (more prompting, never less).
 */

import { expandHomePath } from "#src/expand-home";
import { wildcardMatch } from "#src/wildcard-matcher";
import type { Authorizer, AuthorizerVerdict } from "#src/authority/authorizer";
import {
  type CommandSafetyJudgeConfig,
  resolveCommandSafetyConfig,
} from "#src/authority/command-safety-config";
import {
  type CompleteSimpleFn,
  type ModelRegistryLike,
  type OperationContext,
  reviewOperation,
} from "#src/authority/command-safety-review";
import type { PromptPermissionDetails } from "#src/authority/permission-prompter";
import type { AuthorizerLog } from "#src/service";

const DECISION_EVENT = "command_safety_judge.decision";
const SHORT_CIRCUIT_EVENT = "command_safety_judge.short_circuit";
const MODEL_REPLY_EVENT = "command_safety_judge.model_reply";

type PreModelDeferReason =
  | "no-config"
  | "model-unresolved" // both primary and fallback missing
  | "auth-failed"
  | "manual-confirm-path";

export interface CommandSafetyJudgeDeps {
  /** Read the resolved config live per ask. `undefined` keeps the judge inert. */
  getConfig: () => CommandSafetyJudgeConfig | undefined;
  /** The pi model registry (resolves provider/model → a Model + auth). */
  getRegistry: () => ModelRegistryLike | undefined;
  /** The `completeSimple` seam (supports a `reasoning` level). */
  completeSimple: CompleteSimpleFn;
  /** The session cwd, for operation context. */
  getCwd?: () => string | undefined;
}

/**
 * Create the `command-safety-judge` authorize callback. Reads config + registry
 * live per ask, so a config edit applies to the next ask without a restart.
 */
export function createCommandSafetyJudge(
  deps: CommandSafetyJudgeDeps,
): Authorizer["authorize"] {
  return async (details, _query, log) => {
    const config = deps.getConfig();
    if (!config) {
      return { kind: "defer" };
    }
    const { requestId } = details;
    const op = operationContextOf(details, deps);

    // 配置类文件：不送 LLM，直接 defer（人工确认）。manualConfirmGlobs 命中即跳过模型调用。
    if (op.path && config.manualConfirmGlobs.length > 0) {
      const normalized = expandHomePath(op.path);
      if (config.manualConfirmGlobs.some((g) => wildcardMatch(g, normalized))) {
        return deferWith(log, requestId, op, config, "manual-confirm-path");
      }
    }

    // Resolve a model: try the primary, fall back to the secondary.
    const registry = deps.getRegistry();
    const resolved = resolveModel(registry, config);
    if (!registry || !resolved) {
      return deferWith(log, requestId, op, config, "model-unresolved");
    }
    const auth = await registry.getApiKeyAndHeaders(resolved.model);
    if (!auth.ok) {
      // If the primary failed auth, try the fallback before giving up.
      if (resolved.isPrimary) {
        const fb = resolveFallback(registry, config);
        if (fb) {
          const fbAuth = await registry.getApiKeyAndHeaders(fb);
          if (fbAuth.ok) {
            return await runReview(details, op, config, fb, fbAuth, deps, log);
          }
        }
      }
      return deferWith(log, requestId, op, config, "auth-failed");
    }

    return await runReview(
      details,
      op,
      config,
      resolved.model,
      auth,
      deps,
      log,
    );
  };
}

/** Resolve the primary model, falling back if it is not registered. */
function resolveModel(
  registry: ModelRegistryLike | undefined,
  config: CommandSafetyJudgeConfig,
):
  | {
      model: import("#src/authority/command-safety-review").Model;
      isPrimary: boolean;
    }
  | undefined {
  if (!registry) return undefined;
  const primary = registry.find(config.provider, config.model);
  if (primary) return { model: primary, isPrimary: true };
  const fallback = resolveFallback(registry, config);
  return fallback ? { model: fallback, isPrimary: false } : undefined;
}

/** Resolve the fallback model alone. */
function resolveFallback(
  registry: ModelRegistryLike | undefined,
  config: CommandSafetyJudgeConfig,
): import("#src/authority/command-safety-review").Model | undefined {
  if (!registry) return undefined;
  if (!config.fallbackProvider || !config.fallbackModel) return undefined;
  return registry.find(config.fallbackProvider, config.fallbackModel);
}

/** Run the model review and log the outcome. */
async function runReview(
  details: PromptPermissionDetails,
  op: OperationContext,
  config: CommandSafetyJudgeConfig,
  model: import("#src/authority/command-safety-review").Model,
  auth: { ok: true; apiKey?: string; headers?: Record<string, string> },
  deps: CommandSafetyJudgeDeps,
  log: AuthorizerLog,
): Promise<AuthorizerVerdict> {
  const { requestId } = details;
  const modelId = `${model.providerId ?? "?"}/${model.id}`;
  const outcome = await reviewOperation({
    op,
    config,
    model,
    completeSimple: deps.completeSimple,
    apiKey: auth.apiKey,
    headers: auth.headers,
  });
  if (outcome.rawReply !== undefined) {
    log.debug(MODEL_REPLY_EVENT, {
      requestId,
      modelId,
      rawReply: outcome.rawReply,
    });
  }
  log.review(DECISION_EVENT, {
    requestId,
    surface: op.surface,
    toolName: op.toolName,
    path: op.path,
    command: op.command,
    modelCalled: true,
    modelId,
    reasoning: config.reasoning,
    latencyMs: outcome.latencyMs,
    verdict: outcome.verdict.kind,
    deferReason: outcome.deferReason ?? null,
  });
  return outcome.verdict;
}

/** Build the operation context the model reasons about, from ask details. */
function operationContextOf(
  details: PromptPermissionDetails,
  deps: CommandSafetyJudgeDeps,
): OperationContext {
  return {
    toolName: details.toolName,
    command: details.command,
    path: details.path ?? details.value ?? undefined,
    cwd: details.toolName === "bash" ? deps.getCwd?.() : undefined,
    surface: details.accessIntent?.surface ?? details.surface ?? undefined,
    message: details.message,
    agentName: details.agentName ?? undefined,
  };
}

function deferWith(
  log: AuthorizerLog,
  requestId: string,
  op: OperationContext,
  config: CommandSafetyJudgeConfig,
  deferReason: PreModelDeferReason,
): AuthorizerVerdict {
  log.review(DECISION_EVENT, {
    requestId,
    surface: op.surface,
    toolName: op.toolName,
    path: op.path,
    command: op.command,
    modelCalled: false,
    modelId: `${config.provider}/${config.model}`,
    reasoning: config.reasoning,
    latencyMs: null,
    verdict: "defer",
    deferReason,
  });
  return { kind: "defer" };
}

export { resolveCommandSafetyConfig };
