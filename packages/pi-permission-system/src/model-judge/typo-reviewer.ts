/**
 * The deny-first typo-path reviewer: the `Authorizer` chain link registered as
 * `"model-judge"` (feature 2, ported from pi-permission-model-judge).
 *
 * The decision runs top to bottom, deferring at the first miss:
 *   1. surface is `external_directory` (else defer),
 *   2. a candidate path is present (else defer),
 *   3. the path matches a configured typo pattern (else defer, no model call),
 *   4. the model confirms the typo (deny with a teaching reason) or defers.
 *
 * Every failure path defers — more prompting, never less. Never emits `allow`.
 */

import type { Authorizer, AuthorizerVerdict } from "../authority/authorizer";
import type { PromptPermissionDetails } from "../authority/permission-prompter";
import type { AuthorizerLog } from "../service";
import type { ModelJudgeConfig } from "./config-schema";
import {
  type CompleteFn,
  type ModelRegistryLike,
  reviewPath,
} from "./model-review";
import {
  type CompiledTypoPatterns,
  compileTypoPatterns,
  matchTypoPattern,
} from "./typo-patterns";

const REVIEWED_SURFACE = "external_directory";

const DECISION_EVENT = "model_judge.decision";
const SHORT_CIRCUIT_EVENT = "model_judge.short_circuit";
const MODEL_REPLY_EVENT = "model_judge.model_reply";
const INVALID_PATTERNS_EVENT = "model_judge.invalid_patterns";

type PreModelDeferReason = "model-unresolved" | "auth-failed";

interface DecisionBase {
  requestId: string;
  path: string;
  matchedPattern: string;
  modelId: string;
}

export interface TypoReviewerDeps {
  getConfig: () => ModelJudgeConfig | undefined;
  getRegistry: () => ModelRegistryLike | undefined;
  complete: CompleteFn;
}

export function createTypoReviewer(
  deps: TypoReviewerDeps,
): Authorizer["authorize"] {
  const compiledFor = memoizeCompiledPatterns();

  return async (details, _query, log) => {
    const config = deps.getConfig();
    if (!config) {
      return { kind: "defer" };
    }
    if (surfaceOf(details) !== REVIEWED_SURFACE) {
      return { kind: "defer" };
    }
    const { requestId } = details;
    const candidates = candidatePathsOf(details);
    if (candidates.length === 0) {
      log.debug(SHORT_CIRCUIT_EVENT, { requestId, reason: "no-path" });
      return { kind: "defer" };
    }
    const compiled = compiledFor(config, log);
    let matched: { path: string; matchedPattern: string } | undefined;
    for (const candidate of candidates) {
      const pattern = matchTypoPattern(candidate, compiled);
      if (pattern !== undefined) {
        matched = { path: candidate, matchedPattern: pattern };
        break;
      }
    }
    if (matched === undefined) {
      log.debug(SHORT_CIRCUIT_EVENT, {
        requestId,
        path: candidates[0],
        reason: "pattern-miss",
      });
      return { kind: "defer" };
    }
    const { path, matchedPattern } = matched;

    const modelId = `${config.provider}/${config.model}`;
    const base: DecisionBase = { requestId, path, matchedPattern, modelId };
    const registry = deps.getRegistry();
    const model = registry?.find(config.provider, config.model);
    if (!registry || !model) {
      return deferWith(log, base, "model-unresolved");
    }
    const auth = await registry.getApiKeyAndHeaders(model);
    if (!auth.ok) {
      return deferWith(log, base, "auth-failed");
    }

    const outcome = await reviewPath({
      path,
      config,
      model,
      complete: deps.complete,
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
      surface: REVIEWED_SURFACE,
      path,
      matchedPattern,
      modelCalled: true,
      modelId,
      latencyMs: outcome.latencyMs,
      verdict: outcome.verdict.kind,
      deferReason: outcome.deferReason ?? null,
    });
    return outcome.verdict;
  };
}

function deferWith(
  log: AuthorizerLog,
  base: DecisionBase,
  deferReason: PreModelDeferReason,
): AuthorizerVerdict {
  log.review(DECISION_EVENT, {
    requestId: base.requestId,
    surface: REVIEWED_SURFACE,
    path: base.path,
    matchedPattern: base.matchedPattern,
    modelCalled: false,
    modelId: base.modelId,
    latencyMs: null,
    verdict: "defer",
    deferReason,
  });
  return { kind: "defer" };
}

function surfaceOf(details: PromptPermissionDetails): string | undefined {
  return details.accessIntent?.surface ?? details.surface ?? undefined;
}

function candidatePathsOf(details: PromptPermissionDetails): string[] {
  const seen = new Set<string>();
  for (const value of details.accessIntent?.matchValues ?? []) {
    seen.add(value);
  }
  if (details.path !== undefined) {
    seen.add(details.path);
  }
  if (details.value != null) {
    seen.add(details.value);
  }
  return [...seen];
}

function memoizeCompiledPatterns(): (
  config: ModelJudgeConfig,
  log: AuthorizerLog,
) => CompiledTypoPatterns {
  let cache:
    | { config: ModelJudgeConfig; compiled: CompiledTypoPatterns }
    | undefined;
  return (config, log) => {
    if (cache?.config === config) {
      return cache.compiled;
    }
    const compiled = compileTypoPatterns(config.typoPatterns);
    if (compiled.invalidPatterns.length > 0) {
      log.debug(INVALID_PATTERNS_EVENT, {
        invalidPatterns: compiled.invalidPatterns,
      });
    }
    cache = { config, compiled };
    return compiled;
  };
}
