/**
 * The bounded-delegation enforcement checkpoint (ADR 0007 §5).
 *
 * The chain owner caps every registered link's verdict so a buggy or over-eager
 * external judge can never exceed the operator's policy: a link's `allow` on an
 * excluded surface is downgraded to `defer`, letting the `ask` fall through to
 * the terminal (a prompt) instead. The checkpoint only ever *tightens* a
 * verdict — it never turns a `defer`/`deny` into an `allow`.
 *
 * The excluded set is the whole `path` surface plus `external_directory`. A
 * finer secret-shaped-`path` exclusion (letting a link allow a non-secret path)
 * is deferred to the allow-capable slice that needs it (#620); until then the
 * conservative whole-surface exclusion ships. The checkpoint is dormant while
 * the only registered links are deny-first (they never `allow`).
 */

import type { Authorizer } from "./authorizer";
import type { PromptPermissionDetails } from "./permission-prompter";

/** Surfaces on which a link may never grant an `allow` (ADR 0007 §5). */
export const DELEGATION_EXCLUDED_SURFACES: ReadonlySet<string> = new Set([
  "external_directory",
  "path",
]);

/**
 * Wrap a link's `authorize` so an `allow` that would loosen a hard `deny` is
 * capped to `defer`. All other verdicts pass through unchanged.
 *
 * Fine-grained (#620): instead of excluding whole surfaces (`path` /
 * `external_directory`), the envelope now consults the injected `query` to test
 * whether the operation's path actually resolves to a `deny` on the
 * `path`/`path_write` surface. A non-sensitive path (no deny hit) may be
 * auto-allowed by a link; a deny-matched path keeps the link's `allow` capped to
 * `defer`. `external_directory` stays whole-surface excluded (its boundary is
 * the policy itself, not a per-path rule). Fail-safe: an ask whose path/surface
 * cannot be determined is treated as excluded (more prompting, never less).
 */
export function encloseInDelegationEnvelope(
  authorize: Authorizer["authorize"],
): Authorizer["authorize"] {
  return async (details, query, log) => {
    const verdict = await authorize(details, query, log);
    if (verdict.kind === "allow" && isCappedByHardRule(details, query)) {
      return { kind: "defer" };
    }
    return verdict;
  };
}

/**
 * Whether a link's `allow` must be capped to `defer` because the operation hits
 * a hard rule the operator's policy denies.
 *
 * - `external_directory` asks stay whole-surface excluded (the boundary *is* the
 *   policy; there is no per-path deny to consult).
 * - `path`/`path_write` asks consult the query: only a path that resolves to
 *   `deny` is excluded, so a non-sensitive path may be auto-allowed.
 * - An undeterminable surface is excluded (fail-safe, ADR 0007 invariant 2).
 */
function isCappedByHardRule(
  details: PromptPermissionDetails,
  query: import("#src/service").PermissionQuery,
): boolean {
  const surface = details.accessIntent?.surface ?? details.surface ?? undefined;
  if (surface === undefined) return true;
  // external_directory: whole-surface exclusion (boundary is the policy).
  if (surface === "external_directory") return true;
  // path / path_write: fine-grained — cap only if the path resolves to deny.
  if (surface === "path" || surface === "path_write") {
    return pathHitsDeny(details, query, surface);
  }
  // Other surfaces (bash, tool-level): no cap (their denies already fired at
  // the gate before the ask reached the chain).
  return false;
}

/**
 * True when any candidate path value resolves to a `deny` on `surface`.
 */
function pathHitsDeny(
  details: PromptPermissionDetails,
  query: import("#src/service").PermissionQuery,
  surface: string,
): boolean {
  const values = candidatePathValues(details);
  if (values.length === 0) return true; // no path to test → fail-safe cap
  // Fail-safe: if the query cannot resolve (missing checkPermission, or it
  // returns no result), treat the path as excluded (more prompting, never less).
  if (typeof query.checkPermission !== "function") return true;
  for (const value of values) {
    const result = query.checkPermission(
      surface,
      value,
      details.agentName ?? undefined,
    );
    if (!result || result.state === "deny") return true;
  }
  return false;
}

/** The path value(s) an ask carries, from accessIntent matchValues or display fields. */
function candidatePathValues(details: PromptPermissionDetails): string[] {
  const seen = new Set<string>();
  for (const value of details.accessIntent?.matchValues ?? []) {
    if (value) seen.add(value);
  }
  if (details.path) seen.add(details.path);
  if (typeof details.value === "string" && details.value) {
    seen.add(details.value);
  }
  return [...seen];
}
