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
import type { PermissionQuery } from "#src/service";

/** Surfaces on which a link may never grant an `allow` (ADR 0007 §5). */
export const DELEGATION_EXCLUDED_SURFACES: ReadonlySet<string> = new Set([
  "external_directory",
  "path",
]);

/**
 * Wrap a link's `authorize` so an `allow` on an excluded surface is capped to
 * `defer`. All other verdicts, and `allow`s on non-excluded surfaces, pass
 * through unchanged. `details`, the injected `query`, and the review-log `log`
 * are forwarded as-is.
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
 * Whether the ask's surface is excluded from link grants. Reads the
 * gate-authoritative `accessIntent.surface`, falling back to the display
 * `surface`. Fail-safe: an ask whose surface cannot be determined is treated as
 * excluded (more prompting, never less — ADR 0007 invariant 2).
 */
function isCappedByHardRule(
  details: PromptPermissionDetails,
  query: PermissionQuery,
): boolean {
  const surface = details.accessIntent?.surface ?? details.surface ?? undefined;
  if (surface === undefined) return true;
  // external_directory: whole-surface exclusion (the boundary *is* the policy).
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
  query: PermissionQuery,
  surface: string,
): boolean {
  const values = candidatePathValues(details);
  if (values.length === 0) return true; // no path to test → fail-safe cap
  // Fail-safe: if the query cannot resolve, treat the path as excluded.
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
