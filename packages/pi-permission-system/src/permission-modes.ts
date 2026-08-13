/**
 * Feature 6: Claude-style permission modes — a coarse layer over the per-rule
 * allow/ask/deny policy.
 *
 * Invariants:
 * - A mode ONLY resolves `ask` results. A configured `deny` is a hard boundary
 *   and is never overridden by any mode; a configured `allow` is never demoted.
 * - `default` leaves everything unchanged.
 * - `acceptEdits` auto-allows file-mutation asks (edit/write/bash).
 * - `plan` auto-denies file-mutation asks (read-only session).
 * - `bypassPermissions` auto-allows every ask.
 */
export type PermissionMode =
  | "default"
  | "acceptEdits"
  | "plan"
  | "bypassPermissions";

/** Tool surfaces treated as mutations for mode purposes. */
const MUTATION_TOOLS = new Set(["edit", "write", "bash"]);

export function isMutationTool(surface: string): boolean {
  return MUTATION_TOOLS.has(surface);
}

/**
 * Apply the mode to a resolved policy state. Only `ask` is transformed;
 * `allow`/`deny` pass through untouched.
 */
export function applyMode(
  state: "allow" | "ask" | "deny",
  surface: string,
  mode: PermissionMode,
): "allow" | "ask" | "deny" {
  if (state !== "ask") {
    return state;
  }
  switch (mode) {
    case "acceptEdits":
      return isMutationTool(surface) ? "allow" : state;
    case "plan":
      return isMutationTool(surface) ? "deny" : state;
    case "bypassPermissions":
      return "allow";
    case "default":
    default:
      return state;
  }
}
