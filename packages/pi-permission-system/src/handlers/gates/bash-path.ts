import type { AccessPath } from "#src/access-intent/access-path";
import type { BashProgram } from "#src/access-intent/bash/program";
import type { BashTokenRole } from "#src/access-intent/bash/token-collection";
import type { PathNormalizer } from "#src/path-normalizer";
import type { ScopedPermissionResolver } from "#src/permission-resolver";
import { SessionApproval } from "#src/session-approval";
import { deriveApprovalPattern } from "#src/session-rules";
import type { PermissionCheckResult } from "#src/types";
import { pickMostRestrictive } from "./candidate-check";
import type { GateResult } from "./descriptor";
import { accessFactsFromPath, isCreateWithinCwd } from "./helpers";
import { formatPathAskPrompt } from "./path";
import type { ToolCallContext } from "./types";

/**
 * Build a pure descriptor for the cross-cutting path permission gate (bash).
 *
 * Reads path-rule candidates from the injected `BashProgram` (the broader
 * `path`-rule filter, accepting dot-files and relative paths). Each candidate
 * pairs the raw token with cd-aware policy values; the gate evaluates those
 * values against the `path` permission surface and returns the most
 * restrictive result, while prompts, logs, and session approvals use the raw
 * token.
 *
 * Returns `null` when the gate does not apply (not a shell invocation, no
 * command, no tokens extracted, or all tokens evaluate to `allow`).
 * Returns a `GateBypass` when all tokens are session-covered.
 * Returns a `GateDescriptor` for the most restrictive token needing a check.
 *
 * The shell command (native `bash` or an aliased shell tool) is read from the
 * injected `BashProgram`, which owns the source text it was parsed from, so
 * this gate does not re-derive the input field name (#574).
 */
export function describeBashPathGate(
  tcc: ToolCallContext,
  bashProgram: BashProgram | null,
  resolver: ScopedPermissionResolver,
  normalizer: PathNormalizer,
): GateResult {
  if (!bashProgram) return null;
  const command = bashProgram.commandText();

  const candidates = bashProgram.pathRuleCandidates();
  if (candidates.length === 0) return null;
  const tokens = candidates.map(({ token }) => token);

  // Tokens whose resolved state needs a check (deny/ask), paired with the raw
  // token (prompt/decision display) and its `AccessPath` (whose `value()` is
  // the lexical absolute path the approval pattern is derived from).
  const uncovered: Array<{
    token: string;
    path: AccessPath;
    check: PermissionCheckResult;
    role: BashTokenRole;
  }> = [];
  let allSessionCovered = true;

  for (const { token, path, role } of candidates) {
    // A business argument is not a filesystem target from the shell's
    // perspective (`sys-backup.sh is-tracked "$HOME/.env"`) — neither
    // protection layer applies, so the token is unrestricted.
    if (role === "arg") {
      allSessionCovered = false;
      continue;
    }

    // Creating a not-yet-existing entry inside the cwd is granted by default:
    // sensitive-name rules (`*.env`) protect existing secrets, not new
    // project files. Exempting the token skips both write surfaces
    // (`path_write` and `path`) at once — the token is unrestricted, exactly
    // like an `arg`-role business argument.
    if (role === "write" && isCreateWithinCwd(normalizer, path)) {
      allSessionCovered = false;
      continue;
    }

    // Route by access direction: reads go through the information-security
    // `path` surface; writes go through the integrity `path_write` surface
    // and additionally the `path` surface (a secret overwrite is both a
    // leak and damage), taking the most restrictive result.
    const check =
      role === "write"
        ? (pickMostRestrictive([
            resolver.resolve({
              kind: "access-path",
              surface: "path_write",
              path,
              agentName: tcc.agentName ?? undefined,
            }),
            resolver.resolve({
              kind: "access-path",
              surface: "path",
              path,
              agentName: tcc.agentName ?? undefined,
            }),
          ]) ?? {
            toolName: "path",
            state: "allow",
            source: "special",
            origin: "builtin",
          })
        : resolver.resolve({
            kind: "access-path",
            surface: "path",
            path,
            agentName: tcc.agentName ?? undefined,
          });

    // No explicit path rule matched — only the universal default fired.
    // Treat this token as unrestricted to preserve backward compatibility
    // for configs without a "path" key (#58).
    if (check.matchedPattern === undefined && check.source !== "session") {
      allSessionCovered = false;
      continue;
    }

    if (check.source !== "session") {
      allSessionCovered = false;
    }

    if (check.state === "deny") {
      uncovered.push({ token, path, check, role });
      break; // Short-circuit on deny.
    }
    if (check.state === "ask") {
      uncovered.push({ token, path, check, role });
    }
  }

  // All tokens are session-covered — bypass.
  if (allSessionCovered) {
    return {
      action: "allow",
      log: {
        event: "permission_request.session_approved",
        details: {
          source: "tool_call",
          toolCallId: tcc.toolCallId,
          toolName: tcc.toolName,
          agentName: tcc.agentName,
          command,
          tokens,
          resolution: "session_approved",
        },
      },
    };
  }

  // Pick the most restrictive (deny > ask > allow, first-wins) uncovered token.
  const worstCheck = pickMostRestrictive(uncovered.map(({ check }) => check));
  const worstEntry = worstCheck
    ? uncovered.find(({ check }) => check === worstCheck)
    : undefined;
  const worstToken = worstEntry?.token ?? null;

  // All tokens evaluate to allow — no restriction.
  if (!worstCheck || !worstToken || !worstEntry) return null;

  // Derive the pattern from the lexical absolute form (the cd-aware resolved
  // path), so it matches the values a later call produces. For an unknown base
  // (`forLiteral`) `value()` is the raw token.
  const pattern = deriveApprovalPattern(worstEntry.path.value());
  const askMessage = formatPathAskPrompt(
    tcc.toolName,
    worstToken,
    tcc.agentName ?? undefined,
  );

  // A write-direction token is gated by the integrity `path_write` surface;
  // a read-direction token by the information-security `path` surface. The
  // session approval and decision surface follow the same direction so a
  // session grant scopes to the layer that actually fired.
  const gateSurface = worstEntry.role === "write" ? "path_write" : "path";

  return {
    surface: gateSurface,
    input: { path: worstToken },
    denialContext: {
      kind: "bash_path",
      command,
      pathValue: worstToken,
      agentName: tcc.agentName ?? undefined,
    },
    sessionApproval: SessionApproval.single(gateSurface, pattern),
    promptDetails: {
      source: "tool_call",
      agentName: tcc.agentName,
      message: askMessage,
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      command,
      accessIntent: accessFactsFromPath(gateSurface, worstEntry.path),
    },
    logContext: {
      source: "tool_call",
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      agentName: tcc.agentName,
      command,
      path: worstToken,
    },
    decision: {
      surface: gateSurface,
      value: worstToken,
    },
    preCheck: worstCheck,
  };
}
