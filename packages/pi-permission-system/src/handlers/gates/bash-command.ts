import type {
  BashCommand,
  WrapperKind,
} from "#src/access-intent/bash/command-enumeration";
import { pickMostRestrictive } from "#src/handlers/gates/candidate-check";
import type { ScopedPermissionResolver } from "#src/permission-resolver";
import type { PermissionCheckResult } from "#src/types";

/**
 * Resolve the bash command-pattern decision for a (possibly chained) command.
 *
 * A bash invocation may be a shell program with several commands joined by
 * `&&`, `||`, `;`, `|`, `&`, or newlines. Matching the whole string against the
 * bash patterns lets a denied command ride through on an allowed leading one
 * (issue #301). Instead, the caller supplies the program's command units (from
 * the shared `BashProgram.commands()` parse) — including those nested inside
 * substitutions and subshells (#306); each is evaluated on the `bash` surface
 * and the most restrictive result wins (`deny > ask > allow`).
 *
 * The selected result carries the offending sub-command in `command`, its rule
 * in `matchedPattern`, and the offending command's execution context in
 * `commandContext` (set only for a nested command), so the prompt,
 * session-approval suggestion, and decision event scope to that command.
 *
 * A wrapper unit (flagged with a `wrapperKind` by the enumerator) hides or
 * indirects the command that should be gated, so an `allow` is floored up to a
 * synthetic `deny` — the `<opaque-bash-wrapper>` pattern for an inline-shell
 * payload (`bash -c`/`eval`, #481) or `<indirection-bash-wrapper>` for a
 * prefix/exec wrapper (`sudo`/`env`/`xargs`/`find -exec`/…, #490) — to keep it
 * from riding a permissive rule; an explicit `deny`/`ask` on the wrapper is left
 * untouched (`deny > ask > allow`). A wrapper unit whose text starts with a
 * `wrapperAllowlist` entry keeps its `allow` — the allowlist holds only
 * wrapper commands the user has explicitly vetted and trusted.
 *
 * When `commands` is empty there are two cases. A trivially-empty command (an
 * empty, whitespace-only, or comment-only line) has genuinely nothing to gate,
 * so the whole `command` is resolved as before. A non-empty command that parsed
 * to zero command units (a parse anomaly or an opaque program) fails closed to
 * a synthetic `ask` so a permissive top-level `*` cannot silently allow an
 * unparseable command (e.g. `cd /repo && git push` riding a top-level allow on
 * the empty-parse path) — #452.
 *
 * Pure and synchronous: the (async, tree-sitter) parse happens once in the
 * handler, which passes the decomposed `commands` here.
 */
/**
 * The synthetic `matchedPattern` recorded when a wrapper unit's `allow` is
 * floored to `deny`, keyed by the wrapper kind that caused the floor.
 */
const WRAPPER_SENTINEL: Record<WrapperKind, string> = {
  "opaque-payload": "<opaque-bash-wrapper>",
  indirection: "<indirection-bash-wrapper>",
};

/**
 * Denial reason attached when a wrapper unit's `allow` is floored to `deny`.
 * Tells the agent (and the operator reading the logs) exactly how to lift the
 * floor for a command they have deliberately vetted.
 */
const WRAPPER_DENY_REASON =
  "indirection/opaque wrapper cannot be judged safely — denied by default; if you explicitly trust this command, add it to the `wrapperAllowlist` config key";

/**
 * True when a wrapper command unit's (trimmed) text starts with any
 * `wrapperAllowlist` entry. The allowlist holds only wrapper commands the
 * user has explicitly vetted; a prefix match keeps the unit's `allow`
 * (no floor).
 */
function isAllowlistedWrapperUnit(
  text: string,
  allowlist: readonly string[],
): boolean {
  const unit = text.trim();
  return allowlist.some((entry) => entry.length > 0 && unit.startsWith(entry));
}

/**
 * Pure read-only command names — no side effects, no file mutation. A bash
 * chain whose every unit's command name is in this set, with no write
 * redirect, is auto-allowed without floor-to-ask — it changes nothing.
 *
 * Conservative: commands with write-capable variants (sed -i, awk system(),
 * tee, cp/mv/rm, git commit/push) are excluded. The path/path_write gates
 * still run separately, so secret-file reads stay denied. Wrappers
 * (env/xargs/time — in INDIRECTION_WRAPPER_NAMES) are excluded; their
 * read-only-ness depends on the inner command (handled by the floor path).
 */
const READONLY_COMMAND_NAMES = new Set([
  "echo",
  "printf",
  "date",
  "uptime",
  "whoami",
  "uname",
  "hostname",
  "id",
  "pwd",
  "true",
  "false",
  "test",
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "tac",
  "nl",
  "od",
  "xxd",
  "file",
  "stat",
  "basename",
  "dirname",
  "realpath",
  "readlink",
  "ls",
  "find",
  "fd",
  "grep",
  "rg",
  "ack",
  "locate",
  "tree",
  "which",
  "type",
  "command",
  "wc",
  "sort",
  "uniq",
  "cut",
  "tr",
  "column",
  "paste",
  "expand",
  "fmt",
  "ps",
  "top",
  "free",
  "df",
  "du",
  "lsblk",
  "lscpu",
  "lspci",
  "lsusb",
  "printenv",
  "jq",
  "yq",
  "bat",
  "exa",
  "eza",
]);

/** git subcommands that only read (no repo mutation). */
const READONLY_GIT_SUBCOMMANDS = new Set([
  "log",
  "status",
  "diff",
  "show",
  "blame",
  "branch",
  "reflog",
  "ls-files",
  "ls-tree",
  "remote",
  "rev-parse",
  "describe",
  "shortlog",
  "name-rev",
  "grep",
  "for-each-ref",
]);

/** gh subcommands that only read (two-level: resource + action). */
const READONLY_GH_SUBCOMMANDS = new Set([
  "auth status",
  "auth token",
  "repo view",
  "issue list",
  "issue view",
  "pr list",
  "pr view",
  "pr status",
  "pr checks",
  "pr diff",
  "release list",
  "release view",
  "run list",
  "run view",
  "run watch",
  "workflow list",
  "workflow view",
  "label list",
  "search repos",
  "search code",
  "search issues",
  "search prs",
]);

/**
 * True when a command chain is entirely read-only: every unit's command name
 * is a known read-only command (or a read-only git subcommand), and the full
 * command has no write redirect (">"). Conservative — any ">" (including
 * stderr merges 2>&1 or ">" inside quotes) disables the fast path so the
 * normal floor-to-ask path applies. Never weaker than the default.
 */
/** Harmful write redirect: > or >> to a file (excludes fd merges 2>&1, >&2, and >/dev/null). */
const HARMFUL_REDIRECT = /\d*>{1,2}\s*(?!&|\/dev\/null\b)\S/;

function isReadOnlyChain(
  commands: BashCommand[],
  fullCommand: string,
): boolean {
  if (commands.length === 0) return false;
  // Only short-circuit wrapper chains (env/xargs/sudo…); a non-wrapper chain
  // resolves normally so its matchedPattern/session-approval stays intact.
  if (!commands.some((c) => c.wrapperKind)) return false;
  if (HARMFUL_REDIRECT.test(fullCommand)) return false;
  return commands.every((cmd) => {
    // Opaque payloads (bash -c/eval) can't be penetrated — don't short-circuit.
    if (cmd.wrapperKind === "opaque-payload") return false;
    const parts = cmd.text.trim().split(/\s+/);
    let idx = 0;
    let name = parts[idx++] ?? "";
    // Penetrate indirection wrappers: skip the wrapper + its options/env-vars
    // to reach the inner command name, then judge read-only-ness on that.
    if (cmd.wrapperKind === "indirection") {
      while (
        idx < parts.length &&
        (parts[idx].startsWith("-") ||
          /^[A-Za-z_][A-Za-z0-9_]*=/.test(parts[idx]) ||
          /^\d/.test(parts[idx]))
      ) {
        idx++;
      }
      name = parts[idx++] ?? "";
      // Wrapper with no inner command (e.g. bare env/time) changes no
      // file — treat as read-only.
      if (!name) return true;
    }
    if (READONLY_COMMAND_NAMES.has(name)) return true;
    if (name === "git") {
      const sub = parts[idx] ?? "";
      if (sub === "config") {
        // git config --get*/--list is read-only; --set/--add/--unset writes
        const args = parts.slice(idx + 1);
        return args.some((a) =>
          [
            "--get",
            "--get-all",
            "--get-regexp",
            "--list",
            "-l",
            "--name-only",
          ].includes(a),
        );
      }
      return READONLY_GIT_SUBCOMMANDS.has(sub);
    }
    if (name === "gh") {
      const sub = ((parts[idx] ?? "") + " " + (parts[idx + 1] ?? "")).trim();
      return READONLY_GH_SUBCOMMANDS.has(sub);
    }
    if (name === "sed") {
      // sed without -i/--in-place is read-only stream editing
      return !parts
        .slice(idx)
        .some(
          (p) =>
            /^-[^-]*i/.test(p) ||
            p === "--in-place" ||
            p.startsWith("--in-place"),
        );
    }
    return false;
  });
}

export function resolveBashCommandCheck(
  command: string,
  commands: BashCommand[],
  agentName: string | undefined,
  resolver: ScopedPermissionResolver,
  wrapperAllowlist: readonly string[] = [],
): PermissionCheckResult {
  if (commands.length === 0) {
    if (isTriviallyEmptyCommand(command)) {
      return resolver.resolve({
        kind: "tool",
        surface: "bash",
        input: { command },
        agentName,
      });
    }
    return {
      state: "ask",
      toolName: "bash",
      source: "bash",
      origin: "builtin",
      command,
      matchedPattern: "<unparseable-bash-command>",
    };
  }

  // Read-only fast path: a chain of pure read-only commands with no write
  // redirect changes nothing — auto-allow without floor-to-ask. The separate
  // path/path_write gates still enforce secret-file denies.
  if (isReadOnlyChain(commands, command)) {
    return {
      state: "allow",
      toolName: "bash",
      source: "bash",
      origin: "builtin",
      command,
      matchedPattern: "<readonly-chain>",
    };
  }

  const results = commands.map((cmd) => {
    const base = resolver.resolve({
      kind: "tool",
      surface: "bash",
      input: { command: cmd.text },
      agentName,
    });
    const result =
      cmd.wrapperKind && base.state === "allow"
        ? isAllowlistedWrapperUnit(cmd.text, wrapperAllowlist)
          ? base
          : {
              ...base,
              state: "deny" as const,
              matchedPattern: WRAPPER_SENTINEL[cmd.wrapperKind],
              reason: WRAPPER_DENY_REASON,
            }
        : base;
    return cmd.context ? { ...result, commandContext: cmd.context } : result;
  });
  return (
    pickMostRestrictive(results) ??
    resolver.resolve({
      kind: "tool",
      surface: "bash",
      input: { command },
      agentName,
    })
  );
}

/**
 * True when a command has genuinely nothing to gate: it is empty,
 * whitespace-only, or contains only comment lines (every non-blank line starts
 * with `#`). Such a command yields zero command units legitimately, so the
 * whole-string resolve is safe rather than a parse anomaly.
 */
function isTriviallyEmptyCommand(command: string): boolean {
  const lines = command
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return lines.every((line) => line.startsWith("#"));
}
