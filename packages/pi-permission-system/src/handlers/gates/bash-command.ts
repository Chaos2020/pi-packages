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
 * synthetic `ask` — the `<opaque-bash-wrapper>` pattern for an inline-shell
 * payload (`bash -c`/`eval`, #481) or `<indirection-bash-wrapper>` for a
 * prefix/exec wrapper (`sudo`/`env`/`xargs`/`find -exec`/…, #490) — to keep it
 * from riding a permissive rule; an explicit `deny`/`ask` on the wrapper is left
 * untouched (`deny > ask > allow`).
 *
 * When `commands` is empty there are two cases. A trivially-empty command (an
 * empty, whitespace-only, or comment-only line) has genuinely nothing to gate,
 * so the whole `command` is resolved as before. A non-empty command that parsed
 * to zero command units (a parse anomaly or an opaque program) fails closed to
 * a synthetic `ask` so a permissive top-level `*` cannot silently allow an
 * unparseable command (e.g. `cd /repo && git push` riding a top-level allow on
 * the empty-parse path) — #452. The whole command is still resolved first so an
 * explicit `deny` covering it denies outright rather than being masked into an
 * approvable prompt (#712).
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

/** Denial reason attached when a wrapper unit's `allow` is floored to `deny`. */
const WRAPPER_FLOOR_REASON =
  "indirection/opaque wrapper cannot be judged safely — denied by default; ask the user or operator to review and explicitly trust this command if it should run";

/**
 * Pure read-only command names — no side effects, no file mutation. A bash
 * chain whose every unit's command name is in this set, with no write
 * redirect, is auto-allowed without floor-to-ask — it changes nothing.
 *
 * Conservative: commands with write-capable variants (sed -i/yq -i, awk
 * system(), tee, cp/mv/rm, git commit/push) are excluded — `sort` is handled
 * specially (-o/--output writes in place, F5). Exec/secret-capable names are
 * excluded too: `find` (its exec/delete/report-write flags are floored via
 * EXEC_CONDITIONAL_WRAPPERS, F1), `command` (exec builtin), and `less`/`more`
 * (`+!cmd` shell escapes) can all run or remove things (C1/C2). `jq`
 * (`--rawfile`/`--slurpfile` read a file into the output, F3), `rg` (`--pre`
 * runs a command per matching file, F4), and `fd` (`-x`/`-X` exec per result)
 * have variants this name-only check cannot gate, so they are excluded
 * outright. `printenv` and bare `env` are environment dumps — excluded (M3,
 * F2: a downstream pipe stage like `cat` filters nothing, so a piped `env`
 * is still a full dump). `tree` (-o writes a report file) is excluded. The path/path_write gates still run
 * separately, so secret-file reads stay denied. Wrappers (env/xargs/time — in
 * INDIRECTION_WRAPPER_NAMES) are excluded; their read-only-ness depends on the
 * inner command (handled by the floor path).
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
  "grep",
  "ack",
  "locate",
  "which",
  "type",
  "wc",
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
  "bat",
  "exa",
  "eza",
]);

/**
 * git subcommands that only read (no repo mutation). `branch` (`-D` deletes)
 * and `remote` (`add`/`remove`/`set-url` mutate) are excluded (M1).
 */
const READONLY_GIT_SUBCOMMANDS = new Set([
  "log",
  "status",
  "diff",
  "show",
  "blame",
  "reflog",
  "ls-files",
  "ls-tree",
  "rev-parse",
  "describe",
  "shortlog",
  "name-rev",
  "grep",
  "for-each-ref",
]);

/**
 * gh subcommands that only read (two-level: resource + action). `auth token`
 * dumps a credential — excluded (M1).
 */
const READONLY_GH_SUBCOMMANDS = new Set([
  "auth status",
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
      // sudo/doas never ride the read-only fast path (B1/B2/m1): their flag
      // grammar is open-ended (`-p`/`-a`/`-c`/`-r`/`-t`/`-T`/`-U` take
      // values, a bare `sudo -s`/`-i` spawns a root shell with no inner
      // command, and `sudo -l` enumerates the user's privileges), so no
      // token-level penetration can be safe. Every sudo/doas unit — wrapper
      // or inner — falls through to the normal resolve + wrapper floor
      // (deny unless an explicit deny/ask rule or a wrapperAllowlist entry).
      const wrapperName = parts[0] ?? "";
      if (wrapperName === "sudo" || wrapperName === "doas") return false;
      while (idx < parts.length) {
        if (
          parts[idx].startsWith("-") ||
          /^[A-Za-z_][A-Za-z0-9_]*=/.test(parts[idx]) ||
          /^\d/.test(parts[idx])
        ) {
          idx++;
          continue;
        }
        break;
      }
      name = parts[idx++] ?? "";
      // Wrapper with no inner command (bare wrapper). `env`/`printenv` alone
      // dump the whole environment (secrets) into the agent's output — never
      // read-only, piped or not: a downstream stage like `cat`/`head` filters
      // nothing, so the dump reaches the agent in full (M3, F2). Other bare
      // wrappers (time/timeout/nohup…) change no file.
      if (!name) {
        const wrapperName = parts[0] ?? "";
        return wrapperName !== "env" && wrapperName !== "printenv";
      }
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
      const sub = `${parts[idx] ?? ""} ${parts[idx + 1] ?? ""}`.trim();
      return READONLY_GH_SUBCOMMANDS.has(sub);
    }
    if (name === "sort") {
      // sort without -o/--output writes only to stdout; -o/--output write the
      // sorted result back to a file in place (F5). Short flags cluster
      // (`-ro`, `-nro` — GNU sort treats them as `-r -o`), so any `-x…o`
      // cluster counts, mirroring the sed `-i` cluster check (B3).
      return !parts
        .slice(idx)
        .some(
          (p) =>
            /^-[^-]*o/.test(p) || p === "--output" || p.startsWith("--output"),
        );
    }
    if (name === "sed" || name === "yq") {
      // sed/yq without -i/--in-place is read-only stream editing (M2: yq -i
      // edits files in place exactly like sed -i)
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

/**
 * True when a wrapper command unit matches any `wrapperAllowlist` entry as a
 * complete token-sequence prefix: split the entry and the unit on whitespace;
 * every entry token — the last included — must equal the command token at the
 * same position (whole-token equality, never a substring/prefix inside a
 * longer token). An empty allowlist matches nothing (full floor).
 */
export function wrapperAllowlisted(
  unitText: string,
  wrapperAllowlist: readonly string[],
): boolean {
  const unitTokens = unitText.trim().split(/\s+/);
  for (const entry of wrapperAllowlist) {
    const entryTokens = entry.trim().split(/\s+/);
    if (entryTokens.length === 0 || entryTokens.length > unitTokens.length) {
      continue;
    }
    let matched = true;
    for (let i = 0; i < entryTokens.length; i++) {
      if (entryTokens[i] !== unitTokens[i]) {
        matched = false;
        break;
      }
    }
    if (matched) return true;
  }
  return false;
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
      return resolveWholeCommand(command, agentName, resolver);
    }
    const whole = resolveWholeCommand(command, agentName, resolver);
    if (whole.state === "deny") {
      return whole;
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

  // Fork read-only fast path: a chain whose every unit is provably
  // read-only (known read-only names, read-only git/gh subcommands, no
  // in-place flags, no write redirect) is allowed without the wrapper floor
  // — it changes nothing. Conservative: anything uncertain falls through to
  // the normal resolve + floor path.
  // The fast path is abandoned whenever any unit hits an explicit
  // `deny`/`ask` rule (config or session — an explicit rule carries
  // `matchedPattern`/session source), so a deliberate restriction can never
  // be short-circuited by the fast path (C4).
  if (
    isReadOnlyChain(commands, command) &&
    !commands.some((cmd) => {
      const resolved = resolver.resolve({
        kind: "tool",
        surface: "bash",
        input: { command: cmd.text },
        agentName,
      });
      return (
        resolved.state !== "allow" &&
        (resolved.source === "session" ||
          resolved.matchedPattern !== undefined)
      );
    })
  ) {
    return {
      state: "allow",
      toolName: "bash",
      source: "bash",
      origin: "builtin",
      command,
    };
  }

  const results = commands.map((cmd) => {
    const base = resolver.resolve({
      kind: "tool",
      surface: "bash",
      input: { command: cmd.text },
      agentName,
    });
    const floored =
      cmd.wrapperKind && base.state === "allow"
        ? wrapperAllowlisted(cmd.text, wrapperAllowlist)
          ? base
          : {
              ...base,
              state: "deny" as const,
              matchedPattern: WRAPPER_SENTINEL[cmd.wrapperKind],
              denialReason: WRAPPER_FLOOR_REASON,
            }
        : base;
    const result = cmd.context
      ? { ...floored, commandContext: cmd.context }
      : floored;
    return cmd.executedUnit === undefined
      ? result
      : { ...result, executedUnit: cmd.executedUnit };
  });
  return (
    pickMostRestrictive(results) ??
    resolveWholeCommand(command, agentName, resolver)
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

/** Resolve the whole command string as a single unit on the `bash` surface. */
function resolveWholeCommand(
  command: string,
  agentName: string | undefined,
  resolver: ScopedPermissionResolver,
): PermissionCheckResult {
  return resolver.resolve({
    kind: "tool",
    surface: "bash",
    input: { command },
    agentName,
  });
}
