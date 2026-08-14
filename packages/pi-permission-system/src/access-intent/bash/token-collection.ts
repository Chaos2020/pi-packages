import { basename } from "node:path";
import {
  ARG_NODE_TYPES,
  resolveNodeText,
  SKIP_SUBTREE_TYPES,
} from "#src/access-intent/bash/node-text";
import type { TSNode } from "#src/access-intent/bash/parser";

// ── Public surface ─────────────────────────────────────────────────────────

/**
 * The access direction of a bash path token, used to route the token to the
 * right protection layer:
 *
 * - `"read"`  — the path is actually opened/read (file-read commands, script
 *   execution, redirect input). Checked against the information-security
 *   `path` surface (deny secret reads).
 * - `"write"` — the path is modified/moved/removed/overwritten (write
 *   commands, redirect output). Checked against the integrity-protection
 *   `path_write` surface (protect key files and secrets from damage).
 * - `"arg"`   — a business argument passed to a script/program; the shell
 *   does not treat it as a filesystem target, so neither path layer applies.
 *
 * Layering read vs write keeps information security and file integrity as
 * two independent filters: `cat ~/.env` (read) triggers the secret rule
 * while `sys-backup.sh is-tracked "$HOME/.env"` (arg) does not, and
 * `echo x > ~/.bashrc` (write) triggers the key-file rule while
 * `cat ~/.bashrc` (read) stays allowed.
 */
export type BashTokenRole = "read" | "write" | "arg";

/** A bash path-candidate token paired with its access direction. */
export interface BashTokenRef {
  readonly text: string;
  readonly role: BashTokenRole;
}

/**
 * Commands whose positional arguments are file-read targets: the argument
 * path is opened and read, so the information-security `path` surface
 * applies. Flags and inline patterns are still filtered downstream by the
 * shape classifiers.
 */
const FILE_READ_COMMANDS: ReadonlySet<string> = new Set([
  "cat",
  "tac",
  "head",
  "tail",
  "less",
  "more",
  "sed",
  "awk",
  "gawk",
  "nawk",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "vim",
  "vi",
  "nano",
  "diff",
  "patch",
  "wc",
  "sort",
  "uniq",
  "cut",
  "stat",
  "file",
  "tar",
  "unzip",
  "gunzip",
  "gzip",
  "bzip2",
  "xz",
  "openssl",
  "gpg",
  "ssh-keygen",
  "find",
  "rsync",
  "scp",
  "cd",
  "curl",
  "wget",
]);

/**
 * Commands whose positional arguments are write/delete targets: the argument
 * path is modified, moved, removed, or overwritten, so the integrity
 * `path_write` surface applies (protect key files, secrets, and configs from
 * damage).
 */
const FILE_WRITE_COMMANDS: ReadonlySet<string> = new Set([
  "cp",
  "mv",
  "rm",
  "tee",
  "dd",
  "shred",
  "install",
  "ln",
  "touch",
  "mkdir",
  "chmod",
  "chown",
  "truncate",
]);

/**
 * Commands whose first positional argument is a script/program to execute
 * (the shell reads that file to run it) and whose remaining positional
 * arguments are business arguments passed to the script — never filesystem
 * targets from the shell's perspective. Only the script argument is a read
 * target.
 */
const SCRIPT_EXEC_COMMANDS: ReadonlySet<string> = new Set([
  "bash",
  "sh",
  "zsh",
  "dash",
  "ksh",
  ".",
  "source",
  "python",
  "python2",
  "python3",
  "node",
  "deno",
  "bun",
  "ruby",
  "perl",
  "php",
  "npx",
]);

/**
 * Recursively visit the AST and collect resolved text of nodes that
 * represent command arguments or redirect destinations.
 *
 * Skips `heredoc_body`, `heredoc_end`, and `comment` subtrees entirely.
 *
 * For commands in `PATTERN_FIRST_COMMANDS`, uses position-based
 * argument skipping to avoid collecting inline patterns/scripts
 * as path candidates. For all other commands, collects all
 * arguments generically.
 */
export function collectPathCandidateTokens(node: TSNode): BashTokenRef[] {
  if (SKIP_SUBTREE_TYPES.has(node.type)) return [];
  if (node.type === "command") return collectCommandTokens(node);
  if (node.type === "file_redirect") return collectRedirectTokens(node);

  const tokens: BashTokenRef[] = [];
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) tokens.push(...collectPathCandidateTokens(child));
  }
  return tokens;
}

/**
 * Select the collection strategy for a `command` node: pattern-first
 * commands use `collectPatternCommandTokens`; all others use
 * `collectGenericCommandTokens`.
 */
export function collectCommandTokens(node: TSNode): BashTokenRef[] {
  const commandName = extractCommandName(node);
  const config = commandName
    ? PATTERN_FIRST_COMMANDS.get(commandName)
    : undefined;
  const tokens = config
    ? collectPatternCommandTokens(node, config)
    : collectGenericCommandTokens(node);
  return [...tokens, ...collectEmbeddedOptionValues(node)];
}

/**
 * Collect redirect-destination tokens from a `file_redirect` node.
 */
export function collectRedirectTokens(node: TSNode): BashTokenRef[] {
  const tokens: BashTokenRef[] = [];
  let write = false;
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === "file_descriptor") continue;
    if (!child.isNamed) {
      // Anonymous operator token: `<` is input (read); `>`/`>>`/`2>`/`&>`
      // are output (write). A here-string `<<<` contains no `>` and stays read.
      if (child.text.includes(">")) write = true;
      continue;
    }
    if (ARG_NODE_TYPES.has(child.type)) {
      tokens.push({
        text: resolveNodeText(child),
        role: write ? "write" : "read",
      });
    }
  }
  return tokens;
}

/**
 * Extract the command name from a `command` node.
 * Returns the basename (e.g. `/usr/bin/sed` → `sed`), or undefined
 * if the command name cannot be determined (e.g. variable expansion).
 */
export function extractCommandName(node: TSNode): string | undefined {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === "command_name") {
      const text = resolveNodeText(child);
      return text ? basename(text) : undefined;
    }
  }
  return undefined;
}

// ── Private helpers and config ─────────────────────────────────────────────

/**
 * A long or short option carrying its value inline: one or two leading dashes,
 * a name containing no `=` or whitespace, then `=` and a non-empty value.
 * Only the first `=` separates, so `--opt=/tmp/a=b` yields `/tmp/a=b`.
 */
const OPTION_VALUE_PATTERN = /^-{1,2}[^=\s]+=(.+)$/;

/**
 * The values embedded in this command's `--opt=value` argument tokens.
 *
 * Read straight from the argument nodes rather than from the collected token
 * list, because a pattern-first command's collector classifies a flag and never
 * emits it — so `grep --file=/tmp/patterns` would otherwise lose the path.
 *
 * This is token *preprocessing*, not classification: the extracted value is
 * handed to the ordinary shape classifiers and existence probe, so
 * `--file=/tmp/patterns` reaches the path surfaces while `--format=json`
 * yields a bare `json` that names nothing and is dropped. Keeping the split
 * here is what lets the projection see option-embedded paths without per-command
 * option tables (ADR 0009, #645).
 */
function collectEmbeddedOptionValues(node: TSNode): BashTokenRef[] {
  const values: BashTokenRef[] = [];
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === "command_name" || child.type === "variable_assignment")
      continue;
    if (!ARG_NODE_TYPES.has(child.type)) continue;

    const value = OPTION_VALUE_PATTERN.exec(resolveNodeText(child))?.[1];
    if (value !== undefined) values.push({ text: value, role: "arg" });
  }
  return values;
}

interface PatternCommandConfig {
  /** Flags that consume the next argument as a non-path value (pattern, separator, etc.) */
  readonly argConsumingFlags: ReadonlySet<string>;
  /** Flags that consume the next argument as a file path */
  readonly fileConsumingFlags: ReadonlySet<string>;
  /**
   * Number of leading positional arguments that are patterns/scripts, not paths.
   * Default: 1 (covers sed, awk, grep, rg).
   * sd uses 2 (FIND and REPLACE_WITH are both non-path positionals).
   */
  readonly patternPositionals?: number;
}

/**
 * Commands whose first N positional arguments are inline patterns/scripts,
 * not filesystem paths. The map stores per-command flag configuration so
 * the walker can correctly identify which arguments are consumed by flags
 * vs. which are positional.
 */
const PATTERN_FIRST_COMMANDS: ReadonlyMap<string, PatternCommandConfig> =
  new Map([
    [
      "sed",
      {
        argConsumingFlags: new Set(["-e", "-i"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "awk",
      {
        argConsumingFlags: new Set(["-e", "-F", "-v"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "gawk",
      {
        argConsumingFlags: new Set(["-e", "-F", "-v"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "nawk",
      {
        argConsumingFlags: new Set(["-e", "-F", "-v"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "grep",
      {
        argConsumingFlags: new Set(["-e", "-A", "-B", "-C", "-m"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "egrep",
      {
        argConsumingFlags: new Set(["-e", "-A", "-B", "-C", "-m"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "fgrep",
      {
        argConsumingFlags: new Set(["-e", "-A", "-B", "-C", "-m"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "rg",
      {
        argConsumingFlags: new Set([
          "-e",
          "-A",
          "-B",
          "-C",
          "-m",
          "-g",
          "-t",
          "-T",
          "-j",
          "-M",
          "-r",
          "-E",
        ]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "sd",
      {
        argConsumingFlags: new Set(["-n", "-f"]),
        fileConsumingFlags: new Set([]),
        patternPositionals: 2,
      },
    ],
  ]);

/**
 * Describes what the walker should do when it encounters a flag word inside
 * a pattern-first command.  Using a discriminated union lets the `switch` in
 * `collectPatternCommandTokens` narrow `nextArgAction` without a non-null
 * assertion (which would trigger the Biome/ESLint assertion conflict).
 */
type PatternCommandFlagDirective =
  | { kind: "end-of-flags" }
  | { kind: "regular-flag" }
  | {
      kind: "consume-arg";
      nextArgAction: "skip" | "extract";
      setsExplicitScript: boolean;
    };

/**
 * Classify a flag word from a pattern-first command into a directive that
 * tells the walker how to handle the flag and its following argument.
 */
function classifyPatternCommandFlag(
  text: string,
  config: PatternCommandConfig,
): PatternCommandFlagDirective {
  if (text === "--") return { kind: "end-of-flags" };
  if (config.argConsumingFlags.has(text)) {
    return {
      kind: "consume-arg",
      nextArgAction: "skip",
      setsExplicitScript: text === "-e" || text === "-f",
    };
  }
  if (config.fileConsumingFlags.has(text)) {
    return {
      kind: "consume-arg",
      nextArgAction: "extract",
      setsExplicitScript: true,
    };
  }
  return { kind: "regular-flag" };
}

/**
 * Collect path-candidate tokens from a command known to have
 * pattern/script arguments in leading positional slots.
 *
 * Uses position-based skipping: the first N positional arguments
 * (where N = patternPositionals, default 1) are assumed to be
 * inline patterns/scripts and are skipped. Remaining positional
 * arguments are collected as path candidates.
 *
 * Flags listed in `argConsumingFlags` consume the next argument
 * (skipped). Flags in `fileConsumingFlags` consume the next
 * argument as a file path (collected). The flags `-e` and `-f`
 * additionally signal that an explicit script was provided via
 * flag, so no inline positional script is expected.
 */
function collectPatternCommandTokens(
  node: TSNode,
  config: PatternCommandConfig,
): BashTokenRef[] {
  const patternPositionals = config.patternPositionals ?? 1;
  let hasExplicitScript = false;
  let positionalsSeen = 0;
  let nextArgAction: "skip" | "extract" | null = null;
  let pastEndOfFlags = false;
  const tokens: BashTokenRef[] = [];

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    // Skip command_name and variable_assignment nodes.
    if (child.type === "command_name" || child.type === "variable_assignment")
      continue;

    // Only process argument-like nodes; recurse into others
    // (e.g. command_substitution) for nested commands.
    if (!ARG_NODE_TYPES.has(child.type)) {
      tokens.push(...collectPathCandidateTokens(child));
      continue;
    }

    const text = resolveNodeText(child);

    // Handle consumed argument from previous flag.
    if (nextArgAction === "skip") {
      nextArgAction = null;
      continue;
    }
    if (nextArgAction === "extract") {
      tokens.push({ text, role: "read" });
      nextArgAction = null;
      continue;
    }

    // Flag detection (only before "--" end-of-flags marker).
    if (
      !pastEndOfFlags &&
      child.type === "word" &&
      text.startsWith("-") &&
      text.length > 1
    ) {
      const directive = classifyPatternCommandFlag(text, config);
      switch (directive.kind) {
        case "end-of-flags":
          pastEndOfFlags = true;
          break;
        case "consume-arg":
          nextArgAction = directive.nextArgAction;
          if (directive.setsExplicitScript) hasExplicitScript = true;
          break;
        case "regular-flag":
          break;
      }
      continue;
    }

    // Positional argument.
    if (!hasExplicitScript && positionalsSeen < patternPositionals) {
      positionalsSeen++;
      continue; // Skip: this is an inline pattern/script.
    }

    // File argument — collect as a read target.
    tokens.push({ text, role: "read" });
  }

  return tokens;
}

/**
 * Collect all argument tokens from a generic (non-pattern-first) command node,
 * tagging each with its access direction, skipping the command name and
 * variable assignments.
 *
 * The role is derived from the command name: file-read commands (cat/grep/…)
 * get `read`, write commands (cp/rm/tee/…) get `write`, script executors
 * (bash/python/…) get script-first handling, `git` gets rev-path handling,
 * and everything else is a business argument (`arg`).
 */
function collectGenericCommandTokens(node: TSNode): BashTokenRef[] {
  const commandName = extractCommandName(node);
  if (commandName !== undefined && SCRIPT_EXEC_COMMANDS.has(commandName)) {
    return collectScriptExecTokens(node);
  }
  if (commandName === "git") {
    return collectGitTokens(node);
  }
  return collectPlainGenericTokens(node, argRoleForCommand(commandName));
}

/**
 * The read/write role for a generic command's positional arguments, or
 * `"arg"` for unknown commands (business arguments are not filesystem
 * targets from the shell's perspective).
 */
function argRoleForCommand(commandName: string | undefined): BashTokenRole {
  if (commandName === undefined) return "arg";
  if (FILE_READ_COMMANDS.has(commandName)) return "read";
  if (FILE_WRITE_COMMANDS.has(commandName)) return "write";
  return "arg";
}

/**
 * Collect argument tokens for a command whose positional arguments all share
 * one role (read, write, or business argument).
 */
function collectPlainGenericTokens(
  node: TSNode,
  role: BashTokenRole,
): BashTokenRef[] {
  const tokens: BashTokenRef[] = [];
  let seenCommandName = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === "command_name") {
      seenCommandName = true;
      continue;
    }
    // Skip variable_assignment nodes (FOO=/bar)
    if (child.type === "variable_assignment") continue;

    // If there was no explicit command_name node, the first word-like
    // child is the command name itself — skip it.
    if (!seenCommandName && ARG_NODE_TYPES.has(child.type)) {
      seenCommandName = true;
      continue;
    }

    // Argument nodes: resolve their text and collect with the role.
    if (ARG_NODE_TYPES.has(child.type)) {
      tokens.push({ text: resolveNodeText(child), role });
      continue;
    }

    // Recurse into other children (e.g. command_substitution nested in args)
    tokens.push(...collectPathCandidateTokens(child));
  }

  return tokens;
}

/**
 * Collect arguments for a script executor (`bash script.sh a b`): the first
 * non-flag positional is the script path (`read` — the shell reads it to run
 * it), and every following positional is a business argument (`arg`) that is
 * handed to the script, not opened by the shell.
 */
function collectScriptExecTokens(node: TSNode): BashTokenRef[] {
  const tokens: BashTokenRef[] = [];
  let seenCommandName = false;
  let scriptSeen = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === "command_name") {
      seenCommandName = true;
      continue;
    }
    if (child.type === "variable_assignment") continue;

    if (!seenCommandName && ARG_NODE_TYPES.has(child.type)) {
      seenCommandName = true;
      continue;
    }

    if (ARG_NODE_TYPES.has(child.type)) {
      const text = resolveNodeText(child);
      if (!scriptSeen && !(text.startsWith("-") && text.length > 1)) {
        scriptSeen = true;
        tokens.push({ text, role: "read" });
      } else {
        tokens.push({ text, role: "arg" });
      }
      continue;
    }

    tokens.push(...collectPathCandidateTokens(child));
  }

  return tokens;
}

/**
 * Collect arguments for `git`: a `rev:path` token (`HEAD:.env`) addresses an
 * object in the repo and is read (`read`); a plain path token (`check-ignore
 * path`) is a business argument (`arg`) that git compares without opening.
 */
function collectGitTokens(node: TSNode): BashTokenRef[] {
  const tokens: BashTokenRef[] = [];
  let seenCommandName = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === "command_name") {
      seenCommandName = true;
      continue;
    }
    if (child.type === "variable_assignment") continue;

    if (!seenCommandName && ARG_NODE_TYPES.has(child.type)) {
      seenCommandName = true;
      continue;
    }

    if (ARG_NODE_TYPES.has(child.type)) {
      const text = resolveNodeText(child);
      tokens.push({ text, role: text.includes(":") ? "read" : "arg" });
      continue;
    }

    tokens.push(...collectPathCandidateTokens(child));
  }

  return tokens;
}
