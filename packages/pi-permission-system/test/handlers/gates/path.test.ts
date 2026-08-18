import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock node:fs so realpathSync (used by canonicalizePath) is controllable.
// Default implementation is identity — lexical tests are unaffected.
// lstatSync (used by PathNormalizer.entryExists for the cwd-creation grant)
// defaults to "entry exists" so deny tests model existing secrets; the
// creation-grant tests flip it to ENOENT.
const realpathSync = vi.hoisted(() =>
  vi.fn<(path: string) => string>((p) => p),
);
const lstatSync = vi.hoisted(() =>
  vi.fn<(path: string) => object>(() => ({ isFile: () => true })),
);
vi.mock("node:fs", () => ({
  realpathSync,
  lstatSync,
  default: { realpathSync, lstatSync },
}));

import { AccessPath } from "#src/access-intent/access-path";
import type { GateDescriptor } from "#src/handlers/gates/descriptor";
import { isGateDescriptor } from "#src/handlers/gates/descriptor";
import { describePathGate } from "#src/handlers/gates/path";
import type { ToolCallContext } from "#src/handlers/gates/types";
import { pathFlavorForPlatform, posixPathFlavor } from "#src/path/path-flavor";
import { PathNormalizer } from "#src/path-normalizer";

import {
  makeGateCheckResult as makeCheckResult,
  makeResolver,
} from "#test/helpers/gate-fixtures";

// ── helpers ────────────────────────────────────────────────────────────────

// path.test.ts uses read-tool defaults; the shared makeTcc uses bash defaults.
function makeTcc(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    toolName: "read",
    agentName: null,
    input: { path: ".env" },
    toolCallId: "tc-1",
    cwd: "/test/project",
    ...overrides,
  };
}

// The gate reads the path normalizer (platform + cwd baked in) from the
// session; here it is bound to the makeTcc default cwd.
const normalizer = new PathNormalizer(
  pathFlavorForPlatform(process.platform),
  "/test/project",
);

// ── tests ──────────────────────────────────────────────────────────────────

describe("describePathGate", () => {
  beforeEach(() => {
    realpathSync.mockReset();
    realpathSync.mockImplementation((p: string) => p);
    lstatSync.mockReset();
    lstatSync.mockImplementation(() => ({ isFile: () => true }));
  });

  it("returns null for non-path-bearing tools", () => {
    const resolver = makeResolver();
    const result = describePathGate(
      makeTcc({ toolName: "bash", input: { command: "ls" } }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
    expect(resolver.resolve).not.toHaveBeenCalled();
  });

  it("returns null when tool has no extractable path", () => {
    const resolver = makeResolver();
    const result = describePathGate(
      makeTcc({ toolName: "read", input: {} }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
  });

  it("returns null when path check result is allow", () => {
    const resolver = makeResolver(makeCheckResult({ state: "allow" }));
    const result = describePathGate(makeTcc(), resolver, normalizer);
    expect(result).toBeNull();
  });

  it("returns null when matchedPattern is undefined (universal default)", () => {
    const resolver = makeResolver(
      makeCheckResult({
        state: "ask",
        matchedPattern: undefined,
        source: "special",
        origin: "builtin",
      }),
    );
    const result = describePathGate(makeTcc(), resolver, normalizer);
    expect(result).toBeNull();
  });

  it("returns GateDescriptor when matchedPattern is defined (explicit path rule)", () => {
    const resolver = makeResolver(
      makeCheckResult({
        state: "ask",
        matchedPattern: "*.env",
        source: "special",
        origin: "global",
      }),
    );
    const result = describePathGate(makeTcc(), resolver, normalizer);
    expect(result).not.toBeNull();
    expect(isGateDescriptor(result)).toBe(true);
  });

  it("returns GateDescriptor when path check result is deny", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(makeTcc(), resolver, normalizer);
    expect(result).not.toBeNull();
    expect(isGateDescriptor(result)).toBe(true);
    const desc = result as GateDescriptor;
    expect(desc.surface).toBe("path");
    expect(desc.preCheck?.state).toBe("deny");
  });

  it("returns GateDescriptor when path check result is ask", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "ask", matchedPattern: "*.env" }),
    );
    const result = describePathGate(makeTcc(), resolver, normalizer);
    expect(result).not.toBeNull();
    expect(isGateDescriptor(result)).toBe(true);
    const desc = result as GateDescriptor;
    expect(desc.surface).toBe("path");
    expect(desc.preCheck?.state).toBe("ask");
  });

  it("descriptor has correct session approval surface and pattern", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "ask", matchedPattern: "*" }),
    );
    const result = describePathGate(
      makeTcc({ input: { path: "/test/project/src/.env" } }),
      resolver,
      normalizer,
    ) as GateDescriptor;
    expect(result.sessionApproval).toBeDefined();
    expect(result.sessionApproval?.surface).toBe("path");
    expect(result.sessionApproval?.representativePattern).toBeDefined();
  });

  it("binds a current-directory file's session approval to the cwd subtree", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "ask", matchedPattern: "*" }),
    );
    const result = describePathGate(
      makeTcc({ input: { path: "index.html" }, cwd: "/test/project" }),
      resolver,
      normalizer,
    ) as GateDescriptor;
    expect(result.sessionApproval?.surface).toBe("path");
    expect(result.sessionApproval?.representativePattern).toBe(
      "/test/project/*",
    );
  });

  it("descriptor denialContext references the file path and tool name", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc(),
      resolver,
      normalizer,
    ) as GateDescriptor;
    expect(result.denialContext).toEqual({
      kind: "path",
      toolName: "read",
      pathValue: ".env",
      agentName: undefined,
    });
  });

  it("carries the child-fixed access facts on promptDetails (path surface)", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "ask", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc(),
      resolver,
      normalizer,
    ) as GateDescriptor;
    const accessPath = AccessPath.forPath(".env", {
      cwd: "/test/project",
      flavor: posixPathFlavor,
    });
    expect(result.promptDetails.accessIntent).toEqual({
      surface: "path",
      matchValues: accessPath.matchValues(),
      boundaryValue: accessPath.boundaryValue(),
    });
  });

  it("carries the raw file path on promptDetails so judge-side manualConfirmGlobs can match", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "ask", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc(),
      resolver,
      normalizer,
    ) as GateDescriptor;
    // Regression guard: the path gate already forwards `path`; keep it that
    // way so the command-safety-judge's manualConfirmGlobs keep firing.
    expect(result.promptDetails.path).toBe(".env");
  });

  it("descriptor decision uses surface 'path' and the file path as value", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc(),
      resolver,
      normalizer,
    ) as GateDescriptor;
    expect(result.decision.surface).toBe("path");
    expect(result.decision.value).toBe(".env");
  });

  it("resolves the path surface with an access-path intent and agent name", () => {
    const resolver = makeResolver(makeCheckResult({ state: "allow" }));
    describePathGate(makeTcc({ agentName: "my-agent" }), resolver, normalizer);
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "access-path",
      surface: "path",
      path: AccessPath.forPath(".env", {
        cwd: "/test/project",
        flavor: posixPathFlavor,
      }),
      agentName: "my-agent",
    });
  });

  it("emits an access-path whose matchValues include the symlink-resolved form (#486)", () => {
    // /test/project/.env is a symlink to /vault/secret.env.
    realpathSync.mockImplementation((p: string) =>
      p === "/test/project/.env" ? "/vault/secret.env" : p,
    );
    const resolver = makeResolver(makeCheckResult({ state: "allow" }));
    describePathGate(makeTcc(), resolver, normalizer);

    const intent = resolver.resolve.mock.lastCall?.[0];
    expect(intent?.kind).toBe("access-path");
    expect(intent?.kind === "access-path" && intent.path.matchValues()).toEqual(
      ["/test/project/.env", ".env", "/vault/secret.env"],
    );
  });
});

// cwd-creation grant ──────────────────────────────────────────────────────
//
// Creating a not-yet-existing entry inside the cwd is allowed by default:
// sensitive-name deny rules (`*.env`, `*.key`) glob absolute paths and would
// otherwise also catch brand-new project files. Existing entries and
// out-of-cwd targets keep their deny outcome.

describe("describePathGate — cwd creation grant", () => {
  beforeEach(() => {
    lstatSync.mockReset();
    lstatSync.mockImplementation(() => ({ isFile: () => true }));
  });

  it("returns null for a write to a not-yet-existing in-cwd .env matching a *.env deny", () => {
    lstatSync.mockImplementation(() => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    });
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({ toolName: "write", input: { path: "credentials.env" } }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
  });

  it("still denies an existing in-cwd .env (overwrite protection)", () => {
    // Default lstatSync — the entry exists.
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({ toolName: "write", input: { path: "credentials.env" } }),
      resolver,
      normalizer,
    );
    expect(result).not.toBeNull();
    expect(isGateDescriptor(result)).toBe(true);
  });

  it("still denies a not-yet-existing .env outside the cwd", () => {
    lstatSync.mockImplementation(() => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    });
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({ toolName: "write", input: { path: "/test/vault/new.env" } }),
      resolver,
      normalizer,
    );
    expect(result).not.toBeNull();
    expect(isGateDescriptor(result)).toBe(true);
  });

  it("still denies an existing in-cwd key file read via the gateway shape", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.key" }),
    );
    const result = describePathGate(
      makeTcc({
        toolName: "mcp",
        input: {
          tool: "serena_read_file",
          args: { relative_path: "smith.key" },
        },
      }),
      resolver,
      normalizer,
    );
    expect(result).not.toBeNull();
    expect(isGateDescriptor(result)).toBe(true);
  });
});

// Home-relative path characterization (#350) ──────────────────────────────
//
// The gate passes the raw path to the resolver; home expansion is handled
// downstream by normalizeInput. These tests lock in that the gate works
// correctly when the tool input contains a ~/... or $HOME/... path.

describe("describePathGate — home-relative paths", () => {
  it("passes raw ~/... path to resolver and builds descriptor on deny", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "~/.ssh/*" }),
    );
    const result = describePathGate(
      makeTcc({ input: { path: "~/.ssh/config" } }),
      resolver,
      normalizer,
    ) as GateDescriptor;

    expect(isGateDescriptor(result)).toBe(true);
    expect(result.preCheck?.state).toBe("deny");
    // Raw path preserved in denial context for display.
    expect(result.denialContext).toMatchObject({
      kind: "path",
      toolName: "read",
      pathValue: "~/.ssh/config",
    });
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "access-path",
      surface: "path",
      path: AccessPath.forPath("~/.ssh/config", {
        cwd: "/test/project",
        flavor: posixPathFlavor,
      }),
      agentName: undefined,
    });
  });

  it("passes raw $HOME/... path to resolver and builds descriptor on deny", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "$HOME/.ssh/*" }),
    );
    const result = describePathGate(
      makeTcc({ input: { path: "$HOME/.ssh/config" } }),
      resolver,
      normalizer,
    ) as GateDescriptor;

    expect(isGateDescriptor(result)).toBe(true);
    expect(result.preCheck?.state).toBe("deny");
    expect(result.denialContext).toMatchObject({
      kind: "path",
      pathValue: "$HOME/.ssh/config",
    });
  });

  it("returns null when home-relative path resolves to allow", () => {
    const resolver = makeResolver(makeCheckResult({ state: "allow" }));
    const result = describePathGate(
      makeTcc({ input: { path: "~/.ssh/config" } }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
  });
});

// Extension and MCP tools are now path-gated (#352) ──────────────────────────

describe("describePathGate — extension and MCP tools (#352)", () => {
  function extractorLookup(toolName: string, key: string) {
    return {
      get: (name: string) =>
        name === toolName
          ? (input: Record<string, unknown>) =>
              typeof input[key] === "string" ? input[key] : undefined
          : undefined,
    };
  }

  it("gates an extension tool that exposes input.path", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({ toolName: "my-ext", input: { path: ".env" } }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "access-path",
      surface: "path",
      path: AccessPath.forPath(".env", {
        cwd: "/test/project",
        flavor: posixPathFlavor,
      }),
      agentName: undefined,
    });
  });

  it("gates an MCP tool via arguments.path", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({ toolName: "mcp", input: { arguments: { path: ".env" } } }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "access-path",
      surface: "path",
      path: AccessPath.forPath(".env", {
        cwd: "/test/project",
        flavor: posixPathFlavor,
      }),
      agentName: undefined,
    });
  });

  it("gates a serena read tool via relative_path", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({
        toolName: "serena_read_file",
        input: { relative_path: ".env" },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "access-path",
      surface: "path",
      path: AccessPath.forPath(".env", {
        cwd: "/test/project",
        flavor: posixPathFlavor,
      }),
      agentName: undefined,
    });
  });

  it("gates a serena read tool via the gateway {tool,args} shape", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({
        toolName: "mcp",
        input: { tool: "serena_read_file", args: { relative_path: ".env" } },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path");
    expect(result.preCheck?.state).toBe("deny");
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "access-path",
      surface: "path",
      path: AccessPath.forPath(".env", {
        cwd: "/test/project",
        flavor: posixPathFlavor,
      }),
      agentName: undefined,
    });
  });

  it("reports the effective inner tool name in the gateway descriptor", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({
        toolName: "mcp",
        input: { tool: "serena_read_file", args: { relative_path: ".env" } },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    if (result.denialContext.kind !== "path") {
      throw new Error("expected path denial context");
    }
    expect(result.denialContext.toolName).toBe("serena_read_file");
    expect(result.promptDetails.toolName).toBe("serena_read_file");
  });

  it("denies a gateway read whose args ride as a JSON string targeting .env", () => {
    // The gateway accepts args as a JSON string; the gate must parse it or
    // the read path deny (*.env) is bypassed while the dispatch still reads.
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describePathGate(
      makeTcc({
        toolName: "mcp",
        input: {
          tool: "serena_read_file",
          args: '{"relative_path":".env"}',
        },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path");
    expect(result.preCheck?.state).toBe("deny");
    expect(result.decision.value).toContain(".env");
  });

  it("returns null for a gateway read whose string args fail JSON.parse", () => {
    // The gateway dispatch throws before the inner call executes.
    const resolver = makeResolver();
    const result = describePathGate(
      makeTcc({
        toolName: "mcp",
        input: { tool: "serena_read_file", args: "{oops" },
      }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
    expect(resolver.resolve).not.toHaveBeenCalled();
  });

  it("returns null for a gateway read of an allowed path", () => {
    const resolver = makeResolver(makeCheckResult({ state: "allow" }));
    const result = describePathGate(
      makeTcc({
        toolName: "mcp",
        input: {
          tool: "serena_read_file",
          args: { relative_path: "src/a.ts" },
        },
      }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
  });

  it("uses a registered extractor's path for a custom-shaped tool", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*" }),
    );
    describePathGate(
      makeTcc({ toolName: "ffgrep", input: { target: "/etc/passwd" } }),
      resolver,
      normalizer,
      extractorLookup("ffgrep", "target"),
    );
    expect(resolver.resolve).toHaveBeenCalledWith({
      kind: "access-path",
      surface: "path",
      path: AccessPath.forPath("/etc/passwd", {
        cwd: "/test/project",
        flavor: posixPathFlavor,
      }),
      agentName: undefined,
    });
  });

  it("returns null for an extension tool without a path", () => {
    const resolver = makeResolver();
    const result = describePathGate(
      makeTcc({ toolName: "my-ext", input: { other: true } }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
    expect(resolver.resolve).not.toHaveBeenCalled();
  });
});
