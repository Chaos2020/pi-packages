import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock node:fs so realpathSync (used by canonicalizePath) is controllable.
const realpathSync = vi.hoisted(() =>
  vi.fn<(path: string) => string>((p) => p),
);
vi.mock("node:fs", () => ({
  realpathSync,
  default: { realpathSync },
}));

import { isGateDescriptor } from "#src/handlers/gates/descriptor";
import { describeToolPathWriteGate } from "#src/handlers/gates/tool-path-write";
import type { ToolCallContext } from "#src/handlers/gates/types";
import { pathFlavorForPlatform } from "#src/path/path-flavor";
import { PathNormalizer } from "#src/path-normalizer";

import {
  makeGateCheckResult as makeCheckResult,
  makeResolver,
} from "#test/helpers/gate-fixtures";

function makeTcc(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    toolName: "serena_replace_content",
    agentName: null,
    input: { relative_path: ".env" },
    toolCallId: "tc-1",
    cwd: "/test/project",
    ...overrides,
  };
}

const normalizer = new PathNormalizer(
  pathFlavorForPlatform(process.platform),
  "/test/project",
);

describe("describeToolPathWriteGate", () => {
  beforeEach(() => {
    realpathSync.mockReset();
    realpathSync.mockImplementation((p: string) => p);
  });

  it("returns null for non-serena-write tools", () => {
    const resolver = makeResolver();
    const result = describeToolPathWriteGate(
      makeTcc({ toolName: "serena_read_file" }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
    expect(resolver.resolve).not.toHaveBeenCalled();
  });

  it("denies writing a secret file (.env) through serena_replace_content", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describeToolPathWriteGate(makeTcc(), resolver, normalizer);
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path_write");
    expect(result?.decision.value).toContain(".env");
  });

  it("asks for writing AGENTS.md (key-file ask rule) through serena_replace_content", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "ask", matchedPattern: "*AGENTS.md" }),
    );
    const result = describeToolPathWriteGate(
      makeTcc({ input: { relative_path: "AGENTS.md" } }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path_write");
  });

  it("allows writing ordinary code through serena_replace_content", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "allow", matchedPattern: undefined }),
    );
    const result = describeToolPathWriteGate(
      makeTcc({ input: { relative_path: "src/foo.ts" } }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
  });

  it("conservatively asks for a whole-project replace_in_files scope", () => {
    const resolver = makeResolver();
    const result = describeToolPathWriteGate(
      makeTcc({
        toolName: "serena_replace_in_files",
        input: { needle: "x", repl: "y", mode: "literal" },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path_write");
    expect(result?.decision.value).toBe("<wildcard-scope>");
  });

  it("checks a literal replace_in_files scope against path_write", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "deny", matchedPattern: "*.env" }),
    );
    const result = describeToolPathWriteGate(
      makeTcc({
        toolName: "serena_replace_in_files",
        input: {
          needle: "x",
          repl: "y",
          mode: "literal",
          paths_include_glob: ".env",
        },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path_write");
  });

  it("gates serena_create_text_file writing a settings file", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "ask", matchedPattern: "settings.json" }),
    );
    const result = describeToolPathWriteGate(
      makeTcc({
        toolName: "serena_create_text_file",
        input: {
          relative_path: "/home/user/.pi/agent/settings.json",
          content: "{}",
        },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path_write");
  });
});

// pi exposes MCP servers through the single gateway tool `mcp`, called as
// mcp({ tool: "serena_...", args: {...} }) — serena write tools must still
// hit the path_write surface through that wrapper.
describe("describeToolPathWriteGate — mcp gateway shape", () => {
  it("asks when serena_create_text_file writes AGENTS.md through the gateway", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "ask", matchedPattern: "*AGENTS.md" }),
    );
    const result = describeToolPathWriteGate(
      makeTcc({
        toolName: "mcp",
        input: {
          tool: "serena_create_text_file",
          args: { relative_path: "AGENTS.md", content: "x" },
        },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path_write");
    expect(result.preCheck?.state).toBe("ask");
  });

  it("allows an ordinary file write through the gateway", () => {
    const resolver = makeResolver(
      makeCheckResult({ state: "allow", matchedPattern: undefined }),
    );
    const result = describeToolPathWriteGate(
      makeTcc({
        toolName: "mcp",
        input: {
          tool: "serena_create_text_file",
          args: { relative_path: "src/main.ts", content: "x" },
        },
      }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
  });

  it("conservatively asks for a wildcard replace_in_files scope through the gateway", () => {
    const resolver = makeResolver();
    const result = describeToolPathWriteGate(
      makeTcc({
        toolName: "mcp",
        input: {
          tool: "serena_replace_in_files",
          args: { needle: "x", repl: "y", paths_include_glob: "src/**/*.ts" },
        },
      }),
      resolver,
      normalizer,
    );
    expect(isGateDescriptor(result)).toBe(true);
    if (!isGateDescriptor(result)) throw new Error("expected descriptor");
    expect(result.surface).toBe("path_write");
    expect(result.decision.value).toBe("<wildcard-scope>");
  });

  it("returns null for a non-write serena tool through the gateway", () => {
    const resolver = makeResolver();
    const result = describeToolPathWriteGate(
      makeTcc({
        toolName: "mcp",
        input: {
          tool: "serena_get_symbols_overview",
          args: { relative_path: "src/main.ts" },
        },
      }),
      resolver,
      normalizer,
    );
    expect(result).toBeNull();
    expect(resolver.resolve).not.toHaveBeenCalled();
  });
});
