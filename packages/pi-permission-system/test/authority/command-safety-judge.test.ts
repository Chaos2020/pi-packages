import { describe, expect, test } from "vitest";
import {
  type CommandSafetyJudgeRawConfig,
  resolveCommandSafetyConfig,
} from "#src/authority/command-safety-config";
import { createCommandSafetyJudge } from "#src/authority/command-safety-judge";
import type {
  CompleteSimpleFn,
  ModelRegistryLike,
} from "#src/authority/command-safety-review";
import type { PromptPermissionDetails } from "#src/authority/permission-prompter";
import { describeToolGate } from "#src/handlers/gates/tool";
import type { ToolCallContext } from "#src/handlers/gates/types";
import { posixPathFlavor } from "#src/path/path-flavor";
import { PathNormalizer } from "#src/path-normalizer";
import {
  TOOL_INPUT_LOG_PREVIEW_MAX_LENGTH,
  TOOL_INPUT_PREVIEW_MAX_LENGTH,
  TOOL_TEXT_SUMMARY_MAX_LENGTH,
} from "#src/tool-input-preview";
import { ToolPreviewFormatter } from "#src/tool-preview-formatter";
import type { PermissionCheckResult } from "#src/types";

// command-safety-judge: allow-capable LLM authorizer (deny/suggest/allow/defer).

function makeConfig(
  overrides: Partial<CommandSafetyJudgeRawConfig> = {},
): NonNullable<ReturnType<typeof resolveCommandSafetyConfig>> {
  const resolved = resolveCommandSafetyConfig({
    provider: "zai",
    model: "glm-5.2",
    fallbackProvider: "deepseek",
    fallbackModel: "deepseek-v4-pro",
    reasoning: "max",
    timeoutMs: 1000,
    ...overrides,
  });
  if (!resolved) throw new Error("config unresolved");
  return resolved;
}

function makeDetails(
  overrides: Partial<PromptPermissionDetails> = {},
): PromptPermissionDetails {
  return {
    requestId: "req-1",
    source: "tool_call",
    agentName: null,
    message: "Allow bash command 'xargs wc -l'?",
    toolName: "bash",
    command: "xargs wc -l",
    surface: "bash",
    accessIntent: { surface: "bash", matchValues: ["xargs wc -l"] },
    ...overrides,
  } as unknown as PromptPermissionDetails;
}

function makeRegistry(modelId = "glm-5.2"): ModelRegistryLike {
  return {
    find: (_provider, id) =>
      id === modelId ? { id, providerId: _provider } : undefined,
    getApiKeyAndHeaders: async () => ({ ok: true, apiKey: "k" }),
  };
}

function makeLog() {
  const entries: unknown[] = [];
  return {
    entries,
    debug: (...a: unknown[]) => entries.push(["debug", ...a]),
    review: (...a: unknown[]) => entries.push(["review", ...a]),
  };
}

function completeWith(
  verdict: "deny" | "suggest" | "allow" | "defer",
  fields: Record<string, string> = {},
): CompleteSimpleFn {
  return async () => ({
    content: [{ type: "toolCall", arguments: { verdict, ...fields } }],
  });
}

describe("command-safety-judge authorizer", () => {
  test("defers without calling the LLM when path matches a manual-confirm glob", async () => {
    let called = false;
    const complete = (async () => {
      called = true;
      return { content: [] };
    }) as unknown as CompleteSimpleFn;
    const judge = createCommandSafetyJudge({
      getConfig: () =>
        makeConfig({ manualConfirmGlobs: ["~/.pi/agent/settings.json"] }),
      getRegistry: () => makeRegistry(),
      completeSimple: complete,
      getCwd: () => "/cwd",
    });
    const result = await judge(
      makeDetails({ path: "/home/lxx/.pi/agent/settings.json" }),
      {} as never,
      makeLog(),
    );
    expect(result.kind).toBe("defer");
    expect(called).toBe(false);
  });

  test("edit-tool ask from describeToolGate carries its path: manualConfirmGlobs hit → defer, LLM never called", async () => {
    // Regression (#manual-confirm-path): the tool gate builds the ask's
    // promptDetails; the judge matches manualConfirmGlobs against
    // details.path. Before the fix, describeToolGate never set `path`, so an
    // edit on a whitelisted config path fell through to the LLM (and its
    // noise-averse auto-approve) instead of deferring to the human.
    const formatter = new ToolPreviewFormatter({
      toolInputPreviewMaxLength: TOOL_INPUT_PREVIEW_MAX_LENGTH,
      toolTextSummaryMaxLength: TOOL_TEXT_SUMMARY_MAX_LENGTH,
      toolInputLogPreviewMaxLength: TOOL_INPUT_LOG_PREVIEW_MAX_LENGTH,
    });
    const tcc: ToolCallContext = {
      toolName: "edit",
      agentName: null,
      input: { path: "/home/lxx/.pi/agent/AGENTS.md" },
      toolCallId: "tc-edit-1",
      cwd: "/test/project",
    };
    const check: PermissionCheckResult = {
      state: "ask",
      toolName: "edit",
      source: "tool",
      origin: "builtin",
      matchedPattern: "*",
    };
    const normalizer = new PathNormalizer(posixPathFlavor, "/test/project");
    const accessPath = normalizer.forPath("/home/lxx/.pi/agent/AGENTS.md");
    const desc = describeToolGate(tcc, check, formatter, accessPath);

    let called = false;
    const complete = (async () => {
      called = true;
      return { content: [] };
    }) as unknown as CompleteSimpleFn;
    const judge = createCommandSafetyJudge({
      getConfig: () =>
        makeConfig({ manualConfirmGlobs: ["/home/lxx/.pi/agent/AGENTS.md"] }),
      getRegistry: () => makeRegistry(),
      completeSimple: complete,
      getCwd: () => "/test/project",
    });
    const log = makeLog();
    const verdict = await judge(
      { ...desc.promptDetails, requestId: "req-gate-1" } as PromptPermissionDetails,
      {} as never,
      log,
    );
    expect(verdict.kind).toBe("defer");
    expect(called).toBe(false);
    expect(
      log.entries.some(
        (e) =>
          (e as unknown[])[1] === "command_safety_judge.decision" &&
          (
            (e as unknown[])[2] as { deferReason?: string }
          ).deferReason === "manual-confirm-path",
      ),
    ).toBe(true);
  });

  test("defers when no config (inert / opt-in)", async () => {
    const judge = createCommandSafetyJudge({
      getConfig: () => undefined,
      getRegistry: makeRegistry,
      completeSimple: completeWith("allow"),
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict).toEqual({ kind: "defer" });
  });

  test("allow verdict passes through", async () => {
    const judge = createCommandSafetyJudge({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      completeSimple: completeWith("allow"),
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict).toEqual({ kind: "allow" });
  });

  test("deny verdict carries the reason", async () => {
    const judge = createCommandSafetyJudge({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      completeSimple: completeWith("deny", { reason: "destructive rm -rf" }),
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict).toEqual({ kind: "deny", reason: "destructive rm -rf" });
  });

  test("suggest verdict hands back a no-auth alternative", async () => {
    const judge = createCommandSafetyJudge({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      completeSimple: completeWith("suggest", {
        alternative: "use grep -r pattern dir instead",
      }),
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict).toEqual({
      kind: "suggest",
      alternative: "use grep -r pattern dir instead",
    });
  });

  test("defer verdict carries a risk note", async () => {
    const judge = createCommandSafetyJudge({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      completeSimple: completeWith("defer", {
        risk: "modifies a config file",
        suggestion: "review the diff first",
      }),
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict.kind).toBe("defer");
    expect((verdict as { note?: string }).note).toContain("config file");
    expect((verdict as { note?: string }).note).toContain("建议");
  });

  test("falls back to the secondary model when primary is unregistered", async () => {
    let calls = 0;
    const complete: CompleteSimpleFn = async () => {
      calls++;
      return {
        content: [{ type: "toolCall", arguments: { verdict: "allow" } }],
      };
    };
    // registry only knows the fallback model
    const judge = createCommandSafetyJudge({
      getConfig: () => makeConfig(),
      getRegistry: () => makeRegistry("deepseek-v4-pro"),
      completeSimple: complete,
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict).toEqual({ kind: "allow" });
    expect(calls).toBe(1);
  });

  test("defers when both models are unregistered", async () => {
    const judge = createCommandSafetyJudge({
      getConfig: () => makeConfig(),
      getRegistry: () => ({
        find: () => undefined,
        getApiKeyAndHeaders: async () => ({ ok: false, error: "no" }),
      }),
      completeSimple: completeWith("allow"),
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict).toEqual({ kind: "defer" });
  });

  test("fail-safe: a thrown completeSimple defers", async () => {
    const judge = createCommandSafetyJudge({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      completeSimple: async () => {
        throw new Error("network down");
      },
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict).toEqual({ kind: "defer" });
  });

  test("fail-safe: an unrecognized verdict defers", async () => {
    const judge = createCommandSafetyJudge({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      completeSimple: async () => ({
        content: [{ type: "toolCall", arguments: { verdict: "maybe" } }],
      }),
    });
    const verdict = await judge(makeDetails(), makeQuery(), makeLog() as any);
    expect(verdict).toEqual({ kind: "defer" });
  });
});

describe("resolveCommandSafetyConfig defaults", () => {
  test("applies glm-5.2 + deepseek-v4-pro fallback + max reasoning", () => {
    const cfg = resolveCommandSafetyConfig({});
    expect(cfg?.provider).toBe("zai");
    expect(cfg?.model).toBe("glm-5.2");
    expect(cfg?.fallbackProvider).toBe("deepseek");
    expect(cfg?.fallbackModel).toBe("deepseek-v4-pro");
    expect(cfg?.reasoning).toBe("max");
  });

  test("undefined raw → undefined (inert)", () => {
    expect(resolveCommandSafetyConfig(undefined)).toBeUndefined();
  });
});

function makeQuery() {
  return {
    checkPermission: () => ({
      state: "ask" as const,
      toolName: "bash",
      source: "special" as const,
      origin: "global" as const,
    }),
    getToolPermission: () => "ask" as const,
  };
}
