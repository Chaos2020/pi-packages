import { describe, expect, test } from "vitest";
import type { ModelJudgeConfig } from "#src/model-judge/config-schema";
import { createTypoReviewer } from "#src/model-judge/typo-reviewer";
import type {
  CompleteFn,
  ModelRegistryLike,
} from "#src/model-judge/model-review";
import type { PromptPermissionDetails } from "#src/authority/permission-prompter";

// Feature 2: built-in model-judge authorizer — deny-first typo-path review.

function makeConfig(overrides: Partial<ModelJudgeConfig> = {}): ModelJudgeConfig {
  return {
    provider: "test-provider",
    model: "light",
    instructions: "You judge paths.",
    typoPatterns: ["/pi-permission-system/packages/pi-permission-system"],
    timeoutMs: 1000,
    ...overrides,
  };
}

function makeDetails(path: string): PromptPermissionDetails {
  return {
    requestId: "req-1",
    surface: "external_directory",
    path,
    accessIntent: { surface: "external_directory", matchValues: [path] },
  } as unknown as PromptPermissionDetails;
}

function makeRegistry(): ModelRegistryLike {
  return {
    find: () => ({ id: "light" }),
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

function completeWith(verdict: "deny" | "defer", reason?: string): CompleteFn {
  return async () => ({
    content: [{ type: "toolCall", arguments: { verdict, reason } }],
  });
}

describe("feature 2: model-judge authorizer", () => {
  test("typo path -> deny with teaching reason", async () => {
    const log = makeLog();
    const reviewer = createTypoReviewer({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      complete: completeWith("deny", "correct location is /pi-packages"),
    });
    const verdict = await reviewer(
      makeDetails("/pi-permission-system/packages/pi-permission-system/x.ts"),
      {} as never,
      log as never,
    );
    expect(verdict.kind).toBe("deny");
    if (verdict.kind === "deny") {
      expect(verdict.reason).toContain("/pi-packages");
    }
    expect(
      log.entries.some((e) =>
        Array.isArray(e) && e[0] === "review" && String(e[1]).includes("model_judge.decision"),
      ),
    ).toBe(true);
  });

  test("non-typo path -> defer (no model call)", async () => {
    let modelCalled = false;
    const log = makeLog();
    const reviewer = createTypoReviewer({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      complete: () => {
        modelCalled = true;
        return completeWith("deny")({} as never, {} as never);
      },
    });
    const verdict = await reviewer(
      makeDetails("/home/user/src/app.ts"),
      {} as never,
      log as never,
    );
    expect(verdict.kind).toBe("defer");
    expect(modelCalled).toBe(false);
  });

  test("no config -> defer", async () => {
    const reviewer = createTypoReviewer({
      getConfig: () => undefined,
      getRegistry: makeRegistry,
      complete: completeWith("deny"),
    });
    const verdict = await reviewer(
      makeDetails("/pi-permission-system/packages/pi-permission-system/x.ts"),
      {} as never,
      makeLog() as never,
    );
    expect(verdict.kind).toBe("defer");
  });

  test("non-external_directory surface -> defer", async () => {
    const reviewer = createTypoReviewer({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      complete: completeWith("deny"),
    });
    const details = makeDetails("/pi-permission-system/packages/pi-permission-system/x.ts");
    details.surface = "bash";
    (details.accessIntent as { surface: string }).surface = "bash";
    const verdict = await reviewer(details as never, {} as never, makeLog() as never);
    expect(verdict.kind).toBe("defer");
  });

  test("fail-safe: complete throws -> defer", async () => {
    const reviewer = createTypoReviewer({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      complete: async () => {
        throw new Error("model down");
      },
    });
    const verdict = await reviewer(
      makeDetails("/pi-permission-system/packages/pi-permission-system/x.ts"),
      {} as never,
      makeLog() as never,
    );
    expect(verdict.kind).toBe("defer");
  });

  test("fail-safe: model-unresolved (find returns undefined) -> defer", async () => {
    const reviewer = createTypoReviewer({
      getConfig: () => makeConfig(),
      getRegistry: () => ({
        find: () => undefined,
        getApiKeyAndHeaders: async () => ({ ok: true }),
      }),
      complete: completeWith("deny"),
    });
    const verdict = await reviewer(
      makeDetails("/pi-permission-system/packages/pi-permission-system/x.ts"),
      {} as never,
      makeLog() as never,
    );
    expect(verdict.kind).toBe("defer");
  });

  test("fail-safe: auth-failed (getApiKeyAndHeaders !ok) -> defer", async () => {
    const reviewer = createTypoReviewer({
      getConfig: () => makeConfig(),
      getRegistry: () => ({
        find: () => ({ id: "light" }),
        getApiKeyAndHeaders: async () => ({ ok: false, error: "no key" }),
      }),
      complete: completeWith("deny"),
    });
    const verdict = await reviewer(
      makeDetails("/pi-permission-system/packages/pi-permission-system/x.ts"),
      {} as never,
      makeLog() as never,
    );
    expect(verdict.kind).toBe("defer");
  });

  test("fail-safe: non-deny verdict -> defer", async () => {
    const reviewer = createTypoReviewer({
      getConfig: () => makeConfig(),
      getRegistry: makeRegistry,
      complete: completeWith("defer"),
    });
    const verdict = await reviewer(
      makeDetails("/pi-permission-system/packages/pi-permission-system/x.ts"),
      {} as never,
      makeLog() as never,
    );
    expect(verdict.kind).toBe("defer");
  });
});
