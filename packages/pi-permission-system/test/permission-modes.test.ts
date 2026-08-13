import { describe, expect, it } from "vitest";
import { applyMode, isMutationTool } from "#src/permission-modes";
import { makeCheckResult } from "#test/helpers/handler-fixtures";
import {
  makeDescriptor,
  makeGateRunner,
} from "#test/helpers/gate-fixtures";

// Feature 6: Claude-style permission modes (default/acceptEdits/plan/bypass).

describe("feature 6: permission modes — applyMode", () => {
  it("acceptEdits auto-allows file-mutation asks", () => {
    expect(applyMode("ask", "edit", "acceptEdits")).toBe("allow");
    expect(applyMode("ask", "write", "acceptEdits")).toBe("allow");
    expect(applyMode("ask", "bash", "acceptEdits")).toBe("allow");
  });

  it("acceptEdits leaves non-mutation asks as ask", () => {
    expect(applyMode("ask", "read", "acceptEdits")).toBe("ask");
    expect(applyMode("ask", "grep", "acceptEdits")).toBe("ask");
  });

  it("plan auto-denies file-mutation asks, leaves reads", () => {
    expect(applyMode("ask", "edit", "plan")).toBe("deny");
    expect(applyMode("ask", "bash", "plan")).toBe("deny");
    expect(applyMode("ask", "read", "plan")).toBe("ask");
  });

  it("bypassPermissions auto-allows every ask", () => {
    expect(applyMode("ask", "edit", "bypassPermissions")).toBe("allow");
    expect(applyMode("ask", "read", "bypassPermissions")).toBe("allow");
  });

  it("default and non-ask states are never transformed", () => {
    expect(applyMode("ask", "edit", "default")).toBe("ask");
    expect(applyMode("deny", "edit", "acceptEdits")).toBe("deny");
    expect(applyMode("deny", "edit", "bypassPermissions")).toBe("deny");
    expect(applyMode("allow", "edit", "plan")).toBe("allow");
  });

  it("isMutationTool covers edit/write/bash", () => {
    expect(isMutationTool("edit")).toBe(true);
    expect(isMutationTool("bash")).toBe(true);
    expect(isMutationTool("read")).toBe(false);
  });
});

describe("feature 6: permission modes — gate integration", () => {
  it("acceptEdits auto-allows an edit ask (no prompt, no block)", async () => {
    const { runner, deps } = makeGateRunner({
      resolveResult: makeCheckResult({ state: "ask", matchedPattern: "*" }),
      mode: "acceptEdits",
    });
    const result = await runner.run(makeDescriptor({ surface: "edit" }), null, "tc-1");
    expect(result).toEqual({ action: "allow" });
    expect(deps.escalate).not.toHaveBeenCalled();
  });

  it("plan blocks an edit ask (auto-deny mutation)", async () => {
    const { runner, deps } = makeGateRunner({
      resolveResult: makeCheckResult({ state: "ask", matchedPattern: "*" }),
      mode: "plan",
    });
    const result = await runner.run(makeDescriptor({ surface: "edit" }), null, "tc-1");
    expect(result).toMatchObject({ action: "block" });
    expect(deps.escalate).not.toHaveBeenCalled();
  });

  it("a configured deny is never overridden by bypassPermissions", async () => {
    const { runner } = makeGateRunner({
      resolveResult: makeCheckResult({ state: "deny", matchedPattern: "*" }),
      mode: "bypassPermissions",
    });
    const result = await runner.run(makeDescriptor(), null, "tc-1");
    expect(result).toMatchObject({ action: "block" });
  });
});
