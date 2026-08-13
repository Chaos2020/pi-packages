import { describe, expect, it } from "vitest";
import { makeCheckResult } from "#test/helpers/handler-fixtures";
import {
  makeDescriptor,
  makeGateRunner,
} from "#test/helpers/gate-fixtures";

// Feature 4: dry-run / simulation mode — record would-be decisions, never enforce.

describe("feature 4: dry-run mode", () => {
  it("records would-be deny and allows (no block, no prompt)", async () => {
    const { runner, deps } = makeGateRunner({
      resolveResult: makeCheckResult({ state: "deny", matchedPattern: "*" }),
      dryRun: true,
    });
    const result = await runner.run(makeDescriptor(), null, "tc-1");
    expect(result).toEqual({ action: "allow" });
    expect(deps.reporter.writeReviewLog).toHaveBeenCalledWith(
      "permission_request.dry_run",
      expect.objectContaining({ wouldBe: "deny", tool: "read" }),
    );
    expect(deps.escalate).not.toHaveBeenCalled();
  });

  it("records would-be ask without prompting (dry-run)", async () => {
    const { runner, deps } = makeGateRunner({
      resolveResult: makeCheckResult({ state: "ask", matchedPattern: "*" }),
      dryRun: true,
    });
    const result = await runner.run(makeDescriptor(), null, "tc-1");
    expect(result).toEqual({ action: "allow" });
    expect(deps.reporter.writeReviewLog).toHaveBeenCalledWith(
      "permission_request.dry_run",
      expect.objectContaining({ wouldBe: "ask" }),
    );
    expect(deps.escalate).not.toHaveBeenCalled();
  });

  it("without dry-run, a deny still blocks", async () => {
    const { runner } = makeGateRunner({
      resolveResult: makeCheckResult({ state: "deny", matchedPattern: "*" }),
    });
    const result = await runner.run(makeDescriptor(), null, "tc-1");
    expect(result).toMatchObject({ action: "block" });
  });
});
