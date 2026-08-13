import { describe, expect, test } from "vitest";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgentLogger } from "agentic-logger";
import { createPermissionSystemLogger } from "#src/logging";

// Feature 1 (AgenticLogger integration): every review/debug entry is mirrored
// to the unified AgenticLogger JSONL alongside the extension's own review log.
describe("feature 1: AgenticLogger integration", () => {
  test("review() mirrors a deny entry to AgenticLogger JSONL as ERROR", () => {
    const dir = mkdtempSync(join(tmpdir(), "ps-f1-"));
    process.env.AGENTIC_LOG_DIR = dir;
    const logger = createPermissionSystemLogger({
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        yoloMode: false,
        doublePressToConfirm: true,
      }),
      debugLogPath: join(dir, "debug.jsonl"),
      reviewLogPath: join(dir, "review.jsonl"),
      ensureLogsDirectory: () => undefined,
      agenticLogger: new AgentLogger({
        program: "pi-permission-system",
        command: "test",
        logDir: dir,
      }),
    });

    logger.review("permission_request.deny", {
      tool: "bash",
      pattern: "rm -rf *",
      severity: "CRITICAL",
    });

    // Extension's own review log still written (existing behavior preserved).
    const reviewLog = readFileSync(join(dir, "review.jsonl"), "utf-8");
    expect(reviewLog).toContain("permission_request.deny");

    // Feature 1: AgenticLogger JSONL landed in the unified dir.
    const agenticFiles = readdirSync(dir).filter((f) =>
      f.startsWith("pi-permission-system_"),
    );
    expect(agenticFiles.length).toBe(1);
    const agenticLine = readFileSync(join(dir, agenticFiles[0]), "utf-8");
    expect(agenticLine).toContain("permission-system");
    expect(agenticLine).toContain("permission_request.deny");
    expect(agenticLine).toContain('"level": "ERROR"');
    expect(agenticLine).toContain("rm -rf *");
  });
});
