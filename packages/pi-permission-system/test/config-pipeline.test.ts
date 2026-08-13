import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { loadAndMergeConfigs } from "#src/config-loader";
import { normalizePermissionSystemConfig } from "#src/extension-config";

/**
 * Full-pipeline seam tests: write a temp config.json → loadAndMergeConfigs →
 * normalizePermissionSystemConfig → assert values survive end to end.
 *
 * These tests guard the seam between the two normalizers — the class of bug
 * fixed in #332, where a field declared on PermissionSystemExtensionConfig was
 * silently dropped by the UnifiedPermissionConfig intermediate. The features
 * 2-6 sections below regressed exactly this class once (all five were dropped);
 * these cases pin them.
 */
describe("config pipeline seam", () => {
  let tempDir: string;
  let agentDir: string;
  let cwd: string;
  let extensionRoot: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "config-pipeline-test-"));
    agentDir = join(tempDir, "agent");
    cwd = join(tempDir, "project");
    extensionRoot = join(tempDir, "ext");
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  function writeGlobal(content: Record<string, unknown>): void {
    const dir = join(agentDir, "extensions", "pi-permission-system");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "config.json"), JSON.stringify(content));
  }

  it("runtime knob and preview-length field both survive the full pipeline", () => {
    writeGlobal({
      debugLog: true,
      toolInputPreviewMaxLength: 1000,
    });

    const mergeResult = loadAndMergeConfigs(agentDir, cwd, extensionRoot);
    const config = normalizePermissionSystemConfig(mergeResult.merged);

    expect(config.debugLog).toBe(true);
    expect(config.toolInputPreviewMaxLength).toBe(1000);
  });

  it("text summary length field survives the full pipeline", () => {
    writeGlobal({
      toolTextSummaryMaxLength: 250,
    });

    const mergeResult = loadAndMergeConfigs(agentDir, cwd, extensionRoot);
    const config = normalizePermissionSystemConfig(mergeResult.merged);

    expect(config.toolTextSummaryMaxLength).toBe(250);
  });

  it("project config overrides global preview-length field end to end", () => {
    writeGlobal({ toolInputPreviewMaxLength: 200 });
    const projectDir = join(cwd, ".pi", "extensions", "pi-permission-system");
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(
      join(projectDir, "config.json"),
      JSON.stringify({ toolInputPreviewMaxLength: 500 }),
    );

    const mergeResult = loadAndMergeConfigs(agentDir, cwd, extensionRoot);
    const config = normalizePermissionSystemConfig(mergeResult.merged);

    expect(config.toolInputPreviewMaxLength).toBe(500);
  });

  it("features 2-6 fields all survive the full pipeline", () => {
    writeGlobal({
      dryRun: true,
      permissionMode: "plan",
      modelJudge: {
        provider: "test-provider",
        model: "light",
        instructions: "judge paths",
      },
      secretScan: { enabled: true, action: "alert" },
      denyStorm: { enabled: true, maxDenials: 7, windowMs: 5000 },
    });

    const mergeResult = loadAndMergeConfigs(agentDir, cwd, extensionRoot);
    const config = normalizePermissionSystemConfig(mergeResult.merged);

    expect(config.dryRun).toBe(true);
    expect(config.permissionMode).toBe("plan");
    expect(config.modelJudge?.provider).toBe("test-provider");
    expect(config.secretScan?.enabled).toBe(true);
    expect(config.denyStorm?.maxDenials).toBe(7);
  });

  it("project override of a feature field wins end to end", () => {
    writeGlobal({ permissionMode: "default" });
    const projectDir = join(cwd, ".pi", "extensions", "pi-permission-system");
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(
      join(projectDir, "config.json"),
      JSON.stringify({ permissionMode: "acceptEdits", dryRun: true }),
    );

    const mergeResult = loadAndMergeConfigs(agentDir, cwd, extensionRoot);
    const config = normalizePermissionSystemConfig(mergeResult.merged);

    expect(config.permissionMode).toBe("acceptEdits");
    expect(config.dryRun).toBe(true);
  });
});
