import { describe, it, expect } from "vitest";
import { loadUnifiedConfig } from "../src/config-loader";

describe("live config loads without issues", () => {
  it("parses and validates ~/.pi live config", () => {
    const { config, issues } = loadUnifiedConfig(
      "/home/lxx/.pi/agent/extensions/pi-permission-system/config.json",
    );
    expect(issues).toEqual([]);
    const perm = config.permission as Record<string, unknown>;
    expect(perm["write"]).toBeDefined();
    expect(perm["edit"]).toBeDefined();
    const write = perm["write"] as Record<string, unknown>;
    expect(write["*"]).toBe("allow");
    expect(Object.keys(write).some((k) => k.includes("mySkills"))).toBe(false);
    const edit = perm["edit"] as Record<string, unknown>;
    expect(edit["*"]).toBe("allow");
    expect(Object.keys(edit).some((k) => k.includes("mySkills"))).toBe(false);
    // critical files still protected
    const pwrite = perm["path_write"] as Record<string, unknown>;
    expect(pwrite["*AGENTS.md"]).toBe("ask");
    expect(pwrite["~/.pi/agent/extensions/pi-permission-system/config.json"]).toBe("ask");
    expect(pwrite["~/.pi/agent/auth.json"]).toBe("deny");
  });
});
