import { describe, expect, it } from "vitest";
import { BashProgram } from "#src/access-intent/bash/program";
import { pathFlavorForPlatform } from "#src/path/path-flavor";
import { PathNormalizer } from "#src/path-normalizer";

const flavor = pathFlavorForPlatform(process.platform);
const nm = new PathNormalizer(flavor, "/mnt/big10T/wrk/mySkills");

describe("wrapper path-token regression check (C5)", () => {
  it("timeout 60 cat .env — .env is collected with role read (enters the path gate)", async () => {
    const p = await BashProgram.parse("timeout 60 cat .env", nm);
    const env = p
      .pathRuleCandidates()
      .find((c) => c.token === ".env" || c.token.endsWith("/.env"));
    expect(env, "pathRuleCandidates must contain .env").toBeDefined();
    expect(env?.role).toBe("read");
  });

  it("nohup rm -rf /tmp/x — /tmp/x is collected with role write (enters the path_write gate)", async () => {
    const p = await BashProgram.parse("nohup rm -rf /tmp/x", nm);
    const x = p.pathRuleCandidates().find((c) => c.token === "/tmp/x");
    expect(x, "pathRuleCandidates must contain /tmp/x").toBeDefined();
    expect(x?.role).toBe("write");
  });

  it("env FOO=bar cat .env — .env is collected with role read", async () => {
    const p = await BashProgram.parse("env FOO=bar cat .env", nm);
    const env = p
      .pathRuleCandidates()
      .find((c) => c.token === ".env" || c.token.endsWith("/.env"));
    expect(env).toBeDefined();
    expect(env?.role).toBe("read");
  });

  it("xargs -I{} cp {} /dst — /dst is collected with role write", async () => {
    const p = await BashProgram.parse("xargs -I{} cp {} /dst", nm);
    const dst = p.pathRuleCandidates().find((c) => c.token === "/dst");
    expect(dst).toBeDefined();
    expect(dst?.role).toBe("write");
  });

  it("find -exec — tokens fall back to read, never arg", async () => {
    const p = await BashProgram.parse(
      'find . -name "*.md" -exec grep -l foo {} \\;',
      nm,
    );
    const roles = p.pathRuleCandidates().map((c) => c.role);
    expect(roles.length).toBeGreaterThan(0);
    expect(roles.every((r) => r !== "arg")).toBe(true);
  });

  it("timeout 60 bash -c payload — opaque inner payload falls back to read, never arg", async () => {
    const p = await BashProgram.parse(
      "timeout 60 bash -c 'cat /etc/passwd'",
      nm,
    );
    const roles = p.pathRuleCandidates().map((c) => c.role);
    expect(roles.every((r) => r !== "arg")).toBe(true);
  });
});
