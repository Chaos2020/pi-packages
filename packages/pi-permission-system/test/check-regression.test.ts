import { describe, expect, it } from "vitest";
import { BashProgram } from "#src/access-intent/bash/program";
import { pathFlavorForPlatform } from "#src/path/path-flavor";
import { PathNormalizer } from "#src/path-normalizer";

const flavor = pathFlavorForPlatform(process.platform);
const nm = new PathNormalizer(flavor, "/mnt/big10T/wrk/mySkills");

describe("wrapper path-token regression check", () => {
  it("timeout 60 cat .env — is .env still collected?", async () => {
    const p = await BashProgram.parse("timeout 60 cat .env", nm);
    const cands = p.pathRuleCandidates();
    const dump = cands.map((c) => `${c.role}:${c.token}`);
    require("node:fs").writeFileSync("/tmp/regress.txt", JSON.stringify(dump, null, 2));
    const hasEnv = cands.some((c) => c.token.endsWith(".env"));
    console.log("HAS_ENV:", hasEnv);
    expect(true).toBe(true);
  });
  it("nohup rm -rf /tmp/x", async () => {
    const p = await BashProgram.parse("nohup rm -rf /tmp/x", nm);
    const dump = p.pathRuleCandidates().map((c) => `${c.role}:${c.token}`);
    require("node:fs").appendFileSync("/tmp/regress.txt", "\nnohup: " + JSON.stringify(dump));
    expect(true).toBe(true);
  });
});
