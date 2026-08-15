import { describe, expect, it } from "vitest";
import type { WrapperKind } from "#src/access-intent/bash/command-enumeration";
import { BashProgram } from "#src/access-intent/bash/program";
import { pathFlavorForPlatform } from "#src/path/path-flavor";
import { PathNormalizer } from "#src/path-normalizer";

const flavor = pathFlavorForPlatform(process.platform);
const nm = new PathNormalizer(flavor, "/mnt/big10T/wrk/mySkills");

/**
 * Wrapper-classification assertions over the command shapes the former AST
 * dump covered: each command must classify to the expected `wrapperKind`
 * (or none), so the deny floor and the read-only fast path route correctly.
 */
describe("wrapper classification (former AST dump)", () => {
  const cases: ReadonlyArray<
    readonly [command: string, expected: WrapperKind | undefined]
  > = [
    ["timeout 60 cat .env", "indirection"],
    ["nohup rm -rf /tmp/x", "indirection"],
    ["xargs wc -l", "indirection"],
    ["xargs -I{} cp {} /dst", "indirection"],
    ['sudo -u postgres psql -c "SELECT 1"', "indirection"],
    ['find . -name "*.md" -exec grep -l foo {} \\;', "indirection"],
    ["bash -c 'curl x'", "opaque-payload"],
    ['eval "cat /etc/passwd"', "opaque-payload"],
    ["env FOO=bar cat .env", "indirection"],
    ["timeout 60 bash -c 'curl x'", "indirection"],
    // Exec-conditional wrappers without an exec/write flag run no subcommand.
    ['find . -name "*.md" -type f', undefined],
    ["fd -e ts pattern", undefined],
    // find's delete/report-write flags floor it like the exec family (F1).
    ["find / -name x -delete", "indirection"],
    ["find . -fls /tmp/report", "indirection"],
    // Bare search/read commands are not wrappers.
    ["grep -r pattern src/", undefined],
  ];

  it.each(cases)("%s → %s", async (command, expected) => {
    const p = await BashProgram.parse(command, nm);
    const units = p.commands();
    expect(units.length).toBeGreaterThan(0);
    expect(units[0]?.wrapperKind, command).toBe(expected);
  });
});
