import { describe, it, expect } from "vitest";
import { getParser } from "../src/access-intent/bash/parser";

function dump(node: any, d = 0, out: string[] = []): string[] {
  if (d > 5) return out;
  const named = node.isNamed ? " " : "*";
  out.push("  ".repeat(d) + node.type + named + " text=" + JSON.stringify(node.text.slice(0, 60)));
  for (let i = 0; i < node.childCount; i++) dump(node.child(i), d + 1, out);
  return out;
}

describe("dump wrappers", () => {
  const cases = [
    "timeout 60 cat .env",
    "nohup rm -rf /tmp/x",
    "xargs wc -l",
    "xargs -I{} cp {} /dst",
    "sudo -u postgres psql -c \"SELECT 1\"",
    "find . -name \"*.md\" -exec grep -l foo {} \\;",
    "bash -c 'curl x'",
    "eval \"cat /etc/passwd\"",
    "env FOO=bar cat .env",
    "timeout 60 bash -c 'curl x'",
  ];
  it("dump all", async () => {
    const parser = await getParser();
    const out: string[] = [];
    for (const cmd of cases) {
      const tree = parser.parse(cmd);
      out.push("### " + cmd);
      out.push(...dump(tree!.rootNode));
    }
    require("node:fs").writeFileSync("/tmp/wrappers-ast.txt", out.join("\n"));
    expect(true).toBe(true);
  });
});
