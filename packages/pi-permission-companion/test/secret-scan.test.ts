import { describe, expect, test } from "vitest";
import {
  BUILTIN_SECRET_PATTERNS,
  compileSecretPatterns,
  redactAll,
  redactSecret,
  scanForSecrets,
} from "#src/secret-scan-patterns";

// Feature 3: secret detection in tool output (patterns + redaction).

describe("feature 3: secret detection", () => {
  test("built-in patterns match known secret shapes", () => {
    const compiled = compileSecretPatterns(BUILTIN_SECRET_PATTERNS);
    const cases: [string, string][] = [
      ["sk-abcdef1234567890abcdef", "OpenAI key"],
      ["AIzaSyA-1234567890abcdefghij", "Google key"],
      ["ghp_1234567890abcdefghijklmn", "GitHub PAT"],
      ["AKIA1234567890ABCDEF", "AWS access key"],
      ["xoxb-1234567890-abcdefghijkl", "Slack token"],
      ["API_KEY = superSecretValue123", ".env-style leaked line"],
      ["token: mySecretToken12345", "generic key=value"],
    ];
    for (const [text, label] of cases) {
      const hits = scanForSecrets(text, compiled);
      expect(hits.length, label).toBeGreaterThan(0);
    }
  });

  test("redaction never leaks the full secret", () => {
    const secret = "sk-abcdef1234567890abcdef";
    const compiled = compileSecretPatterns(BUILTIN_SECRET_PATTERNS);
    const hits = scanForSecrets(`prefix ${secret} suffix`, compiled);
    expect(hits.length).toBe(1);
    const redacted = redactSecret(hits[0].match);
    expect(redacted).toBe("[REDACTED]");
    expect(redacted).not.toContain(secret);
    expect(redacted).not.toContain(secret.slice(0, 4)); // no prefix leak
  });

  test("redactAll replaces every occurrence", () => {
    const text = "a sk-abc1234567890abcdef and sk-abc1234567890abcdef again";
    const compiled = compileSecretPatterns(BUILTIN_SECRET_PATTERNS);
    const hits = scanForSecrets(text, compiled);
    expect(hits.length).toBe(1);
    const out = redactAll(text, hits);
    expect(out).not.toContain("sk-abc1234567890abcdef");
    expect(out).toContain("[REDACTED]");
  });

  test("empty pattern list -> no hits (and no throw)", () => {
    const compiled = compileSecretPatterns([]);
    expect(compiled.invalidPatterns).toEqual([]);
    expect(scanForSecrets("sk-abcdef1234567890abcdef", compiled)).toEqual([]);
  });

  test("invalid pattern is skipped, not fatal", () => {
    const compiled = compileSecretPatterns(["([unclosed", "sk-[A-Za-z0-9]{16,}"]);
    expect(compiled.invalidPatterns.length).toBe(1);
    expect(compiled.regexes.length).toBe(1);
    const hits = scanForSecrets("sk-abcdef1234567890abcdef", compiled);
    expect(hits.length).toBe(1);
  });

  test("short matches are ignored (avoid noise)", () => {
    const compiled = compileSecretPatterns(["sk-[A-Za-z0-9]{1,}"]);
    const hits = scanForSecrets("sk-ab", compiled);
    expect(hits.length).toBe(0); // length < 6 filtered
  });
});
