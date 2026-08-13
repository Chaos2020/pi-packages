/**
 * Feature 3: secret-detection patterns — compile + match leaked-secret regexes.
 * Built-in patterns cover common API key / token / .env-style shapes; the
 * operator can extend via `secretScan.patterns` (invalid regexes are skipped
 * with a warning).
 */
export interface CompiledSecretPatterns {
  regexes: RegExp[];
  patterns: string[];
  invalidPatterns: string[];
}

/** Built-in secret shapes (case-insensitive). */
export const BUILTIN_SECRET_PATTERNS: string[] = [
  // OpenAI-style sk-...
  "sk-[A-Za-z0-9_-]{16,}",
  // Google API key
  "AIza[0-9A-Za-z_-]{20,}",
  // GitHub PAT
  "ghp_[A-Za-z0-9]{20,}",
  // GitHub fine-grained PAT
  "github_pat_[A-Za-z0-9_]{20,}",
  // Slack tokens
  "xox[baprs]-[A-Za-z0-9-]{10,}",
  // AWS access key id
  "AKIA[0-9A-Z]{16}",
  // Stripe live key
  "sk_live_[0-9a-zA-Z]{20,}",
  // generic key=value assignment with a long secret value
  "(?:api[_-]?key|token|secret|passwd|password)[ \t]*[:=][ \t]*[A-Za-z0-9_+/=]{12,}",
  // .env-style leaked line with an explicit secret key name (avoids false
  // positives on PATH=, HOME=, CC= etc.)
  "^(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN|BEARER)[ \t]*=[ \t]*[^ \t]{8,}",
];

export function compileSecretPatterns(
  patterns: readonly string[],
): CompiledSecretPatterns {
  const regexes: RegExp[] = [];
  const sources: string[] = [];
  const invalidPatterns: string[] = [];
  for (const pattern of patterns) {
    try {
      regexes.push(new RegExp(pattern, "gim"));
      sources.push(pattern);
    } catch {
      invalidPatterns.push(pattern);
    }
  }
  return { regexes, patterns: sources, invalidPatterns };
}

export interface SecretHit {
  pattern: string;
  match: string;
  /** Redacted form shown in logs/results: first 4 chars + ****. */
  redacted: string;
}

export function redactSecret(_match: string): string {
  // Placeholder only — never leak any prefix of the secret.
  return "[REDACTED]";
}

export function scanForSecrets(
  text: string,
  compiled: CompiledSecretPatterns,
): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < compiled.regexes.length; i++) {
    const regex = compiled.regexes[i];
    const pattern = compiled.patterns[i];
    for (const m of text.matchAll(regex)) {
      const match = m[0];
      if (match.length < 6 || seen.has(match)) {
        continue;
      }
      seen.add(match);
      hits.push({ pattern, match, redacted: redactSecret(match) });
    }
  }
  return hits;
}

export function redactAll(text: string, hits: SecretHit[]): string {
  let out = text;
  // Longest match first, so a shorter hit's placeholder can never break a
  // longer hit's full match (order-safety).
  const ordered = [...hits].sort((a, b) => b.match.length - a.match.length);
  for (const hit of ordered) {
    out = out.split(hit.match).join(hit.redacted);
  }
  return out;
}
