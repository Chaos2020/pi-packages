/**
 * The cost gate: compile the operator's `typoPatterns` to regexes and test a
 * candidate path against them. Only a path that matches a configured pattern
 * reaches the model — an empty/absent pattern list matches nothing, so the
 * reviewer defers everything without a model call.
 *
 * Ported from pi-permission-model-judge (feature 2: built-in model-judge
 * authorizer).
 */
export interface CompiledTypoPatterns {
  regexes: RegExp[];
  patterns: string[];
  invalidPatterns: string[];
}

export function compileTypoPatterns(
  patterns: readonly string[],
): CompiledTypoPatterns {
  const regexes: RegExp[] = [];
  const sources: string[] = [];
  const invalidPatterns: string[] = [];
  for (const pattern of patterns) {
    try {
      regexes.push(new RegExp(pattern));
      sources.push(pattern);
    } catch {
      invalidPatterns.push(pattern);
    }
  }
  return { regexes, patterns: sources, invalidPatterns };
}

export function matchTypoPattern(
  path: string,
  compiled: CompiledTypoPatterns,
): string | undefined {
  const index = compiled.regexes.findIndex((regex) => regex.test(path));
  return index === -1 ? undefined : compiled.patterns[index];
}
