import type { ToolAccessExtractorLookup } from "#src/tool-access-extractor-registry";
import { getNonEmptyString, toRecord } from "#src/value-guards";
import { classifyToolKind } from "./tool-kind";

export function getPathBearingToolPath(
  toolName: string,
  input: unknown,
): string | null {
  if (classifyToolKind(toolName) !== "path") {
    return null;
  }

  return getNonEmptyString(toRecord(input).path);
}

/**
 * Extract the filesystem path a tool will access, for the cross-cutting `path`
 * and `external_directory` gates.
 *
 * Unlike {@link getPathBearingToolPath} (built-in tools only), this recognizes
 * extension and MCP tools so they are no longer exempt from path gating:
 *
 * - `bash` → `null` (bash has its own token-based path gates).
 * - Built-in path-bearing tools → `input.path`.
 * - `mcp` (stdio shape) → `input.arguments.path`.
 * - `mcp` (gateway shape `{tool, args}`) → the unwrapped inner tool's path.
 * - Any other tool → a registered {@link ToolAccessExtractor}'s path, else the
 *   default `input.path` convention.
 */
export function getToolInputPath(
  toolName: string,
  input: unknown,
  extractors?: ToolAccessExtractorLookup,
): string | null {
  const record = toRecord(input);

  switch (classifyToolKind(toolName)) {
    case "bash":
      return null;
    case "path":
      return getNonEmptyString(record.path);
    case "mcp": {
      // Gateway shape: pi routes every MCP server through the single built-in
      // `mcp` tool, called as mcp({ tool: "serena_read_file", args: {...} }).
      // Unwrap once and re-classify the inner tool so gateway-routed calls are
      // path-gated by their real target; a nested "mcp" name is not recursed
      // into (fall through to the stdio `arguments.path` shape instead).
      const innerTool = getNonEmptyString(record.tool);
      if (innerTool && classifyToolKind(innerTool) !== "mcp") {
        return getToolInputPath(innerTool, record.args, extractors);
      }
      return getNonEmptyString(toRecord(record.arguments).path);
    }
    case "skill":
    case "extension": {
      const custom = extractors?.get(toolName);
      if (custom) {
        return getNonEmptyString(custom(record));
      }
      // Serena-family tools carry the target as `relative_path` (single file
      // or directory); the conventional `input.path` is the fallback. Without
      // this, every serena_* tool escapes the cross-cutting path gates.
      return (
        getNonEmptyString(record.path) ??
        getNonEmptyString(record.relative_path)
      );
    }
  }
}
