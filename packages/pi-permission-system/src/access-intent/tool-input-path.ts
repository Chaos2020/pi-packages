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
 * A tool invocation's effective tool name and input after gateway unwrapping.
 */
export interface GatewayCall {
  toolName: string;
  input: unknown;
}

/**
 * Resolve the effective (toolName, input) pair the gateway dispatch will
 * execute, shared by the cross-cutting path gates so the unwrap logic exists
 * exactly once.
 *
 * pi routes every MCP server through the single built-in `mcp` tool, called
 * as mcp({ tool: "serena_read_file", args: {...} }). The deployed
 * pi-mcp-adapter dispatch normalizes the inner name with a dash→underscore
 * fallback (`findToolByName`) and accepts `args` either as an object or a JSON
 * string — the gates must derive the same pair or a dashed name
 * ("serena-create-text-file") or string args silently miss every Set
 * membership and extraction check.
 *
 * - Non-`mcp` tool → the original pair unchanged.
 * - Gateway shape → the normalized inner name plus the parsed `args`
 *   (object as-is; JSON string parsed).
 * - Nested `mcp` inner name → the original pair (falls through to the stdio
 *   `arguments.path` shape instead of recursing).
 * - String `args` that fail `JSON.parse` → `null`: the dispatch itself
 *   throws before the inner call executes, so there is nothing to gate.
 */
export function unwrapGatewayCall(
  toolName: string,
  input: unknown,
): GatewayCall | null {
  if (classifyToolKind(toolName) !== "mcp") {
    return { toolName, input };
  }
  const record = toRecord(input);
  const innerTool = getNonEmptyString(record.tool);
  if (!innerTool) {
    return { toolName, input };
  }
  const normalized = innerTool.replace(/-/g, "_");
  if (classifyToolKind(normalized) === "mcp") {
    return { toolName, input };
  }
  const args = record.args;
  if (typeof args === "string") {
    try {
      return { toolName: normalized, input: JSON.parse(args) };
    } catch {
      return null;
    }
  }
  return { toolName: normalized, input: args ?? {} };
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
 * - `mcp` (gateway shape `{tool, args}`) → {@link unwrapGatewayCall}'s
 *   effective pair: the dash-normalized inner tool's path.
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
      // Gateway shape: unwrap once (see unwrapGatewayCall) and re-classify the
      // inner tool so gateway-routed calls are path-gated by their real
      // target; a still-`mcp` effective name (stdio shape, or a nested
      // gateway name refused recursion) reads the stdio `arguments.path`.
      const effective = unwrapGatewayCall(toolName, input);
      if (!effective) {
        return null; // string args failed JSON.parse — dispatch throws first
      }
      if (classifyToolKind(effective.toolName) === "mcp") {
        return getNonEmptyString(
          toRecord(toRecord(effective.input).arguments).path,
        );
      }
      return getToolInputPath(effective.toolName, effective.input, extractors);
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
