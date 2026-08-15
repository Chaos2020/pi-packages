import { getToolInputPath } from "#src/access-intent/tool-input-path";
import { classifyToolKind } from "#src/access-intent/tool-kind";
import type { PathNormalizer } from "#src/path-normalizer";
import type { ScopedPermissionResolver } from "#src/permission-resolver";
import { SessionApproval } from "#src/session-approval";
import { deriveApprovalPattern } from "#src/session-rules";
import type { ToolAccessExtractorLookup } from "#src/tool-access-extractor-registry";
import type { GateResult } from "./descriptor";
import { accessFactsFromPath, accessFactsFromValue } from "./helpers";
import type { ToolCallContext } from "./types";

/**
 * Serena-family tools that mutate the filesystem. Their targets ride the
 * cross-cutting `path_write` surface — the same key-file policy (settings
 * files, AGENTS.md, secrets) that gates built-in writes — so an agent cannot
 * use serena's symbol/file editing to bypass the file-level ask/deny rules.
 */
const SERENA_WRITE_TOOLS: ReadonlySet<string> = new Set([
  "serena_create_text_file",
  "serena_replace_content",
  "serena_replace_in_files",
  "serena_replace_symbol_body",
  "serena_insert_after_symbol",
  "serena_insert_before_symbol",
  "serena_rename_symbol",
  "serena_safe_delete_symbol",
]);

/**
 * `serena_replace_in_files` can scope to a whole project or a glob; a
 * wildcard scope may touch any file including key files, so only a literal
 * (single-file) scope is statically checkable.
 */
function replaceInFilesScope(record: Record<string, unknown>): string | null {
  const rel = getString(record.relative_path);
  if (rel) return rel;
  const glob = getString(record.paths_include_glob);
  if (glob && !/[?*[\]{}]/.test(glob)) return glob;
  return null; // whole project or wildcard — conservative ask below
}

function getString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/**
 * Tool-side `path_write` gate: a serena-family write tool whose target hits a
 * `path_write` deny/ask rule is blocked/prompted through the same surface as
 * bash writes. Returns `null` when the gate does not apply (not a write tool,
 * target resolves to allow, or no explicit rule matched).
 */
export function describeToolPathWriteGate(
  tcc: ToolCallContext,
  resolver: ScopedPermissionResolver,
  normalizer: PathNormalizer,
  extractors?: ToolAccessExtractorLookup,
): GateResult {
  // pi routes MCP servers through the single gateway tool `mcp`, called as
  // mcp({ tool: "serena_...", args: {...} }) — the real target rides in
  // input.tool/input.args. Match SERENA_WRITE_TOOLS and extract the path
  // against that effective pair; matching the wrapper name ("mcp") would let
  // every serena write bypass this surface entirely.
  const wrapper = (tcc.input ?? {}) as Record<string, unknown>;
  let effToolName = tcc.toolName;
  let effInput: unknown = wrapper;
  if (classifyToolKind(tcc.toolName) === "mcp") {
    const innerTool = getString(wrapper.tool);
    if (innerTool) {
      effToolName = innerTool;
      effInput = wrapper.args ?? {};
    }
  }

  if (!SERENA_WRITE_TOOLS.has(effToolName)) return null;

  const record = (effInput ?? {}) as Record<string, unknown>;
  let filePath: string | null;
  if (effToolName === "serena_replace_in_files") {
    filePath = replaceInFilesScope(record);
  } else {
    filePath = getToolInputPath(effToolName, effInput, extractors);
  }

  // A wildcard/whole-project write scope cannot be statically proven safe —
  // it may touch key files, so conservatively ask.
  if (filePath === null) {
    return {
      surface: "path_write",
      input: { path: undefined },
      denialContext: {
        kind: "tool_path_write",
        toolName: effToolName,
        pathValue: undefined,
        agentName: tcc.agentName ?? undefined,
      },
      sessionApproval: SessionApproval.single("path_write", "**"),
      promptDetails: {
        source: "tool_call",
        agentName: tcc.agentName,
        message:
          "This serena write tool's scope (whole project or wildcard) cannot be statically checked against key-file rules.",
        toolCallId: tcc.toolCallId,
        toolName: effToolName,
        accessIntent: accessFactsFromValue("path_write", "<wildcard-scope>"),
      },
      logContext: {
        source: "tool_call",
        toolCallId: tcc.toolCallId,
        toolName: effToolName,
        agentName: tcc.agentName,
      },
      decision: { surface: "path_write", value: "<wildcard-scope>" },
    };
  }

  const accessPath = normalizer.forPath(filePath);
  const check = resolver.resolve({
    kind: "access-path",
    surface: "path_write",
    path: accessPath,
    agentName: tcc.agentName ?? undefined,
  });

  if (check.state === "allow") return null;
  if (check.matchedPattern === undefined) return null; // universal default only

  const pattern = deriveApprovalPattern(accessPath.value());
  return {
    surface: "path_write",
    input: { path: filePath },
    denialContext: {
      kind: "tool_path_write",
      toolName: effToolName,
      pathValue: filePath,
      agentName: tcc.agentName ?? undefined,
    },
    sessionApproval: SessionApproval.single("path_write", pattern),
    promptDetails: {
      source: "tool_call",
      agentName: tcc.agentName,
      message: `${effToolName} writes a file that is protected by the path_write policy.`,
      toolCallId: tcc.toolCallId,
      toolName: effToolName,
      accessIntent: accessFactsFromPath("path_write", accessPath),
    },
    logContext: {
      source: "tool_call",
      toolCallId: tcc.toolCallId,
      toolName: effToolName,
      agentName: tcc.agentName,
      path: filePath,
    },
    decision: { surface: "path_write", value: filePath },
    preCheck: check,
  };
}
