/**
 * Serena-family MCP tool path extractors — the companion-side half of the
 * fork's serena path gating.
 *
 * The fork's in-tree patch unwraps the `mcp` gateway call inside every gate
 * (path / external_directory / path_write) so gateway-routed calls are gated
 * under their real inner tool (`mcp({tool:"serena_read_file", args:…})` →
 * `serena_read_file`). The gate-side unwrap is an in-tree patch (Phase B);
 * what a companion CAN do today is register extractors for the
 * **non-gateway** invocations:
 *
 * - tools the LLM invokes directly by name (`serena_read_file({relative_path})`)
 *   — `classifyToolKind` routes them to the extension branch, which consults
 *   these extractors.
 *
 * A serena call through the `mcp` gateway umbrella still needs the in-tree
 * unwrap; an extractor registered for `"mcp"` would fire only on the stdio
 * shape (`input.arguments`) and, worse, shadow the built-in gateway unwrap
 * once Phase B lands it upstream-side. So: register the concrete tool names
 * only, and keep the gateway unwrap in-tree.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  getPermissionsService,
  PERMISSIONS_READY_CHANNEL,
} from "gigapie-permissions";

/** Serena tools whose access target rides a non-standard input key. */
export const SERENA_READ_TOOLS: ReadonlySet<string> = new Set([
  "serena_read_file",
  "serena_list_dir",
  "serena_search_for_pattern",
  "serena_find_file",
  "serena_get_symbols_overview",
  "serena_search_for_symbol",
  "serena_get_references",
  "serena_get_symbol_details",
]);

export function registerSerenaExtractors(
  pi: ExtensionAPI,
): () => void {
  const disposers: Array<() => void> = [];
  let done = false;

  function tryRegister(): void {
    if (done) return;
    const service = getPermissionsService();
    if (!service) return;
    for (const toolName of SERENA_READ_TOOLS) {
      try {
        disposers.push(
          service.registerToolAccessExtractor(toolName, (input) => {
            const record = (input ?? {}) as Record<string, unknown>;
            // relative_path (single file/dir) is the serena convention;
            // conventional path key is the fallback.
            const rel =
              typeof record.relative_path === "string" && record.relative_path
                ? record.relative_path
                : undefined;
            const path =
              typeof record.path === "string" && record.path
                ? record.path
                : undefined;
            return rel ?? path;
          }),
        );
      } catch {
        // Already registered by another extension — skip.
      }
    }
    done = true;
  }

  const offReady = pi.events.on(PERMISSIONS_READY_CHANNEL, tryRegister);
  tryRegister();

  return () => {
    offReady();
    for (const dispose of disposers.splice(0)) {
      try {
        dispose();
      } catch {
        // best-effort teardown
      }
    }
    done = false;
  };
}
