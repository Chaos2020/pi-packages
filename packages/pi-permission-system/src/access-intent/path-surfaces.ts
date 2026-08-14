/**
 * File tools that only read — never write — the filesystem.
 * Only these tools are eligible for the Pi infrastructure auto-allow.
 */
export const READ_ONLY_PATH_BEARING_TOOLS: ReadonlySet<string> = new Set([
  "read",
  "find",
  "grep",
  "ls",
]);

export const PATH_BEARING_TOOLS = new Set([
  "read",
  "write",
  "edit",
  "find",
  "grep",
  "ls",
]);

/**
 * Surfaces whose patterns are matched against filesystem paths and therefore
 * fold case (and separators) on Windows: the path-bearing tools plus the
 * cross-cutting `path` gate and the `external_directory` boundary gate.
 */
export const PATH_SURFACES: ReadonlySet<string> = new Set([
  ...PATH_BEARING_TOOLS,
  "external_directory",
  "path",
  // Write-direction protection layer: guards key/config files against
  // modification, deletion, and secret overwrite from bash write targets
  // (redirect destinations, cp/mv/rm/tee/...). Kept separate from `path` so
  // the information-security layer (read-side) and the integrity-protection
  // layer (write-side) stay independent.
  "path_write",
]);
