/**
 * Minimal session-entry view: the only fields {@link getActiveAgentName}
 * reads off each entry. Narrowing to this structural slice (rather than the
 * SDK `SessionEntry` discriminated union) keeps callers and test fixtures free
 * of the union's nine unrelated variants.
 */
export interface SessionEntryView {
  type: string;
  customType?: string;
  data?: unknown;
}

/**
 * Narrow context for {@link getActiveAgentName} — it reads only the session
 * entries. A full `ExtensionContext` satisfies this structurally.
 */
export interface ActiveAgentContext {
  sessionManager: { getEntries(): readonly SessionEntryView[] };
}

/**
 * Matches the `<active_agent name="...">` tag injected by pi-agent-router
 * into the system prompt to identify which agent definition is active.
 */
export const ACTIVE_AGENT_TAG_REGEX =
  /<active_agent\s+name=["']([^"']+)["'][^>]*>/i;

export function normalizeAgentName(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

export function getActiveAgentName(ctx: ActiveAgentContext): string | null {
  const entries = ctx.sessionManager.getEntries();
  for (let i = entries.length - 1; i >= 0; i--) {
    const entry = entries[i];
    if (entry.type !== "custom" || entry.customType !== "active_agent") {
      continue;
    }

    const data = entry.data as { name?: unknown } | undefined;
    const normalizedName = normalizeAgentName(data?.name);
    if (normalizedName) {
      return normalizedName;
    }

    if (data?.name === null) {
      return null;
    }
  }

  return null;
}

export function getActiveAgentNameFromSystemPrompt(
  systemPrompt: string | undefined,
): string | null {
  if (!systemPrompt) {
    return null;
  }

  const match = ACTIVE_AGENT_TAG_REGEX.exec(systemPrompt);
  if (!match?.[1]) {
    return null;
  }

  return normalizeAgentName(match[1]);
}

/**
 * Resolve the active agent name with an env fallback for orchestrator-launched
 * agents (GigaPie supervisor injects GIGAPIE_AGENT_NAME; pi-agent-router injects
 * the `<active_agent>` tag into the system prompt instead). Returns null when
 * neither source is present, which keeps the global scope authoritative.
 */
export function resolveActiveAgentName(
  ctx: ActiveAgentContext,
  systemPrompt: string | undefined,
): string | null {
  const fromSession = getActiveAgentName(ctx);
  if (fromSession) {
    return fromSession;
  }
  const fromSystemPrompt = getActiveAgentNameFromSystemPrompt(systemPrompt);
  if (fromSystemPrompt) {
    return fromSystemPrompt;
  }
  const fromEnv = process.env.GIGAPIE_AGENT_NAME;
  return normalizeAgentName(fromEnv);
}
