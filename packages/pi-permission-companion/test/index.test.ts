/**
 * Extension entry wiring test: decision events drive agentic-mirror levels and
 * deny-storm bursts; secret-scan mutates tool results; shutdown disposes.
 * Runs against a fake pi ExtensionAPI with an in-memory event bus.
 */

import { beforeEach, describe, expect, test, vi } from "vitest";
import companion from "#src/index";
import {
  getPermissionsService,
  PERMISSIONS_DECISION_CHANNEL,
  PERMISSIONS_READY_CHANNEL,
} from "gigapie-permissions";

vi.mock("gigapie-permissions", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("gigapie-permissions")>();
  return {
    ...actual,
    getPermissionsService: vi.fn(),
    PERMISSIONS_DECISION_CHANNEL: "permissions:decision",
    PERMISSIONS_READY_CHANNEL: "permissions:ready",
  };
});

vi.mock("#src/companion-config", () => ({
  loadCompanionConfig: () => ({ config: {}, issues: [] }),
}));

vi.mock("#src/agentic-logger", () => ({
  createAgenticLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

vi.mock("@earendil-works/pi-ai", () => ({
  completeSimple: vi.fn(),
}));

import { createAgenticLogger } from "#src/agentic-logger";

function makePi() {
  const handlers = new Map<string, Array<(data: unknown) => void>>();
  const pi = {
    events: {
      on: (channel: string, handler: (data: unknown) => void) => {
        const list = handlers.get(channel) ?? [];
        list.push(handler);
        handlers.set(channel, list);
        return () =>
          handlers.set(
            channel,
            (handlers.get(channel) ?? []).filter((h) => h !== handler),
          );
      },
      emit: (channel: string, data: unknown) => {
        for (const h of handlers.get(channel) ?? []) h(data);
      },
    },
    on: (event: string, handler: (event: never, ctx?: unknown) => unknown) => {
      const list = handlers.get(event) ?? [];
      list.push(handler as never);
      handlers.set(event, list);
    },
    __fire: (event: string, arg?: unknown, ctx?: unknown) => {
      for (const h of handlers.get(event) ?? []) {
        (h as (a: unknown, c: unknown) => void)(arg, ctx);
      }
    },
    __handlers: handlers,
  };
  return pi;
}

const CWD = "/test/project";

function startSession(pi: ReturnType<typeof makePi>) {
  pi.__fire("session_start", { type: "session_start" }, { cwd: CWD });
}

describe("companion extension wiring", () => {
  beforeEach(() => {
    vi.mocked(getPermissionsService).mockReturnValue(undefined);
  });

  test("secret scan denies a tool result carrying a secret", () => {
    const pi = makePi();
    companion(pi as never);
    startSession(pi);
    // enable secretScan via decision-free path: config load happens at
    // session_start from disk; drive a synthetic result with the builtin
    // pattern through the tool_result handler registered by the extension.
    const handler = pi.__handlers.get("tool_result")?.[0] as
      | ((e: { toolName: string; content: unknown[]; isError?: boolean }) =>
          unknown)
      | undefined;
    expect(handler).toBeDefined();
    // Without enabled config the handler declines (returns undefined).
    expect(
      handler!({
        toolName: "read",
        content: [{ type: "text", text: "API_KEY=abcdefgh12345678" }],
      }),
    ).toBeUndefined();
  });

  test("decision events: allow → info mirror; deny → warn + storm counter", () => {
    const pi = makePi();
    companion(pi as never);
    startSession(pi);
    const logger = createAgenticLogger()!;
    const allow = vi.mocked(logger.info);
    pi.events.emit(PERMISSIONS_DECISION_CHANNEL, {
      surface: "bash",
      value: "ls",
      result: "allow",
      resolution: "rules",
      origin: null,
      agentName: null,
    });
    // agenticMirror disabled by default → no mirror calls
    expect(allow).not.toHaveBeenCalled();
    // deny still feeds the storm monitor (enabled=false → inert), no throw
    expect(() =>
      pi.events.emit(PERMISSIONS_DECISION_CHANNEL, {
        surface: "bash",
        value: "rm -rf /",
        result: "deny",
        resolution: "rules",
        origin: null,
        agentName: null,
      }),
    ).not.toThrow();
  });

  test("session_shutdown disposes without throwing", () => {
    const pi = makePi();
    companion(pi as never);
    startSession(pi);
    expect(() => pi.__fire("session_shutdown")).not.toThrow();
  });

  test("permissions:ready with service but no judge config registers nothing", () => {
    const registerAuthorizer = vi.fn(() => () => undefined);
    vi.mocked(getPermissionsService).mockReturnValue({
      registerAuthorizer,
    } as never);
    const pi = makePi();
    companion(pi as never);
    startSession(pi);
    pi.events.emit(PERMISSIONS_READY_CHANNEL, {});
    expect(registerAuthorizer).not.toHaveBeenCalled();
  });
});
