import { describe, expect, test, vi } from "vitest";
import { SERENA_READ_TOOLS, registerSerenaExtractors } from "#src/serena-extractors";
import type { PermissionsService } from "gigapie-permissions";
import {
  getPermissionsService,
  PERMISSIONS_READY_CHANNEL,
} from "gigapie-permissions";

vi.mock("gigapie-permissions", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("gigapie-permissions")>();
  return {
    ...actual,
    getPermissionsService: vi.fn(),
    PERMISSIONS_READY_CHANNEL: "permissions:ready",
  };
});

function makeService() {
  const extractors = new Map<string, (input: Record<string, unknown>) => string | undefined>();
  const service = {
    registerToolAccessExtractor: (
      toolName: string,
      extractor: (input: Record<string, unknown>) => string | undefined,
    ) => {
      extractors.set(toolName, extractor);
      return () => extractors.delete(toolName);
    },
  } as unknown as PermissionsService;
  return { service, extractors };
}

function makePi() {
  const handlers = new Map<string, Array<(data: unknown) => void>>();
  return {
    events: {
      on: (channel: string, handler: (data: unknown) => void) => {
        const list = handlers.get(channel) ?? [];
        list.push(handler);
        handlers.set(channel, list);
        return () => handlers.set(channel, (handlers.get(channel) ?? []).filter((h) => h !== handler));
      },
      emit: (channel: string) => {
        for (const h of handlers.get(channel) ?? []) h({});
      },
    },
    __handlers: handlers,
  };
}

describe("serena extractors", () => {
  test("registers one extractor per serena read tool after permissions:ready", () => {
    const { service, extractors } = makeService();
    vi.mocked(getPermissionsService).mockReturnValue(service);
    const pi = makePi();
    const dispose = registerSerenaExtractors(pi as never);
    pi.events.emit(PERMISSIONS_READY_CHANNEL);
    expect(extractors.size).toBe(SERENA_READ_TOOLS.size);
    dispose();
  });

  test("extractor prefers relative_path and falls back to path", () => {
    const { service, extractors } = makeService();
    vi.mocked(getPermissionsService).mockReturnValue(service);
    const pi = makePi();
    const dispose = registerSerenaExtractors(pi as never);
    pi.events.emit(PERMISSIONS_READY_CHANNEL);
    const extract = extractors.get("serena_read_file");
    expect(extract).toBeDefined();
    expect(extract!({ relative_path: "src/x.ts" })).toBe("src/x.ts");
    expect(extract!({ path: "src/y.ts" })).toBe("src/y.ts");
    expect(extract!({ relative_path: "", path: "src/z.ts" })).toBe("src/z.ts");
    expect(extract!({})).toBeUndefined();
    dispose();
  });

  test("dispose unregisters everything", () => {
    const { service, extractors } = makeService();
    vi.mocked(getPermissionsService).mockReturnValue(service);
    const pi = makePi();
    const dispose = registerSerenaExtractors(pi as never);
    pi.events.emit(PERMISSIONS_READY_CHANNEL);
    dispose();
    expect(extractors.size).toBe(0);
  });
});
