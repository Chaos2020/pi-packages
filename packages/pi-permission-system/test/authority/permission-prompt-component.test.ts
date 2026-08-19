import { visibleWidth } from "@earendil-works/pi-tui";
import { describe, expect, it, vi } from "vitest";
import type {
  RequestPermissionOptions,
  UnattributedDecision,
} from "#src/authority/permission-dialog";
import {
  type PermissionPromptUi,
  type PermissionPromptView,
  presentInlinePermissionPrompt,
  requestPermissionDecision,
} from "#src/authority/permission-prompt-component";
import { DEFAULT_RENDER_BUDGET } from "#src/presentation/dialog-renderer";
import type { PromptPayload } from "#src/presentation/prompt-payload";
import { makePromptPayload } from "#test/helpers/prompt-details-fixtures";
import { makePromptPreferences } from "#test/helpers/prompt-view-fixtures";

// ── Fake TUI view harness ────────────────────────────────────────────────────

function plainTheme() {
  return {
    fg(_color: string, text: string) {
      return text;
    },
    bg(_color: string, text: string) {
      return text;
    },
  };
}

interface CapturedComponent {
  render(width: number): string[];
  handleInput(data: string): void;
}

type PromptFactory = (
  tui: { requestRender: () => void },
  theme: ReturnType<typeof plainTheme>,
  keybindings: { matches(data: string, action: string): boolean },
  done: (decision: UnattributedDecision) => void,
) => CapturedComponent;

/** Pi's default binding for the `app.tools.expand` action. */
const CTRL_O = "\u000f";

function makeFakeView(
  doublePressToConfirm: boolean,
  expandKey = CTRL_O,
  budget = DEFAULT_RENDER_BUDGET,
  askTimeoutMs = 0,
) {
  const captured: {
    component?: CapturedComponent;
    options?: unknown;
  } = {};
  let toolsExpanded = false;
  const getToolsExpanded = vi.fn(() => toolsExpanded);
  const setToolsExpanded = vi.fn((expanded: boolean) => {
    toolsExpanded = expanded;
  });
  const custom = (
    factory: PromptFactory,
    options: unknown,
  ): Promise<UnattributedDecision> => {
    captured.options = options;
    return new Promise<UnattributedDecision>((resolve) => {
      captured.component = factory(
        { requestRender: vi.fn() },
        plainTheme(),
        {
          matches: (data, action) =>
            action === "app.tools.expand" && data === expandKey,
        },
        resolve,
      );
    });
  };
  const view = makeView(
    "tui",
    doublePressToConfirm,
    {
      select: vi.fn(),
      input: vi.fn(),
      custom,
      getToolsExpanded,
      setToolsExpanded,
    },
    budget,
    askTimeoutMs,
  );
  return { view, captured, getToolsExpanded, setToolsExpanded };
}

/**
 * The view the dispatcher and the inline component take.
 *
 * Typed as `PermissionPromptView` so a field added to it is a compile error
 * here; the cast is confined to the `ui` double, whose generic `custom` a
 * plain `vi.fn()` cannot satisfy.
 */
function makeView(
  mode: PermissionPromptView["mode"],
  doublePressToConfirm: boolean,
  ui: unknown,
  budget = DEFAULT_RENDER_BUDGET,
  askTimeoutMs = 0,
): PermissionPromptView {
  return {
    mode,
    ui: ui as PermissionPromptUi,
    ...makePromptPreferences({ doublePressToConfirm, budget, askTimeoutMs }),
  };
}

const ARROW_DOWN = "\u001b[B";
const ENTER = "\r";
const ESCAPE = "\u001b";

/** How the terminal delivers a paste: one chunk, markers included. */
function paste(content: string): string {
  return `\u001b[200~${content}\u001b[201~`;
}

/** A path ask; `path : /repo/secret.txt` is its decision-relevant line. */
function makeAsk(value = "/repo/secret.txt"): PromptPayload {
  return makePromptPayload({
    kind: "path",
    request: {
      ...makePromptPayload().request,
      surface: "path",
      toolName: "read",
      value,
      matchedPattern: null,
    },
  });
}

const ASK = makeAsk();

/** Title, blank separator, four decision options, blank, hint. */
const DECISION_CHROME_ROWS = 8;

async function runPrompt(
  doublePressToConfirm: boolean,
  keys: string[],
  options?: RequestPermissionOptions,
): Promise<UnattributedDecision> {
  const { view, captured } = makeFakeView(doublePressToConfirm);
  const promise = presentInlinePermissionPrompt(
    view,
    "Permission Required",
    ASK,
    options,
  );
  for (const key of keys) {
    captured.component?.handleInput(key);
  }
  return promise;
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe("presentInlinePermissionPrompt", () => {
  it("renders inline (not as an overlay) with the request facts and hotkey labels", () => {
    const { view, captured } = makeFakeView(true);
    void presentInlinePermissionPrompt(view, "Permission Required", ASK);
    expect(captured.options).toEqual({ overlay: false });
    const text = captured.component?.render(80).join("\n") ?? "";
    expect(text).toContain("tool : read");
    expect(text).toContain("path : /repo/secret.txt");
    expect(text).toContain("Yes");
    expect(text).toContain("No, provide reason");
    expect(text).toContain("y");
    expect(text).toContain("r");
  });

  it("clips every rendered line to the terminal width", () => {
    const { view, captured } = makeFakeView(true);
    void presentInlinePermissionPrompt(
      view,
      "Permission Required",
      makeAsk(`~/.pi/agent/sessions/${"a".repeat(300)}`),
    );
    const width = 40;
    const lines = captured.component?.render(width) ?? [];
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(visibleWidth(line)).toBeLessThanOrEqual(width);
    }
  });

  describe("double-press to confirm (enabled)", () => {
    it("resolves approved on y, y", async () => {
      expect(await runPrompt(true, ["y", "y"])).toEqual({
        approved: true,
        state: "approved",
      });
    });

    it("does not resolve on a single armed press", async () => {
      const { view, captured } = makeFakeView(true);
      const promise = presentInlinePermissionPrompt(
        view,
        "Permission Required",
        ASK,
      );
      let settled = false;
      void promise.then(() => {
        settled = true;
      });
      captured.component?.handleInput("y");
      await Promise.resolve();
      expect(settled).toBe(false);
      const text = captured.component?.render(80).join("\n") ?? "";
      expect(text).toContain("Press y again to approve.");
    });

    it("resolves denied on n, n", async () => {
      expect(await runPrompt(true, ["n", "n"])).toEqual({
        approved: false,
        state: "denied",
      });
    });
  });

  describe("double-press to confirm (disabled)", () => {
    it("resolves approved on a single y", async () => {
      expect(await runPrompt(false, ["y"])).toEqual({
        approved: true,
        state: "approved",
      });
    });
  });

  describe("navigation and escape", () => {
    it("resolves the highlighted option on enter", async () => {
      // y -> s -> n, then enter
      expect(await runPrompt(true, [ARROW_DOWN, ARROW_DOWN, ENTER])).toEqual({
        approved: false,
        state: "denied",
      });
    });

    it("denies on escape at the decision step", async () => {
      expect(await runPrompt(true, [ESCAPE])).toEqual({
        approved: false,
        state: "denied",
      });
    });

    it("never decides on a stray paste at the decision step", async () => {
      const { view, captured } = makeFakeView(false);
      const promise = presentInlinePermissionPrompt(view, "Title", ASK);
      let settled = false;
      void promise.then(() => {
        settled = true;
      });

      captured.component?.handleInput(paste("y"));
      captured.component?.handleInput(paste("some copied text"));
      await Promise.resolve();

      expect(settled).toBe(false);
      captured.component?.handleInput("n");
      expect(await promise).toEqual({ approved: false, state: "denied" });
    });
  });

  describe("deny with reason", () => {
    it("collects a typed reason and resolves denied_with_reason", async () => {
      const decision = await runPrompt(false, ["r", "n", "o", "p", "e", ENTER]);
      expect(decision).toEqual({
        approved: false,
        state: "denied_with_reason",
        denialReason: "nope",
      });
    });

    it("rejects an empty reason and shows an error, then accepts a real one", async () => {
      const { view, captured } = makeFakeView(false);
      const promise = presentInlinePermissionPrompt(view, "T", ASK);
      captured.component?.handleInput("r"); // opens reason step
      captured.component?.handleInput(ENTER); // empty submit -> rejected
      const text = captured.component?.render(80).join("\n") ?? "";
      expect(text).toContain("A reason is required.");
      captured.component?.handleInput("x");
      captured.component?.handleInput(ENTER);
      expect(await promise).toEqual({
        approved: false,
        state: "denied_with_reason",
        denialReason: "x",
      });
    });

    it("supports backspace while editing the reason", async () => {
      const decision = await runPrompt(false, [
        "r",
        "a",
        "b",
        "\u007f", // backspace removes "b"
        ENTER,
      ]);
      expect(decision).toEqual({
        approved: false,
        state: "denied_with_reason",
        denialReason: "a",
      });
    });

    it("accepts pasted text into the reason", async () => {
      expect(
        await runPrompt(false, ["r", paste("pasted text"), ENTER]),
      ).toEqual({
        approved: false,
        state: "denied_with_reason",
        denialReason: "pasted text",
      });
    });

    it("flattens a multi-line paste into one readable line", async () => {
      expect(
        await runPrompt(false, [
          "r",
          paste("denied because it touches\n~/.ssh"),
          ENTER,
        ]),
      ).toEqual({
        approved: false,
        state: "denied_with_reason",
        denialReason: "denied because it touches ~/.ssh",
      });
    });

    it("keeps a pasted reason on one row, however long it is", () => {
      const { view, captured } = makeFakeView(false);
      void presentInlinePermissionPrompt(view, "Title", ASK);
      captured.component?.handleInput("r");
      const before = captured.component?.render(40) ?? [];

      // "q" appears nowhere else in this render; "x" would match `secret.txt`.
      captured.component?.handleInput(paste("q".repeat(500)));
      const after = captured.component?.render(40) ?? [];

      expect(after).toHaveLength(before.length);
      expect(after.join("\n")).toContain("qqq");
      for (const line of after) {
        expect(visibleWidth(line)).toBeLessThanOrEqual(40);
      }
    });

    it("drops the expand key instead of typing it into the reason", async () => {
      const { view, captured, setToolsExpanded } = makeFakeView(false);
      const promise = presentInlinePermissionPrompt(view, "Title", ASK);

      captured.component?.handleInput("r");
      captured.component?.handleInput("a");
      captured.component?.handleInput(CTRL_O);
      captured.component?.handleInput(ENTER);

      expect(await promise).toEqual({
        approved: false,
        state: "denied_with_reason",
        denialReason: "a",
      });
      expect(setToolsExpanded).not.toHaveBeenCalled();
    });

    it("navigates back to the decision step on escape from the reason step", async () => {
      // r opens reason, esc returns to decision, then n deny
      expect(await runPrompt(false, ["r", ESCAPE, "n"])).toEqual({
        approved: false,
        state: "denied",
      });
    });
  });

  describe("requestPermissionDecision dispatch", () => {
    it("renders the inline dialog in TUI mode", async () => {
      const { view, captured } = makeFakeView(true);
      const promise = requestPermissionDecision(view, "Title", ASK);
      expect(captured.component).toBeDefined();
      captured.component?.handleInput("y");
      captured.component?.handleInput("y");
      expect(await promise).toEqual({
        approved: true,
        state: "approved",
        decidedBy: { kind: "user", via: "dialog" },
      });
    });

    it("bounds a pathological forwarded ask instead of filling the viewport", () => {
      const { view, captured } = makeFakeView(true);
      const body = Array.from(
        { length: 200 },
        () => "- a finding line about some module in the codebase",
      ).join("\n");
      const command = `@'\n${body}\n'@ | Out-File -FilePath report.md`;

      void presentInlinePermissionPrompt(
        view,
        "Permission Required (Subagent)",
        makePromptPayload({
          kind: "forwarded",
          request: {
            ...makePromptPayload().request,
            requester: {
              agentName: "scout",
              forwarded: true,
              sessionId: "abc123",
            },
            surface: "bash",
            toolName: null,
            value: command,
            matchedPattern: null,
          },
          evidence: [{ label: "requested", text: command, detail: null }],
        }),
      );
      const lines = captured.component?.render(120) ?? [];

      // The same ask renders 205 rows through the unbounded flat message.
      expect(lines.length).toBeLessThanOrEqual(
        DEFAULT_RENDER_BUDGET.maxRows + DECISION_CHROME_ROWS,
      );
      expect(lines).toContain("subagent  : scout · session abc123");
    });

    it("falls back to the select flow outside TUI mode", async () => {
      const custom = vi.fn();
      const select = vi.fn().mockResolvedValue("Yes");
      const view = makeView("rpc", true, {
        select,
        input: vi.fn(),
        custom,
      });

      const decision = await requestPermissionDecision(view, "Title", ASK);

      expect(custom).not.toHaveBeenCalled();
      expect(select).toHaveBeenCalledWith(
        "Title\ntool : read\npath : /repo/secret.txt",
        expect.any(Array),
        { timeout: undefined },
      );
      expect(decision).toEqual({
        approved: true,
        state: "approved",
        decidedBy: { kind: "user", via: "select" },
      });
    });

    it("attributes a denial to the surface the human answered on", async () => {
      const select = vi.fn().mockResolvedValue("No");
      const view = makeView("rpc", true, {
        select,
        input: vi.fn(),
        custom: vi.fn(),
      });

      const decision = await requestPermissionDecision(view, "Title", ASK);

      // The denial is the human's, and which surface they used is what
      // separates "the operator declined" from "a prompt they never saw".
      expect(decision).toEqual({
        approved: false,
        state: "denied",
        decidedBy: { kind: "user", via: "select" },
      });
    });
  });

  describe("approve-for-session scope (forwarded asks)", () => {
    const options: RequestPermissionOptions = {
      sessionScope: {
        subagentLabel: "This subagent only",
        servingSessionLabel: "The whole session",
      },
    };

    it("commits the subagent scope by default", async () => {
      expect(await runPrompt(false, ["s", ENTER], options)).toEqual({
        approved: true,
        state: "approved_for_session",
      });
    });

    it("commits the serving-session scope when the second option is chosen", async () => {
      expect(await runPrompt(false, ["s", ARROW_DOWN, ENTER], options)).toEqual(
        { approved: true, state: "approved_for_serving_session" },
      );
    });
  });

  describe("tool expansion", () => {
    const scopeOptions: RequestPermissionOptions = {
      sessionScope: {
        subagentLabel: "This subagent only",
        servingSessionLabel: "The whole session",
      },
    };

    it("toggles tool expansion without settling the decision", async () => {
      const { view, captured, getToolsExpanded, setToolsExpanded } =
        makeFakeView(true);
      const promise = presentInlinePermissionPrompt(view, "Title", ASK);
      let settled = false;
      void promise.then(() => {
        settled = true;
      });

      captured.component?.handleInput(CTRL_O);
      await Promise.resolve();
      expect(setToolsExpanded).toHaveBeenNthCalledWith(1, true);
      expect(settled).toBe(false);

      captured.component?.handleInput(CTRL_O);
      await Promise.resolve();
      expect(setToolsExpanded).toHaveBeenNthCalledWith(2, false);
      expect(settled).toBe(false);
      expect(getToolsExpanded).toHaveBeenCalledTimes(2);

      captured.component?.handleInput("y");
      captured.component?.handleInput("y");
      // Unattributed: the inline component states the outcome, and the
      // dispatcher above it names the surface the human answered on.
      expect(await promise).toEqual({ approved: true, state: "approved" });
    });

    it("toggles during the scope step without committing the grant", async () => {
      const { view, captured, setToolsExpanded } = makeFakeView(false);
      const promise = presentInlinePermissionPrompt(
        view,
        "Title",
        ASK,
        scopeOptions,
      );

      captured.component?.handleInput("s"); // decision -> scope
      captured.component?.handleInput(CTRL_O);
      expect(setToolsExpanded).toHaveBeenNthCalledWith(1, true);

      captured.component?.handleInput(ENTER);
      expect(await promise).toEqual({
        approved: true,
        state: "approved_for_session",
      });
    });

    it("expands the dialog to the complete request and back", () => {
      const { view, captured, setToolsExpanded } = makeFakeView(true, CTRL_O, {
        maxRows: 24,
        fieldMaxWidth: 10,
      });
      void presentInlinePermissionPrompt(
        view,
        "Title",
        makeAsk("/repo/a/very/long/secret.txt"),
      );
      const bounded = captured.component?.render(120) ?? [];
      expect(bounded).toContain("path : /repo/a/ve…");
      expect(bounded.at(-1)).toContain("ctrl+o full request");

      captured.component?.handleInput(CTRL_O);
      const expanded = captured.component?.render(120) ?? [];
      expect(expanded).toContain("path : /repo/a/very/long/secret.txt");
      expect(expanded.at(-1)).toContain("ctrl+o collapse");
      // The host's own tool expansion still follows the same keystroke (#642).
      expect(setToolsExpanded).toHaveBeenCalledWith(true);

      captured.component?.handleInput(CTRL_O);
      expect(captured.component?.render(120)).toEqual(bounded);
    });

    it("advertises the affordance only when the render left something out", () => {
      const { view, captured } = makeFakeView(true);
      void presentInlinePermissionPrompt(view, "Title", ASK);

      expect(captured.component?.render(120).at(-1)).not.toContain("ctrl+o");
    });

    it("does not intercept the expand key while a denial reason is typed", async () => {
      // Bound to a printable key on purpose: the default Ctrl+O is a control
      // character the reason editor rejects anyway, so it cannot discriminate.
      const { view, captured, setToolsExpanded } = makeFakeView(false, "e");
      const promise = presentInlinePermissionPrompt(view, "Title", ASK);

      captured.component?.handleInput("r"); // decision -> reason
      captured.component?.handleInput("e"); // typed literally, not an app action
      captured.component?.handleInput(ENTER);

      expect(await promise).toEqual({
        approved: false,
        state: "denied_with_reason",
        denialReason: "e",
      });
      expect(setToolsExpanded).not.toHaveBeenCalled();
    });
  });
});

  describe("ask timeout (TUI timer)", () => {
    it("auto-denies with timedOut markers once askTimeoutMs elapses", async () => {
      vi.useFakeTimers();
      try {
        const { view } = makeFakeView(false, CTRL_O, DEFAULT_RENDER_BUDGET, 1000);
        const promise = presentInlinePermissionPrompt(view, "T", ASK);
        let settled = false;
        void promise.then(() => {
          settled = true;
        });
        await vi.advanceTimersByTimeAsync(999);
        expect(settled).toBe(false);
        await vi.advanceTimersByTimeAsync(1);
        expect(await promise).toMatchObject({
          approved: false,
          state: "denied",
          timedOut: true,
          confirmationUnavailable: true,
        });
      } finally {
        vi.useRealTimers();
      }
    });

    it("does not time out when askTimeoutMs is 0 (waits indefinitely)", async () => {
      vi.useFakeTimers();
      try {
        const { view } = makeFakeView(false); // askTimeoutMs defaults to 0
        const promise = presentInlinePermissionPrompt(view, "T", ASK);
        let settled = false;
        void promise.then(() => {
          settled = true;
        });
        await vi.advanceTimersByTimeAsync(60_000);
        expect(settled).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it("clears the timer when the user decides before the deadline", async () => {
      vi.useFakeTimers();
      try {
        const { view, captured } = makeFakeView(false, CTRL_O, DEFAULT_RENDER_BUDGET, 1000);
        const promise = presentInlinePermissionPrompt(view, "T", ASK);
        captured.component?.handleInput("y"); // single press (no double-press)
        expect(await promise).toEqual({ approved: true, state: "approved" });
        // The timer must have been cleared — no late re-settle crash observable,
        // and advancing past the deadline leaves the settled value intact.
        await vi.advanceTimersByTimeAsync(2000);
        await expect(promise).resolves.toEqual({
          approved: true,
          state: "approved",
        });
      } finally {
        vi.useRealTimers();
      }
    });
  });
