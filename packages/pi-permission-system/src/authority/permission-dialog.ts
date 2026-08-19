import type { DecisionSource } from "#src/authority/decision-source";

export type PermissionDecisionState =
  | "approved"
  | "approved_for_session"
  | "approved_for_serving_session"
  | "denied"
  | "denied_with_reason";

export type PermissionPromptDecision = {
  approved: boolean;
  state: PermissionDecisionState;
  denialReason?: string;
  /**
   * True when the decision was made automatically by yolo mode rather than
   * by an interactive user prompt. Used by handlers to emit "auto_approved"
   * rather than "user_approved" in the permissions:decision broadcast.
   */
  autoApproved?: true;
  /**
   * True when no human ever ruled on this ask: either no live authority was
   * reachable at all (`DenyingAuthorizer`, a no-UI non-subagent session) or the
   * forwarding path gave up before reaching one (`ParentAuthorizer` — target
   * unresolvable, request undeliverable, target not serving, or no answer
   * within the timeout). Consumed by deriveResolution (the decision-event
   * resolution), the gate (block reason), and PermissionPrompter (review-entry
   * resolution) to emit "confirmation_unavailable" rather than a plain user
   * denial — a user who was never asked denied nothing (#719).
   */
  confirmationUnavailable?: true;
  /**
   * True when the ask was auto-denied because the user did not answer within
   * `askTimeoutMs` — the dialog (TUI timer or the RPC select/input timeout)
   * settled the ask as denied rather than hanging. Distinguishes a timeout
   * denial from an active user denial in logs and review entries (resolution
   * "ask_timeout"). Always accompanies `confirmationUnavailable`.
   */
  timedOut?: true;
  /**
   * What decided this request, stamped by the site that decided it.
   *
   * Required: every decision names its decider, and the type is what
   * guarantees it rather than a convention each producer has to remember — the
   * same discipline `PromptPermissionDetails.payload` carries (#726).
   */
  decidedBy: DecisionSource;
};

/**
 * A decision before its decider is known.
 *
 * The inner producers — the dialog's decision model, the `select`/`input`
 * fallback, the verdict mapper — state the outcome; which decider to attribute
 * it to is settled one layer up, at the site that chose the producer. The same
 * shape `GateBypass.decision` uses for the request id: a producer emits only
 * what it knows.
 */
export type UnattributedDecision = Omit<PermissionPromptDecision, "decidedBy">;

export interface PermissionDecisionUi {
  /**
   * Select an option. Passing pi's native `{ timeout }` dialog option resolves
   * `undefined` when no answer arrives in time; the caller treats that as a
   * timeout denial.
   */
  select(
    title: string,
    options: string[],
    opts?: { timeout?: number },
  ): Promise<string | undefined>;
  /**
   * Free-text input. Same native `{ timeout }` option and timeout-denial
   * handling as `select`.
   */
  input(
    title: string,
    placeholder?: string,
    opts?: { timeout?: number },
  ): Promise<string | undefined>;
}

const APPROVE_OPTION = "Yes";
const APPROVE_FOR_SESSION_OPTION = "Yes, for this session";
const DENY_OPTION = "No";
const DENY_WITH_REASON_OPTION = "No, provide reason";

export function normalizePermissionDenialReason(
  value: unknown,
): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function createDeniedPermissionDecision(
  denialReason?: string,
): UnattributedDecision {
  const normalizedReason = normalizePermissionDenialReason(denialReason);
  return normalizedReason
    ? {
        approved: false,
        state: "denied_with_reason",
        denialReason: normalizedReason,
      }
    : {
        approved: false,
        state: "denied",
      };
}

/**
 * The decision settled when an ask goes unanswered past `askTimeoutMs`: denied
 * by default — never allowed — with `timedOut` (plus
 * `confirmationUnavailable`) marking that no human actively ruled, so logs and
 * review entries can tell a timeout denial from a user denial.
 */
export function createTimedOutPermissionDecision(): UnattributedDecision {
  return {
    approved: false,
    state: "denied",
    denialReason: "permission ask timed out — denied by default",
    timedOut: true,
    confirmationUnavailable: true,
  };
}

export function isPermissionDecisionState(
  value: unknown,
): value is PermissionDecisionState {
  return (
    value === "approved" ||
    value === "approved_for_session" ||
    value === "approved_for_serving_session" ||
    value === "denied" ||
    value === "denied_with_reason"
  );
}

export interface RequestPermissionOptions {
  /** Override the "for this session" option label (e.g. to show the suggested pattern). */
  sessionLabel?: string;
  /**
   * Auto-deny the ask after this many milliseconds of no answer (pi's native
   * `{ timeout }` select/input parameter). `0` or `undefined` waits
   * indefinitely. A timed-out select resolves as a timeout denial rather than
   * a user dismissal.
   */
  askTimeoutMs?: number;
  /**
   * Forwarded asks only: when set, choosing the "for this session" option opens
   * a second select asking whether the grant applies to the requesting subagent
   * only (the least-privilege default) or the whole serving session.
   */
  sessionScope?: {
    subagentLabel: string;
    servingSessionLabel: string;
  };
}

export async function requestPermissionDecisionFromUi(
  ui: PermissionDecisionUi,
  title: string,
  message: string,
  options?: RequestPermissionOptions,
): Promise<UnattributedDecision> {
  const sessionOption = options?.sessionLabel ?? APPROVE_FOR_SESSION_OPTION;
  const decisionOptions = [
    APPROVE_OPTION,
    sessionOption,
    DENY_OPTION,
    DENY_WITH_REASON_OPTION,
  ] as const;

  const timeoutMs =
    options?.askTimeoutMs && options.askTimeoutMs > 0
      ? options.askTimeoutMs
      : undefined;

  const selected = await ui.select(`${title}\n${message}`, [...decisionOptions], {
    timeout: timeoutMs,
  });

  // A timed-out first select is a timeout denial; without an armed timeout,
  // `undefined` is the user dismissing the dialog (plain user denial).
  if (selected === undefined) {
    return timeoutMs === undefined
      ? createDeniedPermissionDecision()
      : createTimedOutPermissionDecision();
  }

  if (selected === APPROVE_OPTION) {
    return {
      approved: true,
      state: "approved",
    };
  }

  if (selected === sessionOption) {
    if (options?.sessionScope) {
      const scope = await ui.select(
        `${title}\nApply this session grant to:`,
        [options.sessionScope.subagentLabel, options.sessionScope.servingSessionLabel],
        { timeout: timeoutMs },
      );
      // A timed-out scope select must not fall back to an approval — deny.
      if (scope === undefined && timeoutMs !== undefined) {
        return createTimedOutPermissionDecision();
      }
      return {
        approved: true,
        // A cancelled scope select (undefined) falls back to the
        // least-privilege subagent scope.
        state:
          scope === options.sessionScope.servingSessionLabel
            ? "approved_for_serving_session"
            : "approved_for_session",
      };
    }
    return {
      approved: true,
      state: "approved_for_session",
    };
  }

  if (selected === DENY_WITH_REASON_OPTION) {
    const denialReason = normalizePermissionDenialReason(
      await ui.input(
        `${title}\nShare why this request was denied (optional).`,
        "Reason shown back to the agent",
        { timeout: timeoutMs },
      ),
    );

    return createDeniedPermissionDecision(denialReason);
  }

  return createDeniedPermissionDecision();
}
