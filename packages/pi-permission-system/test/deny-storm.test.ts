import { describe, expect, it, vi } from "vitest";
import { DenyStormMonitor } from "#src/deny-storm";

// Feature 5: deny-storm alerting — sliding-window burst detector.

function makeMonitor(overrides: {
  enabled?: () => boolean;
  maxDenials?: () => number;
  windowMs?: () => number;
  onAlert?: (count: number) => void;
} = {}) {
  const onAlert = overrides.onAlert ?? vi.fn();
  const monitor = new DenyStormMonitor({
    enabled: overrides.enabled ?? (() => true),
    maxDenials: overrides.maxDenials ?? (() => 3),
    windowMs: overrides.windowMs ?? (() => 1000),
    onAlert,
  });
  return { monitor, onAlert };
}

describe("feature 5: deny-storm alerting", () => {
  it("alerts once when maxDenials is reached within the window", () => {
    const { monitor, onAlert } = makeMonitor({ maxDenials: () => 3 });
    monitor.recordDenial(1000);
    monitor.recordDenial(1100);
    expect(onAlert).not.toHaveBeenCalled();
    monitor.recordDenial(1200); // reaches 3
    expect(onAlert).toHaveBeenCalledTimes(1);
    expect(onAlert).toHaveBeenCalledWith(3);
  });

  it("does not alert below the threshold", () => {
    const { monitor, onAlert } = makeMonitor({ maxDenials: () => 5 });
    for (let i = 0; i < 4; i++) {
      monitor.recordDenial(1000 + i);
    }
    expect(onAlert).not.toHaveBeenCalled();
  });

  it("expires old denials outside the window", () => {
    const { monitor, onAlert } = makeMonitor({
      maxDenials: () => 3,
      windowMs: () => 1000,
    });
    monitor.recordDenial(1000);
    monitor.recordDenial(1100);
    monitor.recordDenial(3000); // first two expired (3000-1000 > 1000)
    expect(onAlert).not.toHaveBeenCalled(); // only 1 in window
  });

  it("cooldown: after an alert, the next burst alerts again", () => {
    const { monitor, onAlert } = makeMonitor({ maxDenials: () => 3 });
    monitor.recordDenial(1000);
    monitor.recordDenial(1100);
    monitor.recordDenial(1200); // alert 1
    monitor.recordDenial(5000);
    monitor.recordDenial(5100);
    monitor.recordDenial(5200); // alert 2
    expect(onAlert).toHaveBeenCalledTimes(2);
  });

  it("disabled -> never alerts", () => {
    const { monitor, onAlert } = makeMonitor({ enabled: () => false });
    monitor.recordDenial(1000);
    monitor.recordDenial(1100);
    monitor.recordDenial(1200);
    expect(onAlert).not.toHaveBeenCalled();
  });

  it("a throwing onAlert never breaks recordDenial", () => {
    const { monitor } = makeMonitor({
      maxDenials: () => 1,
      onAlert: () => {
        throw new Error("notify down");
      },
    });
    expect(() => monitor.recordDenial(1000)).not.toThrow();
  });
});
