/**
 * Feature 5: deny-storm alerting — a sliding-window burst detector for enforced
 * denials. When `maxDenials` denials occur within `windowMs`, `onAlert` fires
 * once (cooldown: the window resets, so the next burst alerts again).
 * Fail-safe: disabled config, non-positive thresholds, or a throwing onAlert
 * never break the caller.
 */
export interface DenyStormDeps {
  enabled: () => boolean;
  maxDenials: () => number;
  windowMs: () => number;
  /** Called once per detected burst with the deny count that triggered it. */
  onAlert: (count: number) => void;
}

export class DenyStormMonitor {
  private window: number[] = [];
  constructor(private readonly deps: DenyStormDeps) {}

  recordDenial(now: number = Date.now()): void {
    try {
      if (!this.deps.enabled()) {
        return;
      }
      const maxDenials = this.deps.maxDenials();
      const windowMs = this.deps.windowMs();
      if (!(maxDenials > 0) || !(windowMs > 0)) {
        return;
      }
      this.window = this.window.filter((t) => now - t <= windowMs);
      this.window.push(now);
      if (this.window.length >= maxDenials) {
        const count = this.window.length;
        this.window = []; // cooldown: one alert per burst
        this.deps.onAlert(count);
      }
    } catch {
      // deny-storm alerting must never break the permission gate
    }
  }
}
