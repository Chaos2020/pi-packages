/**
 * Companion config loader — reads pi's standard extension config locations:
 * project `.pi/extensions/pi-permission-companion/config.json`, then the
 * global `~/.pi/agent/extensions/pi-permission-companion/config.json`, merged
 * shallowly with the project scope winning. Fail-safe: unreadable/invalid
 * config resolves to the empty config (every feature inert) plus issues.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { z } from "zod";

const EXTENSION_ID = "pi-permission-companion";

export interface ConfigIssue {
  path: string;
  message: string;
  sourcePath?: string;
}

const reasonLevelSchema = z
  .enum(["minimal", "low", "medium", "high", "xhigh", "max"])
  .meta({ description: "Reasoning level the judge model runs at." });

export const commandSafetyJudgeSchema = z
  .object({
    provider: z.string().min(1).optional(),
    model: z.string().min(1).optional(),
    fallbackProvider: z.string().min(1).optional(),
    fallbackModel: z.string().min(1).optional(),
    reasoning: reasonLevelSchema.optional(),
    instructions: z.string().min(1).optional(),
    timeoutMs: z.number().int().positive().optional(),
    manualConfirmGlobs: z.array(z.string().min(1)).optional(),
  })
  .meta({
    description:
      "The 'command-safety-judge' authorizer: an allow-capable LLM judge that rules on any `ask`. Inert unless 'command-safety-judge' is named in pi-permission-system's `authorizerChain`.",
  });

export const companionConfigSchema = z
  .object({
    commandSafetyJudge: commandSafetyJudgeSchema.optional(),
    secretScan: z
      .object({
        enabled: z.boolean().default(false),
        action: z.enum(["deny", "alert"]).default("deny"),
        patterns: z.array(z.string().min(1)).optional(),
        excludeTools: z.array(z.string().min(1)).default([]),
      })
      .optional(),
    agenticMirror: z
      .object({
        enabled: z.boolean().default(false),
        logDir: z.string().optional(),
      })
      .optional(),
    denyStorm: z
      .object({
        enabled: z.boolean().default(false),
        maxDenials: z.number().int().positive().default(20),
        windowMs: z.number().int().positive().default(60_000),
      })
      .optional(),
  })
  .meta({
    description:
      "pi-permission-companion config: command-safety-judge, secret scan, AgenticLogger mirror, deny-storm.",
  });

export type CompanionConfig = z.infer<typeof companionConfigSchema>;

export interface LoadConfigResult {
  config: CompanionConfig;
  issues: ConfigIssue[];
}

function readScope(
  sourcePath: string,
  issues: ConfigIssue[],
): Record<string, unknown> {
  if (!existsSync(sourcePath)) return {};
  try {
    const parsed: unknown = JSON.parse(readFileSync(sourcePath, "utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      issues.push({ path: "$", message: "config must be a JSON object", sourcePath });
      return {};
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    issues.push({
      path: "$",
      message: `unreadable JSON: ${error instanceof Error ? error.message : String(error)}`,
      sourcePath,
    });
    return {};
  }
}

export function loadCompanionConfig(cwd: string): LoadConfigResult {
  const issues: ConfigIssue[] = [];
  const candidates = isAbsolute(cwd) && existsSync(cwd)
    ? [
        join(cwd, ".pi", "extensions", EXTENSION_ID, "config.json"),
        join(
          homedir(),
          ".pi",
          "agent",
          "extensions",
          EXTENSION_ID,
          "config.json",
        ),
      ]
    : [join(homedir(), ".pi", "agent", "extensions", EXTENSION_ID, "config.json")];

  // Project scope wins per key (shallow merge), same as pi-permission-system.
  const merged: Record<string, unknown> = {};
  for (const sourcePath of candidates) {
    Object.assign(merged, readScope(sourcePath, issues));
  }

  const result = companionConfigSchema.safeParse(merged);
  if (!result.success) {
    for (const issue of result.error.issues) {
      issues.push({
        path: issue.path.join(".") || "$",
        message: issue.message,
      });
    }
    return { config: {}, issues };
  }
  return { config: result.data, issues };
}
