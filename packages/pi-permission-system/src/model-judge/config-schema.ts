/**
 * Feature 2: built-in model-judge config (zod). The `modelJudge` section of the
 * fork's config.json: provider/model/instructions/typoPatterns/timeoutMs.
 * Ported from pi-permission-model-judge (config-schema.ts).
 */
import { z } from "zod";

/** Default per-review model-call budget, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 5000;

export const modelJudgeConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: z.string().min(1),
  model: z.string().min(1),
  instructions: z.string().min(1),
  typoPatterns: z.array(z.string().min(1)).default([]),
  timeoutMs: z.number().int().positive().default(DEFAULT_TIMEOUT_MS),
});

export type ModelJudgeConfig = z.infer<typeof modelJudgeConfigSchema>;

export const DEFAULT_MODEL_JUDGE_CONFIG: ModelJudgeConfig = {
  enabled: false,
  provider: "",
  model: "",
  instructions: "",
  typoPatterns: [],
  timeoutMs: DEFAULT_TIMEOUT_MS,
};
