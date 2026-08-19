/**
 * Config type + defaults for the `command-safety-judge` authorizer link.
 *
 * The judge consults a smart model (default: glm-5.2, fallback: deepseek-v4-pro)
 * at its highest `reasoning` level to rule on an `ask`. Unlike the deny-first
 * typo reviewer, this judge is allow-capable and reasons about the whole
 * operation, returning one of four verdicts (deny / suggest / allow / defer).
 */

export type ReasoningLevel =
  | "minimal"
  | "low"
  | "medium"
  | "high"
  | "xhigh"
  | "max";

export interface CommandSafetyJudgeRawConfig {
  /** Primary model provider (e.g. "zai"). */
  provider?: string;
  /** Primary model id (e.g. "glm-5.2"). */
  model?: string;
  /** Fallback provider when the primary model is unavailable. */
  fallbackProvider?: string;
  /** Fallback model id (e.g. "deepseek-v4-pro"). */
  fallbackModel?: string;
  /** Highest reasoning level; clamped to what the model supports. Default "max". */
  reasoning?: ReasoningLevel;
  /** System prompt guiding the verdict. Defaults to a built-in prompt. */
  instructions?: string;
  /** Per-call timeout (ms). Default 30000. */
  timeoutMs?: number;
  /** Path globs whose asks bypass the LLM and defer straight to the human. */
  manualConfirmGlobs?: string[];
}

/**
 * The resolved config the judge reads at each ask. All fields are concrete
 * (no `undefined`) so the judge logic has no nullable drift.
 */
export interface CommandSafetyJudgeConfig {
  provider: string;
  model: string;
  fallbackProvider?: string;
  fallbackModel?: string;
  reasoning: ReasoningLevel;
  instructions: string;
  timeoutMs: number;
  /** Path globs whose asks bypass the LLM and defer straight to the human. */
  manualConfirmGlobs: readonly string[];
}

/** Default reasoning level — the model's top mode, clamped at call time. */
export const DEFAULT_REASONING: ReasoningLevel = "max";

/** Default per-call timeout. */
export const DEFAULT_TIMEOUT_MS = 30000;

/** Default model — glm-5.2 (strong, supports `max` reasoning). */
export const DEFAULT_PROVIDER = "zai";
export const DEFAULT_MODEL = "glm-5.2";

/** Default fallback — deepseek-v4-pro (strong, supports `max`). */
export const DEFAULT_FALLBACK_PROVIDER = "deepseek";
export const DEFAULT_FALLBACK_MODEL = "deepseek-v4-pro";

/** Built-in system prompt (used when config omits `instructions`). */
export const DEFAULT_INSTRUCTIONS = [
  "你是命令安全审查员（command-safety-judge）。给定一个需要授权的操作（bash 命令、文件读写、MCP 调用等），判断它是否安全。",
  "",
  "安全模型分层：硬性 deny 规则（敏感文件、破坏性命令）已在你的判断之前由规则引擎拦截，能到达你的 ask 都没命中 deny 硬规则。所以你的职责是判断这些「灰色地带」操作：",
  "",
  "判断优先级（务必按顺序）：",
  "1. deny：操作有害（数据丢失、敏感信息泄露、破坏性覆盖、明显误操作）",
  "2. suggest：存在更简单/安全的免授权替代方案（如改用 read/grep/ls、serena MCP 编辑代码、temp 目录代替 rm）。只要有明显更优方式，优先 suggest 而非 defer",
  "3. allow：操作安全且常规（只读、临时文件、agent 自己的项目文件、常见构建/测试/运行命令）",
  "4. defer：确实拿不准且无更优免授权方式，才转交人工",
  "",
  "关键原则：",
  "- 偏向 allow/suggest，减少对用户打扰（这些操作用户 95% 会批准）",
  "- 但对真正危险的操作必须 deny（宁可错杀不可放过）",
  "- 免授权替代方案要具体可执行（如「改用 grep -r pattern dir 代替 cat 逐个文件」）",
].join("\n");

/**
 * Resolve a raw (possibly partial) config into a concrete one, applying the
 * built-in defaults. Returns `undefined` when neither provider nor model is
 * configured (the judge stays inert, matching the opt-in model).
 */
export function resolveCommandSafetyConfig(
  raw: CommandSafetyJudgeRawConfig | undefined,
): CommandSafetyJudgeConfig | undefined {
  if (!raw) return undefined;
  const provider = raw.provider ?? DEFAULT_PROVIDER;
  const model = raw.model ?? DEFAULT_MODEL;
  return {
    provider,
    model,
    fallbackProvider: raw.fallbackProvider ?? DEFAULT_FALLBACK_PROVIDER,
    fallbackModel: raw.fallbackModel ?? DEFAULT_FALLBACK_MODEL,
    reasoning: raw.reasoning ?? DEFAULT_REASONING,
    instructions: raw.instructions ?? DEFAULT_INSTRUCTIONS,
    timeoutMs: raw.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    manualConfirmGlobs: raw.manualConfirmGlobs ?? [],
  };
}
