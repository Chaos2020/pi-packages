import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { getAgentDir, getPackageDir } from "@earendil-works/pi-coding-agent";
import { complete } from "@earendil-works/pi-ai";
import { warmBashParser } from "./access-intent/bash/parser";
import {
  DEFAULT_TIMEOUT_MS,
  type ModelJudgeConfig,
} from "./model-judge/config-schema";
import type { CompleteFn, ModelRegistryLike } from "./model-judge/model-review";
import { createTypoReviewer } from "./model-judge/typo-reviewer";
import {
  BUILTIN_SECRET_PATTERNS,
  compileSecretPatterns,
  redactAll,
  scanForSecrets,
} from "./secret-scan/patterns";
import { DenyStormMonitor } from "./deny-storm";
import { buildResolvedIntentFromMatchValues } from "./access-intent/input-normalizer";
import { AuthorizerRegistry } from "./authority/authorizer-registry";
import { AuthorizerSelection } from "./authority/authorizer-selection";
import {
  ForwardedRequestServer,
  type ServingPolicy,
} from "./authority/forwarded-request-server";
import { ForwardingManager } from "./authority/forwarding-manager";
import { PERMISSION_FORWARDING_TIMEOUT_MS } from "./authority/permission-forwarding";
import { requestPermissionDecision } from "./authority/permission-prompt-component";
import { PermissionPrompter } from "./authority/permission-prompter";
import { getServingSessionRegistry } from "./authority/serving-registry";
import { SubagentDetection } from "./authority/subagent-detection";
import { subscribeSubagentLifecycle } from "./authority/subagent-lifecycle-events";
import { getSubagentSessionRegistry } from "./authority/subagent-registry";
import { registerBuiltinToolInputFormatters } from "./builtin-tool-input-formatters";
import { registerPermissionSystemCommand } from "./config-modal";
import { getGlobalConfigPath } from "./config-paths";
import { ConfigStore } from "./config-store";
import { DecisionAudit } from "./decision-audit";
import { GateDecisionReporter } from "./decision-reporter";
import { isYoloModeEnabled } from "./extension-config";
import { computeExtensionPaths } from "./extension-paths";
import {
  AgentPrepHandler,
  PermissionGateHandler,
  SessionLifecycleHandler,
} from "./handlers";
import { GateRunner } from "./handlers/gates/runner";
import { SkillInputGatePipeline } from "./handlers/gates/skill-input-gate-pipeline";
import { ToolCallGatePipeline } from "./handlers/gates/tool-call-gate-pipeline";
import { createFailClosedToolCall } from "./handlers/tool-call-boundary";
import { pathFlavorForPlatform } from "./path/path-flavor";
import { PermissionManager } from "./permission-manager";
import { PermissionResolver } from "./permission-resolver";
import { PermissionSession } from "./permission-session";
import { LocalPermissionsService } from "./permissions-service";
import { PermissionServiceLifecycle } from "./service-lifecycle";
import { PermissionSessionLogger } from "./session-logger";
import { SessionRules } from "./session-rules";
import { ToolAccessExtractorRegistry } from "./tool-access-extractor-registry";
import { ToolInputFormatterRegistry } from "./tool-input-formatter-registry";

export default function piPermissionSystemExtension(pi: ExtensionAPI): void {
  const agentDir = getAgentDir();
  // getPackageDir() is Pi's own install dir; auto-allow it for read-only tools
  // so the agent can read Pi's bundled docs/examples regardless of layout.
  const paths = computeExtensionPaths(agentDir, getPackageDir());
  // The single process.platform read for the whole extension, resolved once
  // into the path-language flavor that every consumer shares (the session's
  // PathNormalizer, rule evaluation, and subagent detection). Interior modules
  // must not read process.platform (enforced by the eslint guard scoped to
  // src/) and never re-derive the win32 flavor — they receive this product.
  const hostFlavor = pathFlavorForPlatform(process.platform);
  const sessionRules = new SessionRules();
  const subagentRegistry = getSubagentSessionRegistry();
  // Process-global, like subagentRegistry: an in-process child reads it from a
  // separate jiti instance to learn whether its parent is draining its inbox.
  const servingRegistry = getServingSessionRegistry();
  // Single owner of subagent detection, shared across every consumer instead of
  // threading the (subagentSessionsDir, platform, registry) triple into each.
  const subagentDetection = new SubagentDetection({
    subagentSessionsDir: paths.subagentSessionsDir,
    flavor: hostFlavor,
    registry: subagentRegistry,
  });
  const formatterRegistry = new ToolInputFormatterRegistry();
  registerBuiltinToolInputFormatters(formatterRegistry);
  const accessExtractorRegistry = new ToolAccessExtractorRegistry();
  // One registry instance backs both the registerAuthorizer service surface and
  // AuthorizerSelection's chain resolution, so a registration is visible to
  // composition.
  const authorizerRegistry = new AuthorizerRegistry();

  // Both `configStore` and `session` are forward-declared so the logger's
  // lazy thunks can close over them without a cast or null-init holder.
  // TypeScript exempts closure captures from definite-assignment analysis;
  // all synchronous reads occur after the assignments below.
  // eslint-disable-next-line prefer-const -- forward-declared let; `const` requires an initializer
  let configStore: ConfigStore;
  // eslint-disable-next-line prefer-const -- forward-declared let; `const` requires an initializer
  let session: PermissionSession;

  // Constructed after the `configStore` forward declaration so the yolo reader
  // can close over it; the closure runs per check(), after configStore is
  // assigned below. yolo becomes a composition-stage ask→allow rewrite (#526).
  const permissionManager = new PermissionManager({
    agentDir,
    flavor: hostFlavor,
    isYoloEnabled: () => isYoloModeEnabled(configStore.current()),
  });

  const logger = new PermissionSessionLogger({
    globalLogsDir: paths.globalLogsDir,
    getConfig: () => configStore.current(),
    notify: (message) => session.notify(message),
  });

  configStore = new ConfigStore({
    agentDir,
    policyPaths: permissionManager,
    logger,
  });

  const prompter = new PermissionPrompter({ logger });

  const authorizerSelection = new AuthorizerSelection({
    detection: subagentDetection,
    events: pi.events,
    getPromptPreferences: () => ({
      doublePressToConfirm: configStore.current().doublePressToConfirm,
    }),
    requestPermissionDecision,
    forwardingDir: paths.forwardingDir,
    registry: subagentRegistry,
    servingRegistry,
    getForwardingTimeoutMs: () =>
      configStore.current().forwardingTimeoutMs ??
      PERMISSION_FORWARDING_TIMEOUT_MS,
    logger,
    prompter,
    // The published service is the narrow, session-scoped PermissionQuery a
    // chain link is handed (it routes bash/path at gate parity against the live
    // session cwd). A thunk because `permissionsService` is constructed below;
    // it resolves at session_start (activate), well after assignment.
    getPermissionQuery: () => permissionsService,
    // Same registry instance the registerAuthorizer service surface writes to,
    // resolved in config order at activation.
    authorizerRegistry,
    getAuthorizerChain: () => configStore.current().authorizerChain ?? [],
  });

  // Resolver composes the manager + session ruleset and owns the
  // access-path → path-values unwrap. Constructed here (before `session`) so
  // the forwarded-request server's ServingPolicy can resolve against it; the
  // service and gates below share this one instance.
  const resolver = new PermissionResolver(permissionManager, sessionRules);

  // Serving a forwarded request is resolution: resolve the child-fixed
  // ForwardedAccessIntent (ADR 0008) directly against the serving node's
  // composed ruleset, agent-scoped to the requester (§3) — the match values
  // are used as fixed by the child, never re-derived through this session's
  // PathNormalizer/cwd (#597).
  const servingPolicy: ServingPolicy = {
    resolve: (intent) =>
      resolver.resolve(
        buildResolvedIntentFromMatchValues(
          intent.surface,
          intent.matchValues,
          intent.principal.agentName,
        ),
      ),
  };

  const requestServer = new ForwardedRequestServer({
    forwardingDir: paths.forwardingDir,
    logger,
    policy: servingPolicy,
    escalator: authorizerSelection,
    // Records a whole-session grant into the same SessionRules the resolver and
    // gate runner read, so a serving-scope grant governs the parent and future
    // forwarded resolutions.
    recorder: sessionRules,
    registry: subagentRegistry,
  });

  session = new PermissionSession(
    paths,
    new ForwardingManager({
      detection: subagentDetection,
      forwarder: requestServer,
      serving: servingRegistry,
      logger,
    }),
    permissionManager,
    sessionRules,
    configStore,
    authorizerSelection,
    hostFlavor,
  );

  // refresh() must run after `session` is assigned: a debug-write IO failure
  // triggers the logger's notify sink — `session.notify(m)` — which no-ops
  // on the null context but requires `session` to be bound.
  // No ctx/trust decision exists at factory init, so withhold the project
  // scope (fail closed); session_start reloads with the real trust decision.
  configStore.refresh(undefined, false);

  const configPath = getGlobalConfigPath(agentDir);
  registerPermissionSystemCommand(pi, {
    config: configStore,
    configPath,
    getActiveAgentConfigRules: () =>
      permissionManager.getComposedConfigRules(
        session.lastKnownActiveAgentName ?? undefined,
      ),
  });

  const permissionsService = new LocalPermissionsService(
    resolver,
    session,
    formatterRegistry,
    accessExtractorRegistry,
    authorizerRegistry,
  );

  // Subscribe to @gotgenes/pi-subagents' child lifecycle events so child
  // sessions register/unregister without the core calling us (ADR 0002).
  const unsubSubagentLifecycle = subscribeSubagentLifecycle(
    pi.events,
    subagentRegistry,
  );

  // PermissionServiceLifecycle owns the process-global service publication:
  // activate() publishes (skipped for registered subagent children — see #302)
  // and emits ready; teardown() unsubscribes all session listeners and
  // unpublishes. Deferred to session_start because identifying a child
  // requires the session id from ctx, unavailable at factory-init time.
  const serviceLifecycle = new PermissionServiceLifecycle(
    permissionsService,
    subagentDetection,
    pi.events,
    [unsubSubagentLifecycle],
  );

  const toolRegistry = {
    getAll: () => pi.getAllTools(),
    getActive: () => pi.getActiveTools(),
    setActive: (names: string[]) => pi.setActiveTools(names),
  };

  const audit = new DecisionAudit();
  const lifecycle = new SessionLifecycleHandler(
    session,
    resolver,
    serviceLifecycle,
    logger,
    audit,
  );
  const agentPrep = new AgentPrepHandler(
    session,
    resolver,
    toolRegistry,
    () => {
      void warmBashParser();
    },
  );

  const reporter = new GateDecisionReporter(logger, pi.events);
  const denyStorm = new DenyStormMonitor({
    enabled: () => configStore.current().denyStorm?.enabled ?? false,
    maxDenials: () => configStore.current().denyStorm?.maxDenials ?? 5,
    windowMs: () => configStore.current().denyStorm?.windowMs ?? 60000,
    onAlert: (count) => {
      reporter.writeReviewLog("permission_request.deny_storm", { count });
      session.notify(
        `[pi-permission-system] Deny storm: ${count} denials within the window.`,
      );
    },
  });
  const gateRunner = new GateRunner(
    resolver,
    sessionRules,
    authorizerSelection,
    reporter,
    () => configStore.current().dryRun ?? false,
    () => denyStorm.recordDenial(),
    () => configStore.current().permissionMode,
  );
  const toolCallGatePipeline = new ToolCallGatePipeline(
    resolver,
    session,
    formatterRegistry,
    accessExtractorRegistry,
  );
  const skillInputGatePipeline = new SkillInputGatePipeline(resolver);
  const gates = new PermissionGateHandler(
    session,
    toolRegistry,
    toolCallGatePipeline,
    skillInputGatePipeline,
    gateRunner,
  );

  // Feature 2: register the built-in 'model-judge' authorizer when the config
  // provides a complete model mechanism. Inert unless named in authorizerChain.
  let modelJudgeRegistered = false;
  function registerModelJudge(ctx: unknown): void {
    if (modelJudgeRegistered) return;
    const mj = configStore.current().modelJudge;
    if (!mj?.provider || !mj.model || !mj.instructions) return;
    modelJudgeRegistered = true;
    const mjConfig: ModelJudgeConfig = {
      enabled: true,
      provider: mj.provider,
      model: mj.model,
      instructions: mj.instructions,
      typoPatterns: mj.typoPatterns ?? [],
      timeoutMs: mj.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    };
    const registry = (ctx as { modelRegistry?: ModelRegistryLike })
      .modelRegistry;
    authorizerRegistry.register(
      "model-judge",
      createTypoReviewer({
        getConfig: () => mjConfig,
        getRegistry: () => registry,
        complete: complete as unknown as CompleteFn,
      }),
    );
  }

  pi.on("session_start", (event, ctx) => {
    const result = lifecycle.handleSessionStart(event, ctx);
    registerModelJudge(ctx);
    return result;
  });
  pi.on("resources_discover", (event, ctx) =>
    lifecycle.handleResourcesDiscover(event, ctx),
  );
  pi.on("session_shutdown", () => lifecycle.handleSessionShutdown());
  pi.on("before_agent_start", (event, ctx) => agentPrep.handle(event, ctx));
  pi.on("input", (event, ctx) => gates.handleInput(event, ctx));
  pi.on(
    "tool_call",
    createFailClosedToolCall(
      (event, ctx) => gates.handleToolCall(event, ctx),
      reporter,
      audit,
      logger,
    ),
  );

  // Feature 3: secret detection in tool output (tool_result can modify result).
  function toolResultText(content: readonly unknown[]): string {
    return (content as { type?: string; text?: string }[])
      .filter((p) => p.type === "text" && typeof p.text === "string")
      .map((p) => p.text as string)
      .join("\n");
  }
  pi.on("tool_result", (event, _ctx) => {
    const sc = configStore.current().secretScan;
    if (!sc?.enabled) {
      return undefined;
    }
    if (sc.excludeTools?.includes(event.toolName)) {
      return undefined;
    }
    const text = toolResultText(event.content ?? []);
    if (!text) {
      return undefined;
    }
    const compiled = compileSecretPatterns([
      ...BUILTIN_SECRET_PATTERNS,
      ...(sc.patterns ?? []),
    ]);
    const hits = scanForSecrets(text, compiled);
    if (hits.length === 0) {
      return undefined;
    }
    const redacted = redactAll(text, hits);
    logger.review("permission_request.secret_detected", {
      tool: event.toolName,
      count: hits.length,
      patterns: hits.map((h) => h.pattern),
      action: sc.action ?? "deny",
      isError: event.isError,
    });
    if (sc.action === "alert") {
      return undefined;
    }
    const warning = `[pi-permission-system] Secret detected in tool output and redacted (${hits.length}): ${hits
      .map((h) => h.pattern)
      .join(", ")}\n`;
    return { content: [{ type: "text", text: warning + redacted }] };
  });
}
