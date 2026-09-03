import {
  DEFAULT_WEBUI_MODEL_IDS,
  THINKING_LEVELS,
  serviceableModelIds,
  modelServiceable,
  resolveModel,
  ALL_PROVIDERS_AVAILABLE,
  type ModelProviderAvailability,
} from "../model/pi-models.ts";

export const NON_INTERACTIVE_THINKING_LEVEL = "xhigh";
export const NON_INTERACTIVE_FAST_MODE = false;
export const STRATEGIC_THINKING_LEVEL = "high";

const STRATEGIC_INTENT =
  /\b(?:strateg(?:y|ic)|executive|recommend(?:ation)?|prioriti[sz]e|decision|trade-?offs?|scenario|risk|plan|brief|synthesi[sz]e|compare|evaluate)\b/i;
const MULTI_SOURCE_HINT =
  /\b(?:calendar|e-?mail|gmail|notion|clarify|crm|analytics|metrics|transcripts?|slack|public|web|market|accounts?|customers?)\b/gi;
const EXPLICIT_MULTI_SOURCE =
  /\b(?:across (?:our )?sources|everything we know|internal and public|multiple sources|triangulate)\b/i;
const PUBLIC_RESEARCH =
  /\b(?:deep research|public research|market research|competitive (?:research|analysis)|research (?:the )?(?:market|competitors?|industry))\b/i;
const ACCOUNT_SYNTHESIS =
  /\b(?:(?:account|customer) (?:health|brief|overview)|what should I know about (?:the )?(?:account|customer))\b/i;

export function strategicThinkingLevel(text: string | undefined): typeof STRATEGIC_THINKING_LEVEL | undefined {
  const bounded = text?.slice(0, 8_192) ?? "";
  if (!bounded) return undefined;
  if (PUBLIC_RESEARCH.test(bounded) || ACCOUNT_SYNTHESIS.test(bounded)) return STRATEGIC_THINKING_LEVEL;
  if (!STRATEGIC_INTENT.test(bounded)) return undefined;
  const sourceCount = new Set((bounded.match(MULTI_SOURCE_HINT) ?? []).map((value) => value.toLowerCase())).size;
  return sourceCount >= 2 || EXPLICIT_MULTI_SOURCE.test(bounded) ? STRATEGIC_THINKING_LEVEL : undefined;
}

export function resolveTurnFastMode(
  requested: boolean | undefined,
  humanTurn: boolean,
  interactiveDefault: boolean,
): boolean | undefined {
  if (typeof requested === "boolean") return requested;
  return humanTurn && interactiveDefault ? true : undefined;
}

export function turnModelOptions(input: {
  triggered?: boolean;
  thinkingLevel?: string;
  fastMode?: boolean;
  text?: string;
}): {
  thinkingLevel?: string;
  fastMode?: boolean;
} {
  let thinkingLevel = input.thinkingLevel;
  if (!thinkingLevel && input.triggered) thinkingLevel = NON_INTERACTIVE_THINKING_LEVEL;
  if (!thinkingLevel) thinkingLevel = strategicThinkingLevel(input.text);
  let fastMode = input.fastMode;
  if (typeof fastMode !== "boolean" && input.triggered) fastMode = NON_INTERACTIVE_FAST_MODE;
  return {
    ...(thinkingLevel ? { thinkingLevel } : {}),
    ...(typeof fastMode === "boolean" ? { fastMode } : {}),
  };
}

export function webTurnRuntimeModelRefusal(
  runtimeModelId: string,
  orgModelId: string,
  configuredWebuiModels: readonly string[] | null | undefined,
): string | null {
  if (!configuredWebuiModels?.length) return null;
  if (runtimeModelId === orgModelId) return null;
  return configuredWebuiModels.includes(runtimeModelId) ? null : "that model is not enabled for the web UI";
}

export function validateWebTurnModelOptions(
  input: { model?: string; thinkingLevel?: string },
  enabledModels: readonly string[] | null,
  providers: ModelProviderAvailability = ALL_PROVIDERS_AVAILABLE,
): string | null {
  const enabled = enabledModels?.length ? enabledModels : DEFAULT_WEBUI_MODEL_IDS;
  const allowedModels = serviceableModelIds(enabled, providers);
  if (input.model && !allowedModels.includes(input.model)) {
    return resolveModel(input.model) && !modelServiceable(input.model, providers)
      ? "that model isn't available on this deployment (its provider isn't configured)"
      : "that model is not enabled for the web UI";
  }
  if (input.thinkingLevel && !(THINKING_LEVELS as readonly string[]).includes(input.thinkingLevel))
    return "unsupported thinking level";
  return null;
}
