import { createProviderEffectProtocolHarness } from "./authority-harness.mjs";

export function createInertProviderEffectExecutionAuthorityForTesting(value) {
  return createProviderEffectProtocolHarness(value);
}
