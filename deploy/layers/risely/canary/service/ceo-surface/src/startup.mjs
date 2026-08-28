import { activationRequirements } from "./constants.mjs";

export const productionStartup = Object.freeze({
  enabled: false,
  mode: "shadow",
  blockers: activationRequirements,
});

export function startProduction() {
  throw new Error(`CEO surface production startup is hard-disabled: ${activationRequirements.join(", ")}`);
}
