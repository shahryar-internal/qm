import { readFileSync, writeFileSync } from "node:fs";

const path = "/app/src/index.ts";
const before = "if (modelProviderConfigured === false) {";
const after = 'if (modelProviderConfigured === false && process.env.RISELY_CUSTOM_PROVIDER_READY !== "1") {';
const source = readFileSync(path, "utf8");
if (source.split(before).length !== 2) throw new Error("Expected exactly one custom-provider onboarding gate");
writeFileSync(path, source.replace(before, after));
