import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  MODEL_PROVIDER_KEYS,
  localSandboxActive,
  mockHarnessWarning,
  validatePortalTrust,
  type ModelProvider,
  type QmConfig,
} from "../config.ts";
import { CliError, errMessage, step, warn } from "../log.ts";
import { capture, deploymentSecretValue, flyBin, isInvalidSecret, readEnvFile, which } from "../util.ts";
import { computedSecrets } from "../secrets.ts";

type ManifestObject = Record<string, unknown>;

function stripYamlComment(line: string): string {
  let quote = "";
  for (let index = 0; index < line.length; index++) {
    const char = line[index]!;
    if ((char === '"' || char === "'") && line[index - 1] !== "\\") quote = quote === char ? "" : quote || char;
    if (char === "#" && !quote && (index === 0 || /\s/.test(line[index - 1]!))) return line.slice(0, index);
  }
  return line;
}

function yamlScalar(value: string): unknown {
  const clean = value.trim();
  if (!clean) return {};
  if (clean === "true") return true;
  if (clean === "false") return false;
  if (clean === "null" || clean === "~") return null;
  if (/^-?\d+(?:\.\d+)?$/.test(clean)) return Number(clean);
  if (clean.startsWith("[") || clean.startsWith("{")) return yamlFlow(clean);
  if (clean.startsWith('"') && clean.endsWith('"')) return JSON.parse(clean) as unknown;
  if (clean.startsWith("'") && clean.endsWith("'")) return clean.slice(1, -1).replaceAll("''", "'");
  return clean;
}

function flowParts(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let depth = 0;
  let quote = "";
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (quote) {
      if (char === quote && (quote === "'" ? value[index + 1] !== "'" : value[index - 1] !== "\\")) quote = "";
      else if (quote === "'" && char === "'" && value[index + 1] === "'") index += 1;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "[" || char === "{") depth += 1;
    else if (char === "]" || char === "}") depth -= 1;
    else if (char === "," && depth === 0) {
      const part = value.slice(start, index).trim();
      if (!part) throw new Error("empty YAML flow item");
      parts.push(part);
      start = index + 1;
    }
    if (depth < 0) throw new Error("unbalanced YAML flow value");
  }
  if (quote || depth !== 0) throw new Error("unbalanced YAML flow value");
  const tail = value.slice(start).trim();
  if (tail) parts.push(tail);
  else if (parts.length) throw new Error("empty YAML flow item");
  return parts;
}

function flowPairColon(value: string): number {
  let depth = 0;
  let quote = "";
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (quote) {
      if (char === quote && (quote === "'" ? value[index + 1] !== "'" : value[index - 1] !== "\\")) quote = "";
      else if (quote === "'" && char === "'" && value[index + 1] === "'") index += 1;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === "[" || char === "{") depth += 1;
    else if (char === "]" || char === "}") depth -= 1;
    else if (char === ":" && depth === 0) return index;
  }
  return -1;
}

function yamlFlow(value: string): unknown {
  const sequence = value.startsWith("[");
  const close = sequence ? "]" : "}";
  if (!value.endsWith(close)) throw new Error("unbalanced YAML flow value");
  const parts = flowParts(value.slice(1, -1));
  if (sequence) return parts.map(yamlScalar);
  const mapped: ManifestObject = {};
  for (const part of parts) {
    const colon = flowPairColon(part);
    if (colon < 1) throw new Error("invalid YAML flow mapping");
    const rawKey = part.slice(0, colon).trim();
    const parsedKey = yamlScalar(rawKey);
    if (typeof parsedKey !== "string" || !parsedKey) throw new Error("invalid YAML flow mapping key");
    mapped[parsedKey] = yamlScalar(part.slice(colon + 1));
  }
  return mapped;
}

function parseSlackManifest(manifest: string): ManifestObject {
  try {
    const parsed = JSON.parse(manifest) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("manifest root must be a map");
    return parsed as ManifestObject;
  } catch (error) {
    if (manifest.trimStart().startsWith("{") || manifest.trimStart().startsWith("[")) throw error;
  }
  const lines = manifest
    .split(/\r?\n/)
    .map(stripYamlComment)
    .filter((line) => line.trim())
    .map((line) => ({ indent: line.length - line.trimStart().length, text: line.trim() }));
  const parseBlock = (start: number, indent: number): { value: unknown; next: number } => {
    const array = lines[start]?.text.startsWith("-") === true;
    const value: unknown[] | ManifestObject = array ? [] : {};
    let index = start;
    while (index < lines.length && lines[index]!.indent === indent) {
      const line = lines[index]!;
      if (array) {
        if (!line.text.startsWith("-")) throw new Error("mixed YAML sequence and mapping");
        const item = line.text.slice(1).trim();
        if (!item) {
          const nested = parseBlock(index + 1, lines[index + 1]?.indent ?? indent);
          (value as unknown[]).push(nested.value);
          index = nested.next;
          continue;
        }
        const pair = item.match(/^([^:]+):(?:\s+(.*))?$/);
        if (!pair) {
          (value as unknown[]).push(yamlScalar(item));
          index += 1;
          continue;
        }
        const object: ManifestObject = {};
        const key = pair[1]!.trim();
        if (pair[2] !== undefined) object[key] = yamlScalar(pair[2]);
        else if (lines[index + 1] && lines[index + 1]!.indent > indent) {
          const nested = parseBlock(index + 1, lines[index + 1]!.indent);
          object[key] = nested.value;
          index = nested.next - 1;
        } else object[key] = {};
        index += 1;
        while (index < lines.length && lines[index]!.indent > indent) {
          const nestedIndent = lines[index]!.indent;
          const nested = parseBlock(index, nestedIndent);
          if (!nested.value || typeof nested.value !== "object" || Array.isArray(nested.value))
            throw new Error("invalid YAML sequence mapping");
          Object.assign(object, nested.value);
          index = nested.next;
        }
        (value as unknown[]).push(object);
        continue;
      }
      const pair = line.text.match(/^([^:]+):(?:\s+(.*))?$/);
      if (!pair) throw new Error("invalid YAML mapping");
      const key = pair[1]!.trim();
      if (pair[2] !== undefined) {
        (value as ManifestObject)[key] = yamlScalar(pair[2]);
        index += 1;
        continue;
      }
      if (lines[index + 1] && lines[index + 1]!.indent > indent) {
        const nested = parseBlock(index + 1, lines[index + 1]!.indent);
        (value as ManifestObject)[key] = nested.value;
        index = nested.next;
      } else {
        (value as ManifestObject)[key] = {};
        index += 1;
      }
    }
    return { value, next: index };
  };
  if (!lines.length || lines[0]!.indent !== 0) throw new Error("manifest has no root mapping");
  const parsed = parseBlock(0, 0);
  if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value) || parsed.next !== lines.length)
    throw new Error("manifest YAML is malformed");
  return parsed.value as ManifestObject;
}

export function slackManifestBotScopes(manifest: string): string[] {
  try {
    const parsed = parseSlackManifest(manifest) as { oauth_config?: { scopes?: { bot?: unknown } } };
    return Array.isArray(parsed.oauth_config?.scopes?.bot)
      ? parsed.oauth_config.scopes.bot.filter((scope): scope is string => typeof scope === "string")
      : [];
  } catch {
    return [];
  }
}

export function missingSlackAgentCapabilities(manifest: string): string[] {
  const requiredEvents = [
    "message.im",
    "app_home_opened",
    "app_context_changed",
    "assistant_thread_started",
    "assistant_thread_context_changed",
    "agent_session_stopped",
    "agent_session_title_changed",
  ];
  try {
    const parsed = parseSlackManifest(manifest) as {
      features?: {
        agent_view?: { agent_description?: string; suggested_prompts?: unknown[] };
        app_home?: { messages_tab_enabled?: boolean; messages_tab_read_only_enabled?: boolean };
      };
      settings?: {
        event_subscriptions?: { bot_events?: string[] };
        interactivity?: { is_enabled?: boolean };
      };
    };
    const missing: string[] = [];
    if (!parsed.features?.agent_view?.agent_description) missing.push("features.agent_view");
    if (!parsed.features?.agent_view?.suggested_prompts?.length) missing.push("features.agent_view.suggested_prompts");
    if (parsed.features?.app_home?.messages_tab_enabled !== true)
      missing.push("features.app_home.messages_tab_enabled");
    if (parsed.features?.app_home?.messages_tab_read_only_enabled !== false)
      missing.push("features.app_home.messages_tab_read_only_enabled=false");
    if (parsed.settings?.interactivity?.is_enabled !== true) missing.push("settings.interactivity.is_enabled");
    const events = parsed.settings?.event_subscriptions?.bot_events ?? [];
    for (const event of requiredEvents) if (!events.includes(event)) missing.push(`event:${event}`);
    return missing;
  } catch {
    return ["valid JSON or YAML manifest"];
  }
}

export function requiredSlackScopes(configDir?: string): string[] {
  const local = configDir ? join(configDir, "slack-app-manifest.yml") : undefined;
  const sourceTemplate = new URL("../../templates/slack-manifest.json", import.meta.url);
  const packagedTemplate = new URL("../../../templates/slack-manifest.json", import.meta.url);
  const templatePath = existsSync(sourceTemplate) ? sourceTemplate : packagedTemplate;
  const path = local && existsSync(local) ? local : templatePath;
  const manifest = readFileSync(path, "utf8");
  const scopes = slackManifestBotScopes(manifest);
  if (scopes.length === 0) {
    throw new CliError(
      `no bot scopes parse from ${path} — fix oauth_config.scopes.bot in the manifest (doctor cannot verify Slack scopes against an empty list)`,
    );
  }
  if (path === local) {
    const behind = slackManifestBotScopes(readFileSync(templatePath, "utf8")).filter(
      (scope) => !scopes.includes(scope),
    );
    if (behind.length)
      warn(
        `slack-app-manifest.yml lacks bot scopes the current slack plugin uses (${behind.join(", ")}) — merge them from the CLI's template and reinstall the app`,
      );
  }
  return scopes;
}

function validateSlackAgentManifest(configDir?: string): void {
  const local = configDir ? join(configDir, "slack-app-manifest.yml") : undefined;
  const sourceTemplate = new URL("../../templates/slack-manifest.json", import.meta.url);
  const packagedTemplate = new URL("../../../templates/slack-manifest.json", import.meta.url);
  const templatePath = existsSync(sourceTemplate) ? sourceTemplate : packagedTemplate;
  const path = local && existsSync(local) ? local : templatePath;
  const missing = missingSlackAgentCapabilities(readFileSync(path, "utf8"));
  if (missing.length) {
    throw new CliError(
      `Slack agent manifest is missing: ${missing.join(", ")} — merge the current template and reinstall the app`,
    );
  }
}

async function slackApi(
  url: string,
  init: { method?: string; headers: Record<string, string>; body?: string },
): Promise<{ res: Response; body: { ok?: boolean; error?: string; app_id?: string; manifest?: unknown } }> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
  } catch (e) {
    throw new CliError(`could not reach ${url}: ${errMessage(e)} — check network access (and any proxy) and retry`);
  }
  try {
    return {
      res,
      body: (await res.json()) as { ok?: boolean; error?: string; app_id?: string; manifest?: unknown },
    };
  } catch {
    throw new CliError(`${url} returned a non-JSON response (status ${res.status}) — Slack may be degraded; retry`);
  }
}

export async function slackCheck(
  botToken: string,
  appToken: string,
  configDir?: string,
  configToken?: string,
  appId?: string,
): Promise<void> {
  const auth = await slackApi("https://slack.com/api/auth.test", { headers: { authorization: `Bearer ${botToken}` } });
  if (!auth.res.ok || !auth.body.ok)
    throw new CliError(`Slack bot token rejected (${auth.body.error ?? auth.res.status})`);
  const granted = new Set(
    (auth.res.headers.get("x-oauth-scopes") ?? "")
      .split(",")
      .map((scope) => scope.trim())
      .filter(Boolean),
  );
  const missing = requiredSlackScopes(configDir).filter((scope) => !granted.has(scope));
  if (missing.length)
    throw new CliError(
      `Slack app is missing scopes: ${missing.join(", ")}; update from slack-app-manifest.yml and reinstall`,
    );
  validateSlackAgentManifest(configDir);
  if (configToken) {
    const installedAppId = appId?.trim() || auth.body.app_id;
    if (!installedAppId)
      throw new CliError(
        "Slack auth.test did not return app_id and SLACK_APP_ID is unset; installed Agent View cannot be verified",
      );
    const installed = await slackApi("https://slack.com/api/apps.manifest.export", {
      method: "POST",
      headers: { authorization: `Bearer ${configToken}`, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ app_id: installedAppId }).toString(),
    });
    if (!installed.res.ok || !installed.body.ok)
      throw new CliError(
        `Slack installed manifest could not be exported (${installed.body.error ?? installed.res.status})`,
      );
    const installedManifest =
      typeof installed.body.manifest === "string"
        ? installed.body.manifest
        : JSON.stringify(installed.body.manifest ?? null);
    const installedMissing = missingSlackAgentCapabilities(installedManifest);
    if (installedMissing.length)
      throw new CliError(
        `Slack installed app is missing: ${installedMissing.join(", ")} — update and reinstall the app before deploy`,
      );
  } else {
    warn(
      "SLACK_CONFIG_TOKEN is not available — the local manifest is valid, but installed Agent View events were not exported",
    );
  }
  const socket = await slackApi("https://slack.com/api/apps.connections.open", {
    method: "POST",
    headers: { authorization: `Bearer ${appToken}`, "content-type": "application/x-www-form-urlencoded" },
  });
  if (!socket.res.ok || !socket.body.ok)
    throw new CliError(`Slack app token rejected (${socket.body.error ?? socket.res.status})`);
}

export function localDoctorSecrets(configDir: string, envFile?: string): Map<string, string> {
  const path = resolve(envFile ?? join(configDir, ".env"));
  if (envFile && !existsSync(path)) throw new CliError(`--env-file not found: ${envFile}`);
  return existsSync(path) ? readEnvFile(path) : new Map();
}

export function requireFlyAuth(): void {
  if (!which(flyBin())) {
    throw new CliError(
      `flyctl not found on PATH — install it (https://fly.io/docs/flyctl/install/) and run \`fly auth login\``,
    );
  }
  try {
    capture(flyBin(), ["auth", "whoami"]);
  } catch (e) {
    throw new CliError(`fly auth whoami failed: ${errMessage(e)} — run \`fly auth login\``);
  }
}

export async function doctorCommon(
  config: QmConfig,
  secrets: Map<string, string>,
  opts: { requiredSecretValues?: boolean; configDir?: string } = {},
): Promise<void> {
  if (opts.requiredSecretValues) {
    const missing = computedSecrets(config)
      .filter((secret) => secret.required)
      .filter((secret) => {
        const value = deploymentSecretValue(secret.name, secrets.get(secret.name));
        return isInvalidSecret(secret.name, value);
      });
    if (missing.length)
      throw new CliError(
        `required secrets are missing or placeholders: ${missing.map((secret) => secret.name).join(", ")}`,
      );
    step("required local secret values: ok");
  }
  if (localSandboxActive(config)) {
    step("local Docker sandbox: configured");
  } else if (config.target === "aws") {
    step("AWS Lambda MicroVM sandbox: configured");
  } else if (config.sandbox?.app) {
    requireFlyAuth();
    try {
      capture(flyBin(), ["status", "-a", config.sandbox.app]);
    } catch (e) {
      throw new CliError(
        `fly status -a ${config.sandbox.app} failed: ${errMessage(e)} — does the sandbox app exist and can this account see it?`,
      );
    }
    step(`Fly sandbox ${config.sandbox.app}: ok`);
  } else {
    step("sandbox: not configured — agents cannot execute commands (HARNESS=mock turns only)");
  }

  if (config.services.includes("slack")) {
    const bot = deploymentSecretValue("SLACK_BOT_TOKEN", secrets.get("SLACK_BOT_TOKEN"));
    const app = deploymentSecretValue("SLACK_APP_TOKEN", secrets.get("SLACK_APP_TOKEN"));
    if (Boolean(bot) !== Boolean(app)) {
      throw new CliError(
        "Slack setup needs both SLACK_BOT_TOKEN and SLACK_APP_TOKEN, or neither when setup is deferred",
      );
    }
    if (bot && app) {
      await slackCheck(
        bot,
        app,
        opts.configDir,
        deploymentSecretValue("SLACK_CONFIG_TOKEN", secrets.get("SLACK_CONFIG_TOKEN")),
        deploymentSecretValue("SLACK_APP_ID", secrets.get("SLACK_APP_ID")),
      );
      if (opts.requiredSecretValues) {
        step("Slack tokens and manifest scopes: ok");
      } else if (config.target === "aws") {
        step("Slack tokens and manifest scopes: ok (verified the stored AWS secret values)");
      } else {
        step(
          "Slack tokens and manifest scopes: ok (verified the local .env values — Fly's staged secrets are write-only and may differ)",
        );
      }
    } else if (opts.requiredSecretValues) {
      step("Slack setup: deferred to the admin connector page");
    } else {
      warn(
        config.target === "aws"
          ? "SLACK_BOT_TOKEN/SLACK_APP_TOKEN are not in the AWS secret store yet — skipping the live Slack check"
          : "SLACK_BOT_TOKEN/SLACK_APP_TOKEN values are not available locally — skipping the live Slack check (secret names were verified on the Fly apps)",
      );
    }
  }
  if (config.services.includes("portal")) {
    validatePortalTrust(config, "config", opts.requiredSecretValues ? secrets : undefined);
    step(
      config.services.includes("auth")
        ? "built-in sign-in broker and email trust boundary: ok"
        : "portal OIDC client and tenant trust boundary: ok",
    );
  }
  if (config.services.includes("auth")) await authBrokerCheck(config, secrets, opts.requiredSecretValues === true);
  await baseModelCheck(config, secrets);
}

async function baseModelCheck(config: QmConfig, secrets: Map<string, string>): Promise<void> {
  const mockHarness = mockHarnessWarning(config);
  if (mockHarness) warn(mockHarness);
  const provider = config.modelProvider;
  if (!provider) {
    step("base model: no modelProvider set — an administrator supplies the key from the Admin page");
    return;
  }
  const name = MODEL_PROVIDER_KEYS[provider];
  const key = deploymentSecretValue(name, secrets.get(name));
  if (!key) {
    warn(`${name} is not available locally — skipping the live ${provider} check`);
    return;
  }
  await modelProviderCheck(provider, key);
  step(`base model provider ${provider}: ${name} accepted`);
}

const MODEL_PROVIDER_PROBES: Readonly<
  Record<ModelProvider, { url: string; headers: (key: string) => Record<string, string> }>
> = {
  anthropic: {
    url: "https://api.anthropic.com/v1/models?limit=1",
    headers: (key) => ({ "x-api-key": key, "anthropic-version": "2023-06-01" }),
  },
  openai: { url: "https://api.openai.com/v1/models", headers: (key) => ({ authorization: `Bearer ${key}` }) },
  openrouter: { url: "https://openrouter.ai/api/v1/key", headers: (key) => ({ authorization: `Bearer ${key}` }) },
};

async function modelProviderCheck(provider: ModelProvider, apiKey: string): Promise<void> {
  const probe = MODEL_PROVIDER_PROBES[provider];
  let res: Response;
  try {
    res = await fetch(probe.url, { headers: probe.headers(apiKey), signal: AbortSignal.timeout(10_000) });
  } catch (e) {
    throw new CliError(
      `could not reach the ${provider} API: ${errMessage(e)} — check network access (and any proxy) and retry`,
    );
  }
  if (res.status === 401 || res.status === 403) {
    throw new CliError(
      `${provider} rejected ${MODEL_PROVIDER_KEYS[provider]} — the deployment would start but could not serve a single agent turn`,
    );
  }
  if (!res.ok) throw new CliError(`the ${provider} API returned HTTP ${res.status}; retry when it recovers`);
}

async function resendCheck(apiKey: string): Promise<void> {
  let res: Response;
  try {
    res = await fetch("https://api.resend.com/domains", {
      headers: { authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (e) {
    throw new CliError(
      `could not reach the Resend API: ${errMessage(e)} — check network access (and any proxy) and retry`,
    );
  }
  if (res.status === 401 || res.status === 403)
    throw new CliError("Resend rejected RESEND_API_KEY — mint a key with send access at https://resend.com/api-keys");
  if (!res.ok) throw new CliError(`the Resend API returned HTTP ${res.status}; retry when it recovers`);
}

async function smtpReachable(host: string, port: number): Promise<string> {
  const { connect } = await import("node:net");
  return new Promise<string>((resolve, reject) => {
    const socket = connect({ host, port });
    const done = (error?: Error, greeting?: string): void => {
      socket.destroy();
      if (error) reject(error);
      else resolve(greeting ?? "");
    };
    socket.setTimeout(10_000, () => done(new Error("connection timed out")));
    socket.once("error", (e: Error) => done(e));
    socket.once("data", (chunk: Buffer) => done(undefined, chunk.toString("utf8").split("\r\n")[0] ?? ""));
  });
}

async function authBrokerCheck(config: QmConfig, secrets: Map<string, string>, haveValues: boolean): Promise<void> {
  const transport = config.env.auth?.AUTH_EMAIL_TRANSPORT?.trim() === "smtp" ? "smtp" : "resend";
  const sender = deploymentSecretValue("AUTH_EMAIL_FROM", secrets.get("AUTH_EMAIL_FROM"));
  if (haveValues) {
    const address = (/<([^>]+)>\s*$/.exec((sender ?? "").trim())?.[1] ?? sender ?? "").trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address)) {
      throw new CliError(
        `AUTH_EMAIL_FROM must be a verified sender address, optionally as "Name <sender@example.com>" (got ${JSON.stringify(sender ?? "")})`,
      );
    }
    step(`sign-in links send from ${address}`);
  }
  if (transport === "resend") {
    const key = deploymentSecretValue("RESEND_API_KEY", secrets.get("RESEND_API_KEY"));
    if (!key) {
      warn("RESEND_API_KEY is not available locally — skipping the live Resend check");
      return;
    }
    await resendCheck(key);
    step("Resend API key: ok (verify the sending domain under https://resend.com/domains)");
    return;
  }
  const host = deploymentSecretValue("SMTP_HOST", secrets.get("SMTP_HOST"));
  if (!host) {
    warn("SMTP_HOST is not available locally — skipping the live SMTP reachability check");
    return;
  }
  const port = Number(config.env.auth?.SMTP_PORT ?? 587);
  let greeting: string;
  try {
    greeting = await smtpReachable(host, port);
  } catch (e) {
    throw new CliError(
      `SMTP relay ${host}:${port} is unreachable: ${errMessage(e)} — the broker cannot send sign-in links`,
    );
  }
  step(`SMTP relay ${host}:${port}: reachable (${greeting || "no greeting"})`);
}
