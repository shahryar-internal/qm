import { createHmac, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const pilotOrigin = "https://d2arqymlq4fdoe.cloudfront.net";
const origin = new URL(required("PUBLIC_API_URL")).origin;
if (origin !== pilotOrigin) throw new Error("PUBLIC_API_URL must be the committed Risely pilot origin");
const secret = required("PORTAL_SESSION_SECRET");
const principal = required("AUTH_ALLOWED_EMAILS").split(",")[0]?.trim().toLowerCase();
if (!principal) throw new Error("AUTH_ALLOWED_EMAILS has no principal");
const provider = JSON.parse(await readFile(new URL("../gemini-provider.json", import.meta.url), "utf8"));
const model = provider.models[0]?.id;
if (!model) throw new Error("gemini-provider.json has no primary model");

const now = Math.floor(Date.now() / 1000);
const body = Buffer.from(
  JSON.stringify({ k: "session", sub: principal, org: "risely", auth: now, iat: now, exp: now + 600 }),
).toString("base64url");
const sessionKey = createHmac("sha256", secret).update("portal.session.v1").digest();
const signature = createHmac("sha256", sessionKey).update(body).digest("base64url");
const headers = {
  accept: "application/json",
  "content-type": "application/json",
  cookie: `portal_session=${encodeURIComponent(`${body}.${signature}`)}`,
  origin,
};
const readJson = async (response, label) => {
  const raw = await response.text();
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    throw new Error(`${label} returned non-JSON HTTP ${response.status}`);
  }
};

const submit = await fetch(`${origin}/api/turn`, {
  method: "POST",
  headers,
  redirect: "error",
  signal: AbortSignal.timeout(15_000),
  body: JSON.stringify({
    text: "Reply with exactly RISELY_PUBLIC_CHAT_OK",
    threadRef: `web:${principal}:${randomUUID()}`,
    model,
    timezone: "America/Los_Angeles",
  }),
});
const submitted = await readJson(submit, "public chat submit");
if (!submit.ok || typeof submitted.runId !== "string") {
  throw new Error(
    `public chat submit failed with HTTP ${submit.status}: ${submitted.reason ?? submitted.message ?? "unknown"}`,
  );
}

const deadline = Date.now() + 180_000;
let run;
while (Date.now() < deadline) {
  const response = await fetch(`${origin}/api/runs/${encodeURIComponent(submitted.runId)}`, {
    headers,
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`public chat poll failed with HTTP ${response.status}`);
  run = await readJson(response, "public chat poll");
  if (run.status === "done" || run.status === "failed") break;
  await new Promise((resolve) => setTimeout(resolve, 1_000));
}

if (run?.status !== "done" || run.result?.status !== "ok") {
  throw new Error(
    `public chat run failed: run=${run?.status ?? "timeout"} result=${run?.result?.status ?? "missing"} approvals=${run?.result?.pendingApprovals?.length ?? 0} reason=${run?.result?.reason ?? "missing"}`,
  );
}
if (run.result.reply?.trim() !== "RISELY_PUBLIC_CHAT_OK") {
  throw new Error("public chat returned an unexpected reply");
}
process.stdout.write(`${JSON.stringify({ ok: true, model, publicChat: true })}\n`);
