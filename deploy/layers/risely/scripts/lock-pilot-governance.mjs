import { createHmac } from "node:crypto";

const publicUrl = process.env.PUBLIC_API_URL?.replace(/\/+$/, "");
const sessionSecret = process.env.PORTAL_SESSION_SECRET;
const admin = process.env.ADMIN_GRANTS?.split(",")[0]
  ?.replace(/:org_admin$/, "")
  .trim();
if (!publicUrl || !sessionSecret || !admin) throw new Error("Missing pilot operator configuration");

const now = Math.floor(Date.now() / 1000);
const session = { k: "session", sub: admin, org: "risely", auth: now, iat: now, exp: now + 600 };
const key = createHmac("sha256", sessionSecret).update("portal.session.v1").digest();
const payload = Buffer.from(JSON.stringify(session), "utf8").toString("base64url");
const signature = createHmac("sha256", key).update(payload).digest("base64url");
const headers = {
  "content-type": "application/json",
  cookie: `portal_session=${encodeURIComponent(`${payload}.${signature}`)}`,
  origin: publicUrl,
  "sec-fetch-site": "same-origin",
};
const scopePath = "/admin/api/scopes/org%3Arisely";
const desired = { mode: "allowlist", rules: [] };

async function readPolicy() {
  const response = await fetch(`${publicUrl}${scopePath}`, { headers, signal: AbortSignal.timeout(30000) });
  const body = await response.json();
  if (!response.ok) throw new Error(`Governance read failed with HTTP ${response.status}`);
  return body.commandPolicy ?? body.resources?.["command-policy"] ?? null;
}

const before = await readPolicy();
const changed = JSON.stringify(before) !== JSON.stringify(desired);
if (changed) {
  const response = await fetch(`${publicUrl}${scopePath}/command-policy`, {
    method: "PUT",
    headers,
    body: JSON.stringify(desired),
    signal: AbortSignal.timeout(30000),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(`Governance lock failed with HTTP ${response.status}: ${JSON.stringify(body)}`);
}
const after = await readPolicy();
if (JSON.stringify(after) !== JSON.stringify(desired)) throw new Error("Governance lock verification failed");
process.stdout.write(`${JSON.stringify({ changed, commandPolicy: after }, null, 2)}\n`);
