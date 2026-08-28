import { createServer } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";

const upstreamOrigin = "https://generativelanguage.googleapis.com";
const signature = "skip_thought_signature_validator";
const allowedPaths = new Set(["/v1beta/openai/models", "/v1beta/openai/chat/completions"]);
const requestHeaders = new Set(["accept", "authorization", "content-type", "user-agent"]);
const responseHeaders = new Set(["cache-control", "content-type", "date", "retry-after", "x-request-id"]);

export function normalizeGeminiPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return payload;
  const normalized = structuredClone(payload);
  delete normalized.store;
  delete normalized.stream_options;
  if (normalized.max_completion_tokens !== undefined && normalized.max_tokens === undefined) {
    normalized.max_tokens = normalized.max_completion_tokens;
  }
  delete normalized.max_completion_tokens;
  if (Array.isArray(normalized.messages)) {
    for (const message of normalized.messages) {
      if (message?.role !== "assistant" || !Array.isArray(message.tool_calls)) continue;
      for (const toolCall of message.tool_calls) {
        if (!toolCall || typeof toolCall !== "object") continue;
        const google = toolCall.extra_content?.google;
        if (typeof google?.thought_signature === "string" && google.thought_signature) continue;
        toolCall.extra_content = { ...toolCall.extra_content, google: { ...google, thought_signature: signature } };
      }
    }
  }
  return normalized;
}

function readBody(request, limit = 32 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("request_too_large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function selectedHeaders(headers, allowed) {
  const selected = {};
  for (const [name, value] of headers.entries()) {
    if (allowed.has(name.toLowerCase())) selected[name] = value;
  }
  return selected;
}

export function createGeminiCompatibilityServer() {
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://localhost");
      if (request.method === "GET" && url.pathname === "/healthz") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"ok":true}');
        return;
      }
      if (!allowedPaths.has(url.pathname) || !["GET", "POST"].includes(request.method ?? "")) {
        response.writeHead(404, { "content-type": "application/json" });
        response.end('{"error":"not_found"}');
        return;
      }
      const headers = {};
      for (const [name, value] of Object.entries(request.headers)) {
        if (requestHeaders.has(name.toLowerCase()) && typeof value === "string") headers[name] = value;
      }
      let body;
      if (request.method === "POST") {
        const raw = await readBody(request);
        const parsed = JSON.parse(raw.toString("utf8"));
        body = JSON.stringify(normalizeGeminiPayload(parsed));
      }
      const upstream = await fetch(`${upstreamOrigin}${url.pathname}`, {
        method: request.method,
        headers,
        ...(body === undefined ? {} : { body }),
        redirect: "error",
        signal: AbortSignal.timeout(300_000),
      });
      response.writeHead(upstream.status, selectedHeaders(upstream.headers, responseHeaders));
      if (!upstream.body) {
        response.end();
        return;
      }
      await pipeline(Readable.fromWeb(upstream.body), response);
    } catch (error) {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      const status = error instanceof Error && error.message === "request_too_large" ? 413 : 502;
      response.writeHead(status, { "content-type": "application/json" });
      response.end(`{"error":"${status === 413 ? "request_too_large" : "upstream_unavailable"}"}`);
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  createGeminiCompatibilityServer().listen(8080, "0.0.0.0");
}
