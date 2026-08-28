import { readFile } from "node:fs/promises";

const apiKey = process.env.GEMINI_API_KEY?.trim();
if (!apiKey) throw new Error("GEMINI_API_KEY is required");

const provider = JSON.parse(await readFile(new URL("../gemini-provider.json", import.meta.url), "utf8"));
const model = provider.models[0].id;
const normalizeBaseUrl = (value) => {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash)
    throw new Error("Gemini base URL must not include credentials, query parameters, or a fragment");
  return url.toString().replace(/\/$/, "");
};
const directGoogleBaseUrl = "https://generativelanguage.googleapis.com/v1beta/openai";
const allowedBaseUrls = new Set([normalizeBaseUrl(directGoogleBaseUrl), normalizeBaseUrl(provider.baseUrl)]);
const baseUrl = normalizeBaseUrl(process.env.GEMINI_BASE_URL?.trim() || provider.baseUrl);
if (!allowedBaseUrls.has(baseUrl)) {
  throw new Error("GEMINI_BASE_URL must be the committed private gateway or the Google Gemini API endpoint");
}
const response = await fetch(`${baseUrl}/chat/completions`, {
  method: "POST",
  headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
  body: JSON.stringify({
    model,
    messages: [{ role: "user", content: "Reply with exactly RISLEY_GEMINI_OK" }],
  }),
});

if (!response.ok) throw new Error(`Gemini check failed with HTTP ${response.status}`);
const body = await response.json();
const reply = body.choices?.[0]?.message?.content?.trim();
if (reply !== "RISLEY_GEMINI_OK") throw new Error(`Gemini returned an unexpected reply: ${reply ?? "missing"}`);

const toolResponse = await fetch(`${baseUrl}/chat/completions`, {
  method: "POST",
  headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
  body: JSON.stringify({
    model,
    messages: [{ role: "user", content: "Report that the provider is ready." }],
    tools: [
      {
        type: "function",
        function: {
          name: "report_readiness",
          description: "Report provider readiness",
          parameters: {
            type: "object",
            properties: { ready: { type: "boolean" } },
            required: ["ready"],
            additionalProperties: false,
          },
        },
      },
    ],
    tool_choice: { type: "function", function: { name: "report_readiness" } },
  }),
});

if (!toolResponse.ok) throw new Error(`Gemini tool check failed with HTTP ${toolResponse.status}`);
const toolBody = await toolResponse.json();
const toolCall = toolBody.choices?.[0]?.message?.tool_calls?.[0];
if (toolCall?.function?.name !== "report_readiness") throw new Error("Gemini did not return the required tool call");
const args = JSON.parse(toolCall.function.arguments ?? "{}");
if (args.ready !== true) throw new Error("Gemini returned an invalid readiness result");

process.stdout.write(`${JSON.stringify({ ok: true, provider: provider.id, model, toolCalling: true })}\n`);
