import { createHash } from "node:crypto";

const EXACT_MCP_TOOL_PREFIX = "mcp-exact:";
const READ_ONLY_MCP_TOOL_PREFIX = "mcp:";
const EXACT_MCP_TOOL = /^mcp-exact:[a-f0-9]{64}:[A-Za-z0-9_-]{1,128}$/;
const READ_ONLY_MCP_TOOL = /^mcp:[a-f0-9]{64}:[A-Za-z0-9_-]{1,128}$/;
const EXACT_MCP_KEY = /^tool:mcp-exact:[a-f0-9]{64}:[A-Za-z0-9_-]{1,128}:([a-f0-9]{64})$/;
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function canonical(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value !== "object") throw new Error("exact tool approval arguments must be JSON values");
  const record = value as Record<string, unknown>;
  const prototype = Object.getPrototypeOf(record);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error("exact tool approval arguments must be plain JSON objects");
  }
  const keys = Object.keys(record).sort();
  if (keys.some((key) => DANGEROUS_KEYS.has(key))) {
    throw new Error("exact tool approval arguments contain an unsafe field");
  }
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}

export function exactMcpApprovalTool(serverContractSha256: string, name: string): string {
  if (!/^[a-f0-9]{64}$/.test(serverContractSha256) || !/^[A-Za-z0-9_-]{1,128}$/.test(name)) {
    throw new Error("exact MCP approval contract is invalid");
  }
  return `${EXACT_MCP_TOOL_PREFIX}${serverContractSha256}:${name}`;
}

export function readOnlyMcpApprovalTool(serverContractSha256: string, name: string): string {
  if (!/^[a-f0-9]{64}$/.test(serverContractSha256) || !/^[A-Za-z0-9_-]{1,128}$/.test(name)) {
    throw new Error("read-only MCP approval contract is invalid");
  }
  return `${READ_ONLY_MCP_TOOL_PREFIX}${serverContractSha256}:${name}`;
}

export function isExactMcpApprovalTool(tool: string): boolean {
  return EXACT_MCP_TOOL.test(tool);
}

export function isReadOnlyMcpApprovalTool(tool: string): boolean {
  return READ_ONLY_MCP_TOOL.test(tool);
}

export function exactToolApprovalArguments(args: unknown): { canonical: string; sha256: string } {
  const serialized = canonical(args ?? {});
  return { canonical: serialized, sha256: createHash("sha256").update(serialized, "utf8").digest("hex") };
}

export function toolApprovalKey(tool: string, args: unknown): string {
  if (!tool.startsWith(EXACT_MCP_TOOL_PREFIX)) return `tool:${tool}`;
  return `tool:${tool}:${exactToolApprovalArguments(args).sha256}`;
}

export function exactToolApprovalArgumentsSha256(approvalKey: unknown): string | null {
  if (typeof approvalKey !== "string") return null;
  return EXACT_MCP_KEY.exec(approvalKey)?.[1] ?? null;
}

export function exactToolApprovalPreview(args: unknown): { summary: string; summaryDetail: string } {
  const approval = exactToolApprovalArguments(args);
  const clipped = approval.canonical.length > 320 ? `${approval.canonical.slice(0, 320)}…` : approval.canonical;
  const summaryDetail =
    approval.canonical.length > 16_000 ? `${approval.canonical.slice(0, 16_000)}…` : approval.canonical;
  return {
    summary: `Exact request ${approval.sha256}: ${clipped}`,
    summaryDetail,
  };
}
