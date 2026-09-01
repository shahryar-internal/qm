import assert from "node:assert/strict";
import { test } from "node:test";
import {
  exactMcpApprovalTool,
  exactToolApprovalArguments,
  exactToolApprovalArgumentsSha256,
  exactToolApprovalPreview,
  toolApprovalKey,
} from "../src/tools/exact-tool-approval.ts";

test("exact MCP approval keys bind canonical arguments and connector contracts", () => {
  const tool = exactMcpApprovalTool("a".repeat(64), "external_write");
  const left = { payload: { note: "Approved", dealId: "deal_1" } };
  const same = { payload: { dealId: "deal_1", note: "Approved" } };
  const changed = { payload: { dealId: "deal_1", note: "Changed" } };
  assert.equal(exactToolApprovalArguments(left).sha256, exactToolApprovalArguments(same).sha256);
  assert.notEqual(exactToolApprovalArguments(left).sha256, exactToolApprovalArguments(changed).sha256);
  const key = toolApprovalKey(tool, left);
  assert.equal(exactToolApprovalArgumentsSha256(key), exactToolApprovalArguments(left).sha256);
  assert.notEqual(key, toolApprovalKey(tool, changed));
  assert.notEqual(key, toolApprovalKey(exactMcpApprovalTool("b".repeat(64), "external_write"), left));
  assert.equal(toolApprovalKey("mcp:static:read", left), "tool:mcp:static:read");
});

test("exact MCP approval previews show canonical bytes and reject non-JSON arguments", () => {
  const args = { payload: { z: 1, a: "visible exact value" } };
  const preview = exactToolApprovalPreview(args);
  assert.match(preview.summary, /^[A-Za-z ]+[a-f0-9]{64}:/);
  assert.equal(preview.summaryDetail, '{"payload":{"a":"visible exact value","z":1}}');
  assert.throws(() => exactToolApprovalArguments({ payload: { value: undefined } }));
  assert.throws(() => exactToolApprovalArguments(JSON.parse('{"__proto__":{"polluted":true}}')));
});
