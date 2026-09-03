import { test } from "node:test";
import assert from "node:assert/strict";
import {
  NON_INTERACTIVE_FAST_MODE,
  NON_INTERACTIVE_THINKING_LEVEL,
  STRATEGIC_THINKING_LEVEL,
  strategicThinkingLevel,
  turnModelOptions,
  validateWebTurnModelOptions,
  webTurnRuntimeModelRefusal,
} from "../src/core/turn-options.ts";

test("triggered turns default to extra-high thinking and non-fast mode", () => {
  assert.deepEqual(turnModelOptions({ triggered: true }), {
    thinkingLevel: NON_INTERACTIVE_THINKING_LEVEL,
    fastMode: NON_INTERACTIVE_FAST_MODE,
  });
});

test("explicit turn model options win over triggered defaults", () => {
  assert.deepEqual(turnModelOptions({ triggered: true, thinkingLevel: "low", fastMode: true }), {
    thinkingLevel: "low",
    fastMode: true,
  });
});

test("web model controls are bounded by admin configuration", () => {
  assert.equal(
    validateWebTurnModelOptions({ model: "claude-sonnet-4-6" }, ["claude-opus-4-8"]),
    "that model is not enabled for the web UI",
  );
  assert.equal(validateWebTurnModelOptions({ thinkingLevel: "infinite" }, null), "unsupported thinking level");
  assert.equal(validateWebTurnModelOptions({ model: "claude-opus-4-8", thinkingLevel: "high" }, null), null);
});

test("a resolved scope override outside the configured picker is refused, the org default is not", () => {
  const picker = ["claude-sonnet-4-6"];
  assert.equal(
    webTurnRuntimeModelRefusal("claude-opus-4-8", "claude-sonnet-4-6", picker),
    "that model is not enabled for the web UI",
  );
  assert.equal(webTurnRuntimeModelRefusal("claude-sonnet-4-6", "claude-opus-4-8", picker), null);
  assert.equal(webTurnRuntimeModelRefusal("claude-opus-4-8", "claude-opus-4-8", picker), null);
  assert.equal(webTurnRuntimeModelRefusal("claude-opus-4-8", "claude-sonnet-4-6", null), null);
  assert.equal(webTurnRuntimeModelRefusal("claude-opus-4-8", "claude-sonnet-4-6", []), null);
});

test("interactive turns do not force model options", () => {
  assert.deepEqual(turnModelOptions({}), {});
});

test("strategic multi-source turns use high thinking while simple lookups stay automatic", () => {
  assert.equal(
    strategicThinkingLevel("Recommend a plan using our calendar, email, and analytics"),
    STRATEGIC_THINKING_LEVEL,
  );
  assert.equal(strategicThinkingLevel("What is on my calendar tomorrow?"), undefined);
  assert.deepEqual(turnModelOptions({ text: "Compare customer health across our CRM and analytics" }), {
    thinkingLevel: STRATEGIC_THINKING_LEVEL,
  });
  assert.deepEqual(turnModelOptions({ text: "Give me an account health brief for Acme" }), {
    thinkingLevel: STRATEGIC_THINKING_LEVEL,
  });
  assert.deepEqual(turnModelOptions({ text: "Prepare me for my meeting with Acme" }), {
    thinkingLevel: STRATEGIC_THINKING_LEVEL,
  });
  assert.deepEqual(turnModelOptions({ text: "Read this Notion page" }), {});
});

test("explicit public research uses high thinking and explicit options still win", () => {
  assert.deepEqual(turnModelOptions({ text: "Research the competitor market" }), {
    thinkingLevel: STRATEGIC_THINKING_LEVEL,
  });
  assert.deepEqual(turnModelOptions({ text: "Deep research this strategy", thinkingLevel: "low" }), {
    thinkingLevel: "low",
  });
});

test("a triggered turn with an explicit low thinking level overrides the xhigh trigger default", () => {
  assert.deepEqual(turnModelOptions({ triggered: true, thinkingLevel: "low" }), {
    thinkingLevel: "low",
    fastMode: NON_INTERACTIVE_FAST_MODE,
  });
});
