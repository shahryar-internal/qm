import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  buildNotionPageTemplate,
  notionTemplateKinds,
  privateCeoNotionBinding,
} from "../../canary/notion-templates/index.mjs";
import { renderPrivateCeoSlackBlockKit, renderSlackBlockKit, SlackLimits } from "../../canary/slack/index.mjs";

const digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const artifact = Object.freeze({
  schemaVersion: 1,
  artifactRef: `artifact:${digest}`,
  revision: digest,
  kind: "marketing_draft",
  state: "ready",
  evidence: [
    Object.freeze({
      evidenceRef: `evidence:${digest}`,
      trust: "verified_source",
      availability: "available",
    }),
  ],
  links: [Object.freeze({ linkRef: `qm:${digest}`, availability: "available" })],
});

test("Slack Block Kit is deterministic, private, compact, and actionless", () => {
  const first = renderPrivateCeoSlackBlockKit(artifact);
  const second = renderPrivateCeoSlackBlockKit(artifact);
  assert.deepEqual(first, second);
  assert.equal(first.response_type, "ephemeral");
  assert.ok(first.blocks.length <= SlackLimits.blocks);
  assert.ok(first.blocks.every((block) => block.type !== "actions"));
  assert.doesNotMatch(JSON.stringify(first), /action_id|"button"|https?:\/\//);
  assert.match(JSON.stringify(first), /Private CEO work record/);
});

test("Notion uses the exact fixed private CEO proposal shape", () => {
  const proposal = buildNotionPageTemplate(artifact);
  assert.equal(proposal.type, "private_ceo_notion_page_proposal");
  assert.equal(proposal.templateRef, "risely.private-ceo.work-item.v1");
  assert.equal(proposal.audience.scope, "private_ceo");
  assert.equal(proposal.audience.delivery, "actionless_preview");
  assert.deepEqual(proposal.binding, {
    parentRef: "notion:ceo-private-root-v1",
    audienceRef: "audience:ceo-private",
    scope: "private_ceo",
    providerInvocationAllowed: false,
  });
  assert.doesNotMatch(JSON.stringify(proposal), /slack-audience|slack-team|slack-user/u);
  assert.equal(Object.isFrozen(privateCeoNotionBinding), true);
  assert.deepEqual(
    proposal.sections.map((section) => section.key),
    ["executive_brief", "status_and_trust", "review_details", "evidence", "cross_surface_record"],
  );
  assert.equal(proposal.page.artifactRef, artifact.artifactRef);
  assert.equal(proposal.page.revision, artifact.revision);
  assert.equal(proposal.actionless, true);
  assert.deepEqual(notionTemplateKinds, ["private_ceo_work_item"]);
});

test("Slack bounds escaped mrkdwn and every fallback exactly", () => {
  const rendered = renderPrivateCeoSlackBlockKit({ ...artifact, evidence: [] });
  assert.ok(rendered.text.length <= SlackLimits.fallback);
  for (const block of rendered.blocks) {
    if (block.type === "header") assert.ok(block.text.text.length <= SlackLimits.header);
    if (block.type === "section") assert.ok(block.text.text.length <= SlackLimits.section);
    if (block.type === "context") {
      assert.ok(block.elements.length <= SlackLimits.contextElements);
      for (const element of block.elements) assert.ok(element.text.length <= SlackLimits.context);
    }
  }
  const legacy = {
    id: "run-meeting-123",
    revision: "2",
    kind: "meeting_prep",
    state: "ready",
    title: "&".repeat(120),
    summary: "&".repeat(600),
    facts: [],
    evidence: [],
    links: [{ label: "&".repeat(80), url: "https://qm.riselyinternal.ai/" }],
    actions: [],
    updatedAt: "2026-08-26T16:00:00.000Z",
  };
  const legacyRendered = renderSlackBlockKit(legacy);
  for (const block of legacyRendered.blocks) {
    if (block.type === "section") assert.ok(block.text.text.length <= SlackLimits.section);
    if (block.type === "context")
      for (const element of block.elements) assert.ok(element.text.length <= SlackLimits.context);
  }
  assert.doesNotMatch(JSON.stringify(legacyRendered), /&|Weekly marketing draft|Enrollment leaders/);
});

test("the visual preview has no hooks or action controls and retains accessibility boundaries", async () => {
  const [page, card] = await Promise.all([
    readFile(new URL("../../canary/visual-preview/index.html", import.meta.url), "utf8"),
    readFile(new URL("../../canary/visuals/qm-work-card.html", import.meta.url), "utf8"),
  ]);
  assert.match(page, /Skip to CEO work detail/);
  assert.match(page, /no external action can run/);
  assert.doesNotMatch(page, /<button|preview\.js|action_id|https?:\/\//);
  assert.doesNotMatch(card, /<button|risely-work-card__actions/);
});
