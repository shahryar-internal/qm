import { createHash } from "node:crypto";

export const artifactKinds = Object.freeze([
  "meeting_prep",
  "meeting_followup",
  "stale_deals",
  "proposal",
  "marketing_draft",
  "demo_reminder",
]);

export const artifactStates = Object.freeze(["ready", "waiting", "failed", "expired", "superseded"]);

const errorCodes = new Set([
  "connector_unavailable",
  "transcript_pending",
  "source_incomplete",
  "delivery_failed",
  "action_failed",
  "artifact_expired",
]);

const actionKeys = new Set([
  "open",
  "ask_qm",
  "refresh",
  "dismiss",
  "open_runbook",
  "snooze",
  "confirm_ready",
  "review_followup",
  "retry",
  "add_notes",
  "review_deals",
  "draft_followup",
  "revise",
  "create_gmail_draft",
  "mark_approved",
  "discard",
  "open_latest",
  "report_issue",
]);

const actionPolicy = Object.freeze({
  meeting_prep: Object.freeze({
    ready: Object.freeze(["open", "ask_qm", "refresh"]),
    waiting: Object.freeze([]),
    failed: Object.freeze([]),
    expired: Object.freeze([]),
    superseded: Object.freeze([]),
  }),
  meeting_followup: Object.freeze({
    ready: Object.freeze(["review_followup", "open", "add_notes", "dismiss", "create_gmail_draft"]),
    waiting: Object.freeze(["add_notes", "retry"]),
    failed: Object.freeze([]),
    expired: Object.freeze([]),
    superseded: Object.freeze([]),
  }),
  stale_deals: Object.freeze({
    ready: Object.freeze(["review_deals", "draft_followup", "dismiss"]),
    waiting: Object.freeze([]),
    failed: Object.freeze([]),
    expired: Object.freeze([]),
    superseded: Object.freeze([]),
  }),
  proposal: Object.freeze({
    ready: Object.freeze(["open", "revise", "create_gmail_draft", "discard"]),
    waiting: Object.freeze([]),
    failed: Object.freeze([]),
    expired: Object.freeze([]),
    superseded: Object.freeze(["open_latest"]),
  }),
  marketing_draft: Object.freeze({
    ready: Object.freeze(["open", "revise", "mark_approved", "discard"]),
    waiting: Object.freeze([]),
    failed: Object.freeze([]),
    expired: Object.freeze([]),
    superseded: Object.freeze([]),
  }),
  demo_reminder: Object.freeze({
    ready: Object.freeze(["open_runbook", "snooze", "confirm_ready"]),
    waiting: Object.freeze([]),
    failed: Object.freeze([]),
    expired: Object.freeze(["open_latest"]),
    superseded: Object.freeze([]),
  }),
});

const allowedLinkHosts = new Set(["notion.so", "www.notion.so", "qm.riselyinternal.ai"]);
const unsafeText = /[<>\[\]{}*_`~|\\\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/;
const unsafeEmailText =
  /[<>\[\]{}*_`~|\\\u0000-\u0009\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/;
const unsafeEmailAddress = /[\s<>\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/;
const emailAddressPattern =
  /^(?=.{1,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const id = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const hash = /^[0-9a-f]{64}$/;
const interactionRef = /^ir_[A-Za-z0-9_-]{32,512}$/;

function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value;
}

function text(value, label, max = 500) {
  if (typeof value !== "string") throw new TypeError(`${label} must be text`);
  const normalized = value.trim().replace(/\s+/g, " ");
  if (!normalized || normalized.length > max || unsafeText.test(normalized))
    throw new TypeError(`${label} must be safe plain text`);
  return normalized;
}

function identifier(value, label, max = 256) {
  if (typeof value !== "string") throw new TypeError(`${label} must be text`);
  const normalized = value.trim();
  if (!normalized || normalized.length > max || !id.test(normalized))
    throw new TypeError(`${label} must be an identifier`);
  return normalized;
}

function emailText(value, label, max) {
  if (typeof value !== "string") throw new TypeError(`${label} must be text`);
  const normalized = value.replace(/\r\n/g, "\n").trim();
  if (!normalized || normalized.length > max || unsafeEmailText.test(normalized))
    throw new TypeError(`${label} must be safe plain text`);
  return normalized;
}

function optionalText(value, label, max = 500) {
  return value === undefined ? undefined : text(value, label, max);
}

function isoTime(value, label) {
  const normalized = text(value, label, 64);
  if (Number.isNaN(Date.parse(normalized))) throw new TypeError(`${label} must be an ISO timestamp`);
  return normalized;
}

function resourceRef(value, label) {
  if (typeof value !== "string") throw new TypeError(`${label} must be an opaque resource reference`);
  const normalized = value.trim();
  if (!normalized || normalized.length > 256 || !id.test(normalized))
    throw new TypeError(`${label} must be an opaque resource reference`);
  return normalized;
}

function url(value, label) {
  const normalized = text(value, label, 2000);
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new TypeError(`${label} must be an absolute URL`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    !allowedLinkHosts.has(parsed.hostname)
  ) {
    throw new TypeError(`${label} must be an allowlisted HTTPS URL without credentials, query, or fragment`);
  }
  return parsed.toString();
}

function list(value, label, max) {
  if (!Array.isArray(value) || value.length > max) throw new TypeError(`${label} must be a list of at most ${max}`);
  return value;
}

function action(value, index) {
  const input = record(value, `actions[${index}]`);
  const key = identifier(input.key, `actions[${index}].key`, 48);
  if (!actionKeys.has(key)) throw new TypeError(`actions[${index}].key is not supported`);
  return { key, label: text(input.label, `actions[${index}].label`, 48), primary: input.primary === true };
}

function evidence(value, index) {
  const input = record(value, `evidence[${index}]`);
  return {
    label: text(input.label, `evidence[${index}].label`, 120),
    source: text(input.source, `evidence[${index}].source`, 80),
    ...(input.occurredAt === undefined
      ? {}
      : { occurredAt: isoTime(input.occurredAt, `evidence[${index}].occurredAt`) }),
    ...(input.url === undefined ? {} : { url: url(input.url, `evidence[${index}].url`) }),
    ...(input.resourceRef === undefined
      ? {}
      : { resourceRef: resourceRef(input.resourceRef, `evidence[${index}].resourceRef`) }),
  };
}

function link(value, index) {
  const input = record(value, `links[${index}]`);
  if ((input.url === undefined) === (input.resourceRef === undefined))
    throw new TypeError(`links[${index}] must provide exactly one destination`);
  return {
    label: text(input.label, `links[${index}].label`, 80),
    ...(input.url === undefined ? {} : { url: url(input.url, `links[${index}].url`) }),
    ...(input.resourceRef === undefined
      ? {}
      : { resourceRef: resourceRef(input.resourceRef, `links[${index}].resourceRef`) }),
  };
}

function fact(value, index) {
  const input = record(value, `facts[${index}]`);
  return {
    label: text(input.label, `facts[${index}].label`, 60),
    value: text(input.value, `facts[${index}].value`, 280),
  };
}

function emailAddress(value, label) {
  if (typeof value !== "string") throw new TypeError(`${label} must be text`);
  const normalized = value.trim();
  if (unsafeEmailAddress.test(normalized) || !emailAddressPattern.test(normalized)) {
    throw new TypeError(`${label} must be a valid email address`);
  }
  return normalized;
}

export function gmailDraftContentHash(value) {
  const draft = record(value, "gmailDraft");
  return createHash("sha256")
    .update(JSON.stringify({ to: draft.to, subject: draft.subject, body: draft.body }))
    .digest("hex");
}

function gmailDraft(value) {
  const input = record(value, "gmailDraft");
  const allowed = new Set(["to", "subject", "body", "contentSha256"]);
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) throw new TypeError(`gmailDraft.${key} is not supported`);
  }
  const draft = {
    to: emailAddress(input.to, "gmailDraft.to"),
    subject: emailText(input.subject, "gmailDraft.subject", 200),
    body: emailText(input.body, "gmailDraft.body", 12000),
    contentSha256: text(input.contentSha256, "gmailDraft.contentSha256", 64),
  };
  if (!hash.test(draft.contentSha256) || draft.contentSha256 !== gmailDraftContentHash(draft)) {
    throw new TypeError("gmailDraft.contentSha256 must bind the exact recipient, subject, and body");
  }
  return Object.freeze(draft);
}

function allowedActions(kind, state) {
  return actionPolicy[kind]?.[state] ?? [];
}

function validateActionPolicy(kind, state, actions) {
  const allowed = new Set(allowedActions(kind, state));
  const seen = new Set();
  for (const item of actions) {
    if (!allowed.has(item.key)) throw new TypeError(`action ${item.key} is not available for ${kind} in ${state}`);
    if (seen.has(item.key)) throw new TypeError(`action ${item.key} is duplicated`);
    seen.add(item.key);
  }
}

function trustedInteraction(value, actionKey, artifact) {
  const input = record(value, `trustedInteractions.${actionKey}`);
  const allowed = new Set([
    "interactionRef",
    "proposalHash",
    "artifactId",
    "revision",
    "principalRef",
    "expiresAt",
    "gmailDraftContentSha256",
  ]);
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) throw new TypeError(`trustedInteractions.${actionKey}.${key} is not supported`);
  }
  if (typeof input.interactionRef !== "string")
    throw new TypeError(`trustedInteractions.${actionKey}.interactionRef must be opaque`);
  const reference = input.interactionRef.trim();
  if (!interactionRef.test(reference))
    throw new TypeError(`trustedInteractions.${actionKey}.interactionRef must be opaque`);
  const proposalHash = text(input.proposalHash, `trustedInteractions.${actionKey}.proposalHash`, 64);
  if (!hash.test(proposalHash))
    throw new TypeError(`trustedInteractions.${actionKey}.proposalHash must be a SHA-256 hash`);
  if (resourceRef(input.artifactId, `trustedInteractions.${actionKey}.artifactId`) !== artifact.id) {
    throw new TypeError(`trustedInteractions.${actionKey}.artifactId does not match the artifact`);
  }
  if (text(input.revision, `trustedInteractions.${actionKey}.revision`, 64) !== artifact.revision) {
    throw new TypeError(`trustedInteractions.${actionKey}.revision does not match the artifact`);
  }
  resourceRef(input.principalRef, `trustedInteractions.${actionKey}.principalRef`);
  isoTime(input.expiresAt, `trustedInteractions.${actionKey}.expiresAt`);
  if (Date.parse(input.expiresAt) <= Date.now())
    throw new TypeError(`trustedInteractions.${actionKey}.expiresAt must be in the future`);
  if (actionKey === "create_gmail_draft") {
    if (!artifact.gmailDraft || input.gmailDraftContentSha256 !== artifact.gmailDraft.contentSha256) {
      throw new TypeError(`trustedInteractions.${actionKey} must bind the exact Gmail draft`);
    }
  } else if (input.gmailDraftContentSha256 !== undefined) {
    throw new TypeError(`trustedInteractions.${actionKey}.gmailDraftContentSha256 is not supported`);
  }
  return Object.freeze({ key: actionKey, interactionRef: reference });
}

export const interactionIngressRequirements = Object.freeze([
  "durable_registry_lookup",
  "artifact_id_and_revision_binding",
  "proposal_hash_binding",
  "authenticated_principal_binding",
  "unexpired_interaction",
  "single_use_replay_protection",
]);

export function bindTrustedInteractions(artifactInput, trustedInteractions = {}) {
  const artifact = validateArtifact(artifactInput);
  const registry = record(trustedInteractions, "trustedInteractions");
  const available = new Set(artifact.actions.map((item) => item.key));
  for (const key of Object.keys(registry)) {
    if (!available.has(key)) throw new TypeError(`trustedInteractions.${key} is not an available action`);
  }
  const actions = artifact.actions.flatMap((item) => {
    if (registry[item.key] === undefined) return [];
    return [{ ...item, ...trustedInteraction(registry[item.key], item.key, artifact) }];
  });
  return Object.freeze(actions);
}

export function validateArtifact(value) {
  const input = record(value, "artifact");
  const allowed = new Set([
    "id",
    "version",
    "revision",
    "kind",
    "state",
    "title",
    "summary",
    "facts",
    "evidence",
    "links",
    "actions",
    "updatedAt",
    "statusDetail",
    "errorCode",
    "latestId",
    "gmailDraft",
  ]);
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) throw new TypeError(`artifact.${key} is not supported`);
  }
  if (input.version !== undefined && input.version !== 1) throw new TypeError("version is not supported");
  const kind = identifier(input.kind, "kind", 48);
  const state = text(input.state, "state", 32);
  if (!artifactKinds.includes(kind)) throw new TypeError("kind is not supported");
  if (!artifactStates.includes(state)) throw new TypeError("state is not supported");
  const actions = list(input.actions ?? [], "actions", 8).map(action);
  validateActionPolicy(kind, state, actions);
  if (actions.filter((item) => item.primary).length > 1) throw new TypeError("actions may have only one primary item");
  const hasGmailDraftAction = actions.some((item) => item.key === "create_gmail_draft");
  if (hasGmailDraftAction !== (input.gmailDraft !== undefined)) {
    throw new TypeError("create_gmail_draft requires the exact Gmail draft review representation");
  }
  const errorCode = input.errorCode === undefined ? undefined : identifier(input.errorCode, "errorCode", 64);
  if (errorCode !== undefined && !errorCodes.has(errorCode)) throw new TypeError("errorCode is not supported");
  const statusDetail = optionalText(input.statusDetail, "statusDetail", 240);
  return Object.freeze({
    version: 1,
    id: resourceRef(input.id, "id"),
    revision: text(input.revision, "revision", 64),
    kind,
    state,
    title: text(input.title, "title", 120),
    summary: text(input.summary, "summary", 600),
    facts: Object.freeze(list(input.facts ?? [], "facts", 3).map(fact)),
    evidence: Object.freeze(list(input.evidence ?? [], "evidence", 8).map(evidence)),
    links: Object.freeze(list(input.links ?? [], "links", 5).map(link)),
    actions: Object.freeze(actions),
    updatedAt: isoTime(input.updatedAt, "updatedAt"),
    ...(statusDetail === undefined ? {} : { statusDetail }),
    ...(errorCode === undefined ? {} : { errorCode }),
    ...(input.latestId === undefined ? {} : { latestId: resourceRef(input.latestId, "latestId") }),
    ...(input.gmailDraft === undefined ? {} : { gmailDraft: gmailDraft(input.gmailDraft) }),
  });
}

export { actionPolicy, allowedLinkHosts };

export const surfaceArtifactKinds = Object.freeze([
  "meeting_prep",
  "post_meeting",
  "stale_revenue_digest",
  "goals_eod",
  "outreach_linkedin_demo",
  "marketing_plan",
  "marketing_draft",
]);

export const surfaceArtifactStates = Object.freeze(["ready", "waiting", "unavailable", "failed", "superseded"]);

export const surfaceTrustLabels = Object.freeze([
  "verified_source",
  "untrusted_source_data",
  "generated_evidence_cited_update",
  "unavailable_source",
]);

export const surfacePresentationCodeForState = Object.freeze({
  ready: "private_ceo_review",
  waiting: "private_ceo_waiting",
  unavailable: "private_ceo_unavailable",
  failed: "private_ceo_failed",
  superseded: "private_ceo_superseded",
});

export const surfacePresentationCodes = Object.freeze(Object.values(surfacePresentationCodeForState));

const surfaceUnicodeControl = /[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}\u034f\ufeff]/u;
const surfaceUnpairedSurrogate = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u;
const surfaceMarkup = /[<>\[\]{}*_`~|\\@]/u;
const surfaceScheme = /\b[a-z][a-z0-9+.-]{0,31}:/iu;
const surfaceBareHost = /(?:^|[\s(])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?:\b|\/)/iu;
const surfaceEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu;
const surfacePhone = /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b|\b\d{10,15}\b/u;
const surfaceSecret =
  /(?:-----BEGIN(?: [A-Z]+)? PRIVATE[-_ ]?KEY-----|(?:xox[baprs]-|sk-|pk_|ghp_|github_pat_|AKIA|AIza)[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(?:api[_-]?key|access[_-]?token|token|secret|password|credential|private[-_ ]?key)\s*[:=]\s*\S+|\b(?:bearer|token|credential|authorization)\s+[A-Za-z0-9._-]{12,}\b)/iu;
const surfaceRef = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const surfaceDigestReference = /^([a-z_]+):([a-f0-9]{64})$/u;
const surfaceFormattedPhone = /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/u;
const surfaceSsn = /(?:^|[^0-9])\d{3}-\d{2}-\d{4}(?:$|[^0-9])/u;
const surfaceIpv4 = /(?:^|[^0-9])(?:\d{1,3}\.){3}\d{1,3}(?:$|[^0-9])/u;
const surfaceArtifactReferenceNamespaces = new Set(["artifact"]);
const surfaceEvidenceReferenceNamespaces = new Set(["evidence"]);
const surfaceLinkReferenceNamespaces = new Set(["qm"]);
const surfaceRefNamespaces = new Set([
  "artifact",
  "evidence",
  "qm",
  "workflow",
  "record",
  "source",
  "calendar",
  "gmail",
  "clarify",
  "brain",
  "notion",
  "revenue",
  "marketing",
  "goals",
  "outreach",
  "linkedin",
  "demo",
  "ceo",
  "chief_of_staff",
  "deployment",
]);

function snapshotSurfaceValue(value, label, stack = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${label} must be plain data`);
    return;
  }
  if (!value || typeof value !== "object") throw new TypeError(`${label} must be plain data`);
  if (stack.has(value)) throw new TypeError(`${label} must not contain cycles`);
  const isArray = Array.isArray(value);
  const expectedPrototype = isArray ? Array.prototype : Object.prototype;
  if (Object.getPrototypeOf(value) !== expectedPrototype || Object.getOwnPropertySymbols(value).length !== 0) {
    throw new TypeError(`${label} must be plain data`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.getOwnPropertyNames(value);
  const keys = names.filter((key) => descriptors[key].enumerable);
  if (names.some((key) => ["__proto__", "prototype", "constructor"].includes(key))) {
    throw new TypeError(`${label} contains a forbidden key`);
  }
  if (isArray) {
    if (
      names.some((key) => key !== "length" && !/^(?:0|[1-9]\d*)$/.test(key)) ||
      keys.length !== value.length ||
      !Object.hasOwn(descriptors, "length") ||
      descriptors.length.enumerable ||
      !Object.hasOwn(descriptors.length, "value")
    ) {
      throw new TypeError(`${label} must be a dense plain list`);
    }
  } else if (names.length !== keys.length) {
    throw new TypeError(`${label} must be plain data`);
  }
  if (keys.some((key) => !descriptors[key].enumerable || !Object.hasOwn(descriptors[key], "value"))) {
    throw new TypeError(`${label} must be plain data`);
  }
  stack.add(value);
  try {
    for (const key of keys) snapshotSurfaceValue(descriptors[key].value, `${label}.${key}`, stack);
  } finally {
    stack.delete(value);
  }
}

function snapshotSurfaceInput(value) {
  snapshotSurfaceValue(value, "surfaceArtifact");
  try {
    return structuredClone(value);
  } catch {
    throw new TypeError("surfaceArtifact must be cloneable plain data");
  }
}

function surfaceRecord(value, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} must be plain data`);
  }
  return value;
}

function surfaceExact(value, keys, requiredKeys, label) {
  const input = surfaceRecord(value, label);
  for (const key of Object.keys(input)) if (!keys.has(key)) throw new TypeError(`${label}.${key} is not supported`);
  for (const key of requiredKeys) if (!Object.hasOwn(input, key)) throw new TypeError(`${label}.${key} is required`);
  return input;
}

function normalizedSurfaceText(value, label) {
  if (typeof value !== "string" || surfaceUnpairedSurrogate.test(value) || surfaceUnicodeControl.test(value)) {
    throw new TypeError(`${label} must be safe plain text`);
  }
  const normalized = value.normalize("NFKC").trim().replace(/\s+/gu, " ");
  if (!normalized || surfaceUnicodeControl.test(normalized) || surfaceUnpairedSurrogate.test(normalized)) {
    throw new TypeError(`${label} must be safe plain text`);
  }
  return normalized;
}

function surfaceText(value, label, maximum) {
  const normalized = normalizedSurfaceText(value, label);
  if (
    normalized.length > maximum ||
    surfaceMarkup.test(normalized) ||
    surfaceScheme.test(normalized) ||
    surfaceBareHost.test(normalized) ||
    surfaceEmail.test(normalized) ||
    surfacePhone.test(normalized) ||
    surfaceSecret.test(normalized)
  ) {
    throw new TypeError(`${label} must be safe plain text`);
  }
  return normalized;
}

function surfaceReference(value, label) {
  const normalized = normalizedSurfaceText(value, label);
  const namespace = normalized.split(":", 1)[0];
  if (
    normalized !== value ||
    !surfaceRef.test(normalized) ||
    surfaceBareHost.test(normalized) ||
    surfaceEmail.test(normalized) ||
    surfacePhone.test(normalized) ||
    surfaceSecret.test(normalized) ||
    (surfaceScheme.test(normalized) && !surfaceRefNamespaces.has(namespace))
  )
    throw new TypeError(`${label} must be a stable reference`);
  return normalized;
}

function surfaceDigest(value, label, namespaces) {
  const normalized = normalizedSurfaceText(value, label);
  const match = surfaceDigestReference.exec(normalized);
  if (
    normalized !== value ||
    !match ||
    !namespaces.has(match[1]) ||
    surfaceMarkup.test(normalized) ||
    surfaceScheme.test(match[2]) ||
    surfaceBareHost.test(match[2]) ||
    surfaceEmail.test(match[2]) ||
    surfaceFormattedPhone.test(match[2]) ||
    surfaceSsn.test(match[2]) ||
    surfaceIpv4.test(match[2]) ||
    surfaceSecret.test(match[2])
  ) {
    throw new TypeError(`${label} must be a digest reference`);
  }
  return normalized;
}

function surfaceRevision(value, label) {
  const normalized = normalizedSurfaceText(value, label);
  if (normalized !== value || !/^[a-f0-9]{64}$/u.test(normalized))
    throw new TypeError(`${label} must be a digest revision`);
  return surfaceDigest(`artifact:${normalized}`, label, surfaceArtifactReferenceNamespaces).slice("artifact:".length);
}

function surfaceEnum(value, label, maximum) {
  if (typeof value !== "string" || !/^[a-z_]+$/.test(value) || value.length > maximum) {
    throw new TypeError(`${label} must be a supported identifier`);
  }
  return value;
}

function surfaceList(value, label, maximum) {
  if (!Array.isArray(value) || value.length > maximum)
    throw new TypeError(`${label} must be a list of at most ${maximum}`);
  return value;
}

function surfaceEvidence(value, index) {
  const input = surfaceExact(
    value,
    new Set(["evidenceRef", "trust", "availability"]),
    ["evidenceRef", "trust", "availability"],
    `evidence[${index}]`,
  );
  const availability = surfaceText(input.availability, `evidence[${index}].availability`, 16);
  const trust = surfaceEnum(input.trust, `evidence[${index}].trust`, 64);
  if (!surfaceTrustLabels.includes(trust) || !["available", "unavailable"].includes(availability)) {
    throw new TypeError(`evidence[${index}] has an unsupported trust state`);
  }
  if ((availability === "available") !== (trust !== "unavailable_source")) {
    throw new TypeError(`evidence[${index}] must bind availability to trust`);
  }
  return Object.freeze({
    evidenceRef: surfaceDigest(input.evidenceRef, `evidence[${index}].evidenceRef`, surfaceEvidenceReferenceNamespaces),
    trust,
    availability,
  });
}

function surfaceLink(value, index) {
  const input = surfaceExact(
    value,
    new Set(["linkRef", "availability"]),
    ["linkRef", "availability"],
    `links[${index}]`,
  );
  if (input.availability !== "available") throw new TypeError(`links[${index}].availability is not supported`);
  return Object.freeze({
    linkRef: surfaceDigest(input.linkRef, `links[${index}].linkRef`, surfaceLinkReferenceNamespaces),
    availability: "available",
  });
}

export function validateCompactSurfaceText(value, label, maximum) {
  return surfaceText(value, label, maximum);
}

export function validateStableSurfaceReference(value, label) {
  return surfaceReference(value, label);
}

export function validateSurfaceArtifact(value) {
  const input = surfaceExact(
    snapshotSurfaceInput(value),
    new Set(["schemaVersion", "artifactRef", "revision", "kind", "state", "evidence", "links"]),
    ["schemaVersion", "artifactRef", "revision", "kind", "state", "evidence"],
    "surfaceArtifact",
  );
  if (input.schemaVersion !== 1) throw new TypeError("surfaceArtifact.schemaVersion is not supported");
  const kind = surfaceEnum(input.kind, "surfaceArtifact.kind", 48);
  const state = surfaceEnum(input.state, "surfaceArtifact.state", 32);
  if (!surfaceArtifactKinds.includes(kind) || !surfaceArtifactStates.includes(state)) {
    throw new TypeError("surfaceArtifact has an unsupported kind or state");
  }
  const evidence = surfaceList(input.evidence, "surfaceArtifact.evidence", 12).map(surfaceEvidence);
  const links = surfaceList(Object.hasOwn(input, "links") ? input.links : [], "surfaceArtifact.links", 3).map(
    surfaceLink,
  );
  if (new Set(evidence.map((item) => item.evidenceRef)).size !== evidence.length)
    throw new TypeError("surfaceArtifact.evidence is duplicated");
  if (new Set(links.map((item) => item.linkRef)).size !== links.length)
    throw new TypeError("surfaceArtifact.links is duplicated");
  return Object.freeze({
    schemaVersion: 1,
    artifactRef: surfaceDigest(input.artifactRef, "surfaceArtifact.artifactRef", surfaceArtifactReferenceNamespaces),
    revision: surfaceRevision(input.revision, "surfaceArtifact.revision"),
    kind,
    state,
    evidence: Object.freeze(evidence),
    links: Object.freeze(links),
  });
}
