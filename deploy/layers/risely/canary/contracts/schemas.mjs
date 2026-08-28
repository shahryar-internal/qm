const ID = "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$";
const HASH = "^[0-9a-f]{64}$";
const CAPABILITY = "^[a-z][a-z0-9-]{0,62}(?:\\.[a-z][a-z0-9-]{0,62})+$";

const strictObject = (properties, required) => ({
  type: "object",
  additionalProperties: false,
  required,
  properties,
});

const contract = (type, properties, required) =>
  strictObject(
    {
      contractType: { const: type },
      contractVersion: { const: 1 },
      ...properties,
    },
    ["contractType", "contractVersion", ...required],
  );

const id = { type: "string", minLength: 1, maxLength: 256, pattern: ID };
const text = { type: "string", minLength: 1, maxLength: 4096 };
const timestamp = { type: "string", format: "utc-date-time" };
const hash = { type: "string", pattern: HASH };

export const jsonValueSchema = {
  $id: "https://schemas.risely.ai/canary/json-value.v1.schema.json",
  anyOf: [
    { type: "null" },
    { type: "boolean" },
    { type: "number" },
    { type: "string", maxLength: 1000000 },
    {
      type: "array",
      maxItems: 1024,
      items: { $ref: "https://schemas.risely.ai/canary/json-value.v1.schema.json" },
    },
    {
      type: "object",
      maxProperties: 256,
      propertyNames: { type: "string", minLength: 1, maxLength: 128 },
      additionalProperties: { $ref: "https://schemas.risely.ai/canary/json-value.v1.schema.json" },
    },
  ],
};

const jsonObject = {
  type: "object",
  maxProperties: 256,
  propertyNames: { type: "string", minLength: 1, maxLength: 128 },
  additionalProperties: { $ref: jsonValueSchema.$id },
};

const agentRef = strictObject(
  {
    id,
    version: { type: "string", minLength: 1, maxLength: 128 },
  },
  ["id", "version"],
);

const artifactDigest = strictObject(
  {
    artifactId: id,
    sha256: hash,
  },
  ["artifactId", "sha256"],
);

const publication = strictObject(
  {
    system: { enum: ["notion", "qm"] },
    destinationRef: id,
    externalId: id,
    url: { type: "string", minLength: 1, maxLength: 2048, format: "secure-https-url" },
    publishedAt: timestamp,
  },
  ["system", "destinationRef", "externalId", "publishedAt"],
);

export const actorSchema = {
  $id: "https://schemas.risely.ai/canary/actor.v1.schema.json",
  ...contract(
    "actor",
    {
      principalRef: id,
      qmPrincipalId: id,
      externalPrincipalRef: id,
      agent: agentRef,
      surface: { enum: ["slack", "web", "schedule", "system"] },
      scopeRef: id,
      audienceRef: id,
      credentialOwnerRef: id,
    },
    ["principalRef", "qmPrincipalId", "agent", "surface", "scopeRef", "audienceRef", "credentialOwnerRef"],
  ),
};

export const runSchema = {
  $id: "https://schemas.risely.ai/canary/run.v1.schema.json",
  ...contract(
    "run",
    {
      runId: id,
      sessionId: id,
      parentRunId: id,
      actor: { $ref: actorSchema.$id },
      trigger: { enum: ["human", "schedule", "system"] },
      agentVersion: { type: "string", minLength: 1, maxLength: 128 },
      policySnapshotHash: hash,
      inputHash: hash,
      startedAt: timestamp,
    },
    ["runId", "sessionId", "actor", "trigger", "agentVersion", "policySnapshotHash", "inputHash", "startedAt"],
  ),
};

export const evidenceRefSchema = {
  $id: "https://schemas.risely.ai/canary/evidence-ref.v1.schema.json",
  ...contract(
    "evidence-ref",
    {
      evidenceId: id,
      source: { enum: ["brain", "gmail", "calendar", "clarify", "notion", "slack"] },
      sourceRecordRef: id,
      sourceUrl: { type: "string", minLength: 1, maxLength: 2048, format: "secure-https-url" },
      observedAt: timestamp,
      fetchedAt: timestamp,
      contentSha256: hash,
      audienceRef: id,
      sensitivity: { enum: ["internal", "customer", "commercial", "personal"] },
      trust: { const: "untrusted_external" },
    },
    ["evidenceId", "source", "sourceRecordRef", "fetchedAt", "contentSha256", "audienceRef", "sensitivity", "trust"],
  ),
};

export const artifactSchema = {
  $id: "https://schemas.risely.ai/canary/artifact.v1.schema.json",
  ...contract(
    "artifact",
    {
      artifactId: id,
      kind: id,
      runId: id,
      ownerScopeRef: id,
      audienceRef: id,
      storageRef: { type: "string", minLength: 1, maxLength: 2048 },
      mediaType: { type: "string", minLength: 1, maxLength: 255 },
      sizeBytes: { type: "integer", minimum: 0, maximum: 1000000000 },
      sha256: hash,
      evidenceIds: { type: "array", uniqueItems: true, maxItems: 256, items: id },
      createdAt: timestamp,
    },
    [
      "artifactId",
      "kind",
      "runId",
      "ownerScopeRef",
      "audienceRef",
      "storageRef",
      "mediaType",
      "sizeBytes",
      "sha256",
      "evidenceIds",
      "createdAt",
    ],
  ),
};

export const workflowArtifactSchema = {
  $id: "https://schemas.risely.ai/canary/workflow-artifact.v1.schema.json",
  ...contract(
    "workflow-artifact",
    {
      workflowArtifactId: id,
      runId: id,
      workflow: id,
      title: { type: "string", minLength: 1, maxLength: 512 },
      status: { enum: ["draft", "proposed", "published", "archived"] },
      artifact: { $ref: artifactSchema.$id },
      evidenceRefs: {
        type: "array",
        maxItems: 256,
        items: { $ref: evidenceRefSchema.$id },
      },
      publication,
      createdAt: timestamp,
    },
    ["workflowArtifactId", "runId", "workflow", "title", "status", "artifact", "evidenceRefs", "createdAt"],
  ),
  allOf: [
    {
      if: { properties: { status: { const: "published" } }, required: ["status"] },
      then: { required: ["publication"], properties: { publication: {} } },
    },
  ],
};

export const actionProposalSchema = {
  $id: "https://schemas.risely.ai/canary/action-proposal.v1.schema.json",
  ...contract(
    "action-proposal",
    {
      proposalId: id,
      runId: id,
      actor: { $ref: actorSchema.$id },
      capability: { type: "string", pattern: CAPABILITY, maxLength: 255 },
      capabilityVersion: { type: "integer", minimum: 1, maximum: 2147483647 },
      provider: id,
      credentialRef: id,
      subjectRef: id,
      target: jsonObject,
      payload: jsonObject,
      artifactRefs: { type: "array", maxItems: 64, items: artifactDigest },
      evidenceRefs: { type: "array", maxItems: 256, items: { $ref: evidenceRefSchema.$id } },
      capturedState: jsonObject,
      preconditions: { type: "array", maxItems: 64, items: jsonObject },
      createdAt: timestamp,
      expiresAt: timestamp,
      semanticFingerprint: hash,
      effectKey: hash,
      proposalHash: hash,
    },
    [
      "proposalId",
      "runId",
      "actor",
      "capability",
      "capabilityVersion",
      "provider",
      "credentialRef",
      "subjectRef",
      "target",
      "payload",
      "artifactRefs",
      "evidenceRefs",
      "capturedState",
      "preconditions",
      "createdAt",
      "expiresAt",
      "semanticFingerprint",
      "effectKey",
      "proposalHash",
    ],
  ),
};

export const approvalSchema = {
  $id: "https://schemas.risely.ai/canary/approval.v1.schema.json",
  ...contract(
    "approval",
    {
      approvalId: id,
      proposalId: id,
      proposalHash: hash,
      decision: { enum: ["approve_once", "reject"] },
      approverPrincipalRef: id,
      surface: { enum: ["slack", "web"] },
      decidedAt: timestamp,
      expiresAt: timestamp,
    },
    [
      "approvalId",
      "proposalId",
      "proposalHash",
      "decision",
      "approverPrincipalRef",
      "surface",
      "decidedAt",
      "expiresAt",
    ],
  ),
};

export const receiptSchema = {
  $id: "https://schemas.risely.ai/canary/receipt.v1.schema.json",
  ...contract(
    "receipt",
    {
      receiptId: id,
      proposalId: id,
      proposalHash: hash,
      effectKey: hash,
      claimId: id,
      credentialRef: id,
      status: { enum: ["verified", "refused", "stale", "failed", "outcome_unknown"] },
      provider: id,
      providerAccountRef: id,
      providerOperationIds: {
        type: "object",
        propertyNames: { pattern: "^[A-Za-z][A-Za-z0-9._-]{0,127}$" },
        additionalProperties: { type: "string", minLength: 1, maxLength: 512 },
      },
      attemptedAt: timestamp,
      completedAt: timestamp,
      responseHash: hash,
      preflightResults: jsonObject,
      errorCode: { type: "string", minLength: 1, maxLength: 255, pattern: "^[a-z0-9][a-z0-9._-]*$" },
    },
    [
      "receiptId",
      "proposalId",
      "proposalHash",
      "effectKey",
      "claimId",
      "credentialRef",
      "status",
      "provider",
      "providerAccountRef",
      "providerOperationIds",
      "attemptedAt",
      "preflightResults",
    ],
  ),
  allOf: [
    {
      if: { properties: { status: { const: "verified" } }, required: ["status"] },
      then: {
        required: ["completedAt", "responseHash"],
        properties: {
          completedAt: {},
          responseHash: {},
          providerOperationIds: { type: "object", minProperties: 1 },
        },
      },
    },
    {
      if: { properties: { status: { not: { const: "verified" } } }, required: ["status"] },
      then: { required: ["errorCode"], properties: { errorCode: {} } },
    },
    {
      if: { properties: { status: { not: { const: "outcome_unknown" } } }, required: ["status"] },
      then: { required: ["completedAt"], properties: { completedAt: {} } },
    },
  ],
};

export const contractSchemas = Object.freeze({
  actor: actorSchema,
  run: runSchema,
  evidenceRef: evidenceRefSchema,
  artifact: artifactSchema,
  workflowArtifact: workflowArtifactSchema,
  actionProposal: actionProposalSchema,
  approval: approvalSchema,
  receipt: receiptSchema,
});

export const supportingSchemas = Object.freeze([jsonValueSchema]);
