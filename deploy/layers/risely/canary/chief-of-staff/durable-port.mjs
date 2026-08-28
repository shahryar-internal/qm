import { types as utilTypes } from "node:util";
import { PrincipalBinding } from "../shared-contracts/index.mjs";
import {
  assertHash,
  assertInteger,
  assertRecord,
  assertRef,
  parseInstant,
  snapshotPlainJson,
  fail,
} from "./validation.mjs";

const requiredMethods = Object.freeze([
  "reconcileScheduleTransaction",
  "claimDueJob",
  "completeJobAndAppendOutboxTransaction",
  "claimOutbox",
  "acknowledgeOutbox",
  "releaseExpiredClaims",
]);
const ceoIdentity = PrincipalBinding.identity;
const sha256Canonical = PrincipalBinding.hash;
const brandedPorts = new WeakSet();
const claimTtlSeconds = 60;
const serverClockOperations = new Set(["claimDueJob", "claimOutbox", "releaseExpiredClaims"]);
const authorityKeys = Object.freeze([
  "organizationRef",
  "deploymentRef",
  "principalRef",
  "credentialOwnerRef",
  "connectionRef",
  "calendarAccountRef",
  "audienceRef",
  "destinationRef",
]);
const methodPayloadKeys = Object.freeze({
  reconcileScheduleTransaction: Object.freeze([
    "planHash",
    "desiredJobsHash",
    "cancellations",
    "cancellationsHash",
    "expectedStoreRevision",
  ]),
  claimDueJob: Object.freeze([
    "jobId",
    "scheduleRevision",
    "expectedJobRevision",
    "expectedClaimFence",
    "claimFence",
    "claimTtlSeconds",
  ]),
  completeJobAndAppendOutboxTransaction: Object.freeze([
    "jobId",
    "scheduleRevision",
    "expectedJobRevision",
    "claimFence",
    "outboxHash",
    "artifactHash",
  ]),
  claimOutbox: Object.freeze([
    "outboxId",
    "expectedOutboxRevision",
    "expectedClaimFence",
    "claimFence",
    "claimTtlSeconds",
  ]),
  acknowledgeOutbox: Object.freeze(["outboxId", "expectedOutboxRevision", "claimFence", "receiptHash"]),
  releaseExpiredClaims: Object.freeze(["serverClockRequired", "limit"]),
});
const secretKey =
  /(?:access.?token|refresh.?token|secret|password|authorization|cookie|api.?key|credential(?:value|material))/i;
const secretValue = /^(?:Bearer\s|xox[a-z]-|AIza|sk-)/;

const rejectSecretShape = (value) => {
  if (typeof value === "string" && secretValue.test(value)) fail("durable_secret_material_rejected");
  if (Array.isArray(value)) {
    for (const entry of value) rejectSecretShape(entry);
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      if (secretKey.test(key)) fail("durable_secret_material_rejected");
      rejectSecretShape(entry);
    }
  }
};

const assertAuthority = (authority) => {
  assertRecord(authority, authorityKeys, "invalid_durable_authority");
  const normalized = Object.freeze(Object.fromEntries(authorityKeys.map((key) => [key, assertRef(authority[key])])));
  if (
    normalized.organizationRef !== ceoIdentity.organizationRef ||
    normalized.deploymentRef !== ceoIdentity.deploymentRef ||
    normalized.principalRef !== ceoIdentity.principalRef ||
    normalized.credentialOwnerRef !== ceoIdentity.credentialOwnerRef ||
    normalized.audienceRef !== ceoIdentity.audienceRef
  ) {
    fail("durable_authority_mismatch");
  }
  return normalized;
};

const assertNullableRef = (value) => (value === null ? null : assertRef(value));

const cancellationKeys = Object.freeze([
  "cancellationId",
  "organizationRef",
  "deploymentRef",
  "principalRef",
  "credentialOwnerRef",
  "connectionRef",
  "calendarAccountRef",
  "audienceRef",
  "audience",
  "destinationRef",
  "destination",
  "meetingKey",
  "jobId",
  "scheduleRevision",
  "expectedJobRevision",
  "expectedClaimFence",
  "expectedPlanHash",
  "expectedStatus",
  "fencedCasRequired",
  "reason",
]);

const normalizeCancellation = (input) => {
  assertRecord(input, cancellationKeys, "invalid_cancellation_cas");
  if (
    input.audience !== "ceo_private" ||
    !["slack_ceo_dm", "qm_ceo_inbox"].includes(input.destination) ||
    !["scheduled", "leased"].includes(input.expectedStatus) ||
    !["provider_cancelled", "meeting_ineligible", "schedule_moved_or_changed"].includes(input.reason) ||
    input.fencedCasRequired !== true ||
    (input.expectedStatus === "scheduled" && input.expectedClaimFence !== null) ||
    (input.expectedStatus === "leased" && input.expectedClaimFence === null)
  ) {
    fail("invalid_cancellation_cas");
  }
  const normalized = Object.freeze({
    cancellationId: assertHash(input.cancellationId),
    organizationRef: assertRef(input.organizationRef),
    deploymentRef: assertRef(input.deploymentRef),
    principalRef: assertRef(input.principalRef),
    credentialOwnerRef: assertRef(input.credentialOwnerRef),
    connectionRef: assertRef(input.connectionRef),
    calendarAccountRef: assertRef(input.calendarAccountRef),
    audienceRef: assertRef(input.audienceRef),
    audience: input.audience,
    destinationRef: assertRef(input.destinationRef),
    destination: input.destination,
    meetingKey: assertHash(input.meetingKey),
    jobId: assertHash(input.jobId),
    scheduleRevision: assertHash(input.scheduleRevision),
    expectedJobRevision: assertInteger(input.expectedJobRevision, 1, Number.MAX_SAFE_INTEGER),
    expectedClaimFence: assertNullableRef(input.expectedClaimFence),
    expectedPlanHash: assertHash(input.expectedPlanHash),
    expectedStatus: input.expectedStatus,
    fencedCasRequired: true,
    reason: input.reason,
  });
  const expectedCancellationId = sha256Canonical({
    jobId: normalized.jobId,
    scheduleRevision: normalized.scheduleRevision,
    jobRevision: normalized.expectedJobRevision,
    claimFence: normalized.expectedClaimFence,
    planHash: normalized.expectedPlanHash,
  });
  if (normalized.cancellationId !== expectedCancellationId) fail("invalid_cancellation_cas");
  return normalized;
};

const assertMethodPayload = (operation, payload) => {
  const keys = methodPayloadKeys[operation];
  if (!keys) fail("invalid_durable_operation");
  assertRecord(payload, keys, "invalid_durable_payload");
  if (operation === "reconcileScheduleTransaction") {
    if (!Array.isArray(payload.cancellations) || payload.cancellations.length > 1_024) {
      fail("invalid_cancellation_cas");
    }
    const cancellations = Object.freeze(payload.cancellations.map(normalizeCancellation));
    if (assertHash(payload.cancellationsHash) !== sha256Canonical(cancellations)) {
      fail("invalid_cancellation_cas");
    }
    return Object.freeze({
      planHash: assertHash(payload.planHash),
      desiredJobsHash: assertHash(payload.desiredJobsHash),
      cancellations,
      cancellationsHash: payload.cancellationsHash,
      expectedStoreRevision: assertInteger(payload.expectedStoreRevision, 0, Number.MAX_SAFE_INTEGER),
    });
  }
  if (operation === "claimDueJob") {
    if (payload.claimTtlSeconds !== claimTtlSeconds) fail("invalid_durable_claim_ttl");
    return Object.freeze({
      jobId: assertHash(payload.jobId),
      scheduleRevision: assertHash(payload.scheduleRevision),
      expectedJobRevision: assertInteger(payload.expectedJobRevision, 1, Number.MAX_SAFE_INTEGER),
      expectedClaimFence: assertNullableRef(payload.expectedClaimFence),
      claimFence: assertRef(payload.claimFence),
      claimTtlSeconds,
    });
  }
  if (operation === "completeJobAndAppendOutboxTransaction") {
    return Object.freeze({
      jobId: assertHash(payload.jobId),
      scheduleRevision: assertHash(payload.scheduleRevision),
      expectedJobRevision: assertInteger(payload.expectedJobRevision, 1, Number.MAX_SAFE_INTEGER),
      claimFence: assertRef(payload.claimFence),
      outboxHash: assertHash(payload.outboxHash),
      artifactHash: assertHash(payload.artifactHash),
    });
  }
  if (operation === "claimOutbox") {
    if (payload.claimTtlSeconds !== claimTtlSeconds) fail("invalid_durable_claim_ttl");
    return Object.freeze({
      outboxId: assertHash(payload.outboxId),
      expectedOutboxRevision: assertInteger(payload.expectedOutboxRevision, 1, Number.MAX_SAFE_INTEGER),
      expectedClaimFence: assertNullableRef(payload.expectedClaimFence),
      claimFence: assertRef(payload.claimFence),
      claimTtlSeconds,
    });
  }
  if (operation === "acknowledgeOutbox") {
    return Object.freeze({
      outboxId: assertHash(payload.outboxId),
      expectedOutboxRevision: assertInteger(payload.expectedOutboxRevision, 1, Number.MAX_SAFE_INTEGER),
      claimFence: assertRef(payload.claimFence),
      receiptHash: assertHash(payload.receiptHash),
    });
  }
  if (payload.serverClockRequired !== true) fail("durable_server_clock_required");
  return Object.freeze({ serverClockRequired: true, limit: assertInteger(payload.limit, 1, 1_000) });
};

const durableRequestIdentity = (operation, authority, payload) =>
  Object.freeze({ schemaVersion: 1, operation, authority, payload });

export const deriveDurableRequestId = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(value, ["operation", "authority", "payload"], "invalid_durable_request_identity");
  if (!requiredMethods.includes(value.operation)) fail("invalid_durable_operation");
  const authority = assertAuthority(value.authority);
  const payload = assertMethodPayload(value.operation, value.payload);
  return sha256Canonical(durableRequestIdentity(value.operation, authority, payload));
};

const normalizeMethodRequest = (operation, input) => {
  const request = snapshotPlainJson(input);
  rejectSecretShape(request);
  assertRecord(request, ["schemaVersion", "operation", "requestId", "authority", "payload"], "invalid_durable_request");
  if (request.schemaVersion !== 1 || request.operation !== operation) fail("invalid_durable_request");
  const authority = assertAuthority(request.authority);
  const payload = assertMethodPayload(operation, request.payload);
  if (
    operation === "reconcileScheduleTransaction" &&
    payload.cancellations.some(
      (cancellation) =>
        cancellation.organizationRef !== authority.organizationRef ||
        cancellation.deploymentRef !== authority.deploymentRef ||
        cancellation.principalRef !== authority.principalRef ||
        cancellation.credentialOwnerRef !== authority.credentialOwnerRef ||
        cancellation.connectionRef !== authority.connectionRef ||
        cancellation.calendarAccountRef !== authority.calendarAccountRef ||
        cancellation.audienceRef !== authority.audienceRef ||
        cancellation.destinationRef !== authority.destinationRef,
    )
  ) {
    fail("cancellation_authority_mismatch");
  }
  const requestId = assertHash(request.requestId);
  if (requestId !== sha256Canonical(durableRequestIdentity(operation, authority, payload))) {
    fail("durable_request_id_mismatch");
  }
  return Object.freeze({
    schemaVersion: 1,
    operation,
    requestId,
    authority,
    payload,
  });
};

const normalizeMethodResult = (operation, requestId, input) => {
  const result = snapshotPlainJson(input);
  rejectSecretShape(result);
  assertRecord(
    result,
    ["schemaVersion", "operation", "requestId", "status", "stateRevision", "resultHash"],
    "invalid_durable_result",
  );
  if (
    result.schemaVersion !== 1 ||
    result.operation !== operation ||
    result.requestId !== requestId ||
    !["applied", "conflict", "empty"].includes(result.status)
  ) {
    fail("invalid_durable_result");
  }
  return Object.freeze({
    schemaVersion: 1,
    operation,
    requestId,
    status: result.status,
    stateRevision: assertInteger(result.stateRevision, 0, Number.MAX_SAFE_INTEGER),
    resultHash: assertHash(result.resultHash),
  });
};

const unresolvedServerClockResult = (operation, requestId) => {
  const identity = Object.freeze({ operation, requestId, status: "unresolved", serverClockReceiptRequired: true });
  return Object.freeze({
    schemaVersion: 1,
    operation,
    requestId,
    status: "unresolved",
    stateRevision: 0,
    resultHash: sha256Canonical(identity),
    serverClockReceiptRequired: true,
  });
};

export const bindDurableChiefOfStaffPort = (port) => {
  if (
    !port ||
    typeof port !== "object" ||
    utilTypes.isProxy(port) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(port)) ||
    Object.getOwnPropertySymbols(port).length !== 0
  ) {
    fail("invalid_durable_port");
  }
  const descriptors = Object.getOwnPropertyDescriptors(port);
  if (
    Object.keys(descriptors).length !== requiredMethods.length ||
    requiredMethods.some((method) => {
      const descriptor = descriptors[method];
      return (
        !descriptor ||
        !Object.hasOwn(descriptor, "value") ||
        Object.hasOwn(descriptor, "get") ||
        Object.hasOwn(descriptor, "set") ||
        descriptor.enumerable !== true ||
        typeof descriptor.value !== "function" ||
        utilTypes.isProxy(descriptor.value)
      );
    })
  ) {
    fail("invalid_durable_port");
  }
  const bound = Object.freeze(
    Object.fromEntries(
      requiredMethods.map((method) => {
        const implementation = descriptors[method].value;
        return [
          method,
          async (input) => {
            const request = normalizeMethodRequest(method, input);
            if (serverClockOperations.has(method)) return unresolvedServerClockResult(method, request.requestId);
            const result = await Reflect.apply(implementation, undefined, [request]);
            return normalizeMethodResult(method, request.requestId, result);
          },
        ];
      }),
    ),
  );
  brandedPorts.add(bound);
  return bound;
};

export const assertDurableChiefOfStaffPort = (port) => {
  if (!brandedPorts.has(port)) fail("untrusted_durable_port");
  return port;
};

export const buildOutboxRecord = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(
    value,
    [
      "organizationRef",
      "deploymentRef",
      "principalRef",
      "credentialOwnerRef",
      "connectionRef",
      "calendarAccountRef",
      "audienceRef",
      "audience",
      "destinationRef",
      "planHash",
      "jobRevision",
      "claimFence",
      "jobId",
      "meetingKey",
      "destination",
      "artifactHash",
      "artifactRef",
      "createdAt",
    ],
    "invalid_outbox_record",
  );
  const identity = Object.freeze({
    organizationRef: assertRef(value.organizationRef),
    deploymentRef: assertRef(value.deploymentRef),
    principalRef: assertRef(value.principalRef),
    credentialOwnerRef: assertRef(value.credentialOwnerRef),
    connectionRef: assertRef(value.connectionRef),
    calendarAccountRef: assertRef(value.calendarAccountRef),
    audienceRef: assertRef(value.audienceRef),
    audience: value.audience,
    destinationRef: assertRef(value.destinationRef),
    planHash: assertHash(value.planHash),
    jobRevision: assertInteger(value.jobRevision, 1, Number.MAX_SAFE_INTEGER),
    claimFence: assertRef(value.claimFence),
    jobId: assertHash(value.jobId),
    meetingKey: assertHash(value.meetingKey),
    destination: value.destination,
    artifactHash: assertHash(value.artifactHash),
    artifactRef: assertRef(value.artifactRef),
  });
  if (identity.audience !== "ceo_private" || !["qm_ceo_inbox", "slack_ceo_dm"].includes(identity.destination)) {
    fail("invalid_outbox_destination");
  }
  if (
    identity.organizationRef !== ceoIdentity.organizationRef ||
    identity.deploymentRef !== ceoIdentity.deploymentRef ||
    identity.principalRef !== ceoIdentity.principalRef ||
    identity.credentialOwnerRef !== ceoIdentity.credentialOwnerRef ||
    identity.audienceRef !== ceoIdentity.audienceRef
  ) {
    fail("outbox_authority_mismatch");
  }
  const createdAt = parseInstant(value.createdAt).toISOString();
  const outboxId = sha256Canonical(identity);
  return Object.freeze({
    schemaVersion: 1,
    outboxId,
    idempotencyKey: outboxId,
    ...identity,
    createdAt,
    providerEffectAllowed: false,
    requiresDurableClaim: true,
  });
};

export const buildSchedulerPollPlan = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(
    value,
    [
      "organizationRef",
      "deploymentRef",
      "schedulerRef",
      "principalRef",
      "credentialOwnerRef",
      "connectionRef",
      "calendarAccountRef",
      "audienceRef",
      "audience",
      "destinationRef",
      "destination",
      "runAt",
      "lookAheadDays",
    ],
    "invalid_poll_plan",
  );
  const runAt = parseInstant(value.runAt);
  if (!Number.isInteger(value.lookAheadDays) || value.lookAheadDays < 2 || value.lookAheadDays > 31) {
    fail("invalid_poll_plan");
  }
  const schedulerRef = assertRef(value.schedulerRef);
  const organizationRef = assertRef(value.organizationRef);
  const deploymentRef = assertRef(value.deploymentRef);
  const principalRef = assertRef(value.principalRef);
  const credentialOwnerRef = assertRef(value.credentialOwnerRef);
  const connectionRef = assertRef(value.connectionRef);
  const calendarAccountRef = assertRef(value.calendarAccountRef);
  const audienceRef = assertRef(value.audienceRef);
  const audience = value.audience;
  const destinationRef = assertRef(value.destinationRef);
  const destination = value.destination;
  if (audience !== "ceo_private" || !["slack_ceo_dm", "qm_ceo_inbox"].includes(destination)) {
    fail("invalid_poll_plan");
  }
  if (
    organizationRef !== ceoIdentity.organizationRef ||
    deploymentRef !== ceoIdentity.deploymentRef ||
    principalRef !== ceoIdentity.principalRef ||
    credentialOwnerRef !== ceoIdentity.credentialOwnerRef ||
    audienceRef !== ceoIdentity.audienceRef
  ) {
    fail("poll_authority_mismatch");
  }
  const window = Object.freeze({
    from: runAt.toISOString(),
    to: new Date(runAt.valueOf() + value.lookAheadDays * 86_400_000).toISOString(),
  });
  const pollId = sha256Canonical({
    organizationRef,
    deploymentRef,
    schedulerRef,
    principalRef,
    credentialOwnerRef,
    connectionRef,
    calendarAccountRef,
    audienceRef,
    audience,
    destinationRef,
    destination,
    runAt: runAt.toISOString(),
    lookAheadDays: value.lookAheadDays,
    window,
  });
  return Object.freeze({
    schemaVersion: 1,
    pollId,
    idempotencyKey: pollId,
    organizationRef,
    deploymentRef,
    schedulerRef,
    principalRef,
    credentialOwnerRef,
    connectionRef,
    calendarAccountRef,
    audienceRef,
    audience,
    destinationRef,
    destination,
    runAt: runAt.toISOString(),
    lookAheadDays: value.lookAheadDays,
    window,
    durableStateRequired: true,
    inMemoryStateAllowed: false,
  });
};
