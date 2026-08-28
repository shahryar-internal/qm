import { types } from "node:util";
import { assertRuntimeScope } from "../runtime-scope/index.mjs";

const DIGEST = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

export const qmShadowIngressRoute = Object.freeze({
  method: "POST",
  pathWithQuery: "/internal/v1/qm-shadow/observations",
  maxBodyBytes: 16 * 1024,
});

export const qmShadowIngressPolicy = Object.freeze({
  contractType: "qm-shadow-ingress-policy",
  contractVersion: 1,
  allowedSources: Object.freeze(["slack_dm", "web_chat"]),
  persistence: "same_qm_risely_agent_runtime_workflow_runs",
  retainedContent: "digest_only",
  providerInvocationAllowed: false,
  providerEffectBudget: 0,
});

export const qmShadowActivationBlockers = Object.freeze([
  "upstream_qm_turn_observer_deployment_binding_unavailable",
  "upstream_qm_observer_durable_outbox_postgres_acceptance_unverified",
  "qm_surface_identity_bridge_unverified",
  "route_scoped_qm_observer_signing_key_unprovisioned",
  "same_qm_runtime_schema_not_live_verified",
  "private_slack_and_web_acceptance_not_completed",
]);

export class QmShadowIngressError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "QmShadowIngressError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new QmShadowIngressError(code, message);
}

function snapshot(value, scope, label) {
  try {
    return scope.contracts.PrincipalBinding.snapshot(value, label);
  } catch {
    fail("invalid_shadow_observation", `${label} must be canonical plain JSON`);
  }
}

function exact(value, fields, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  ) {
    fail("invalid_shadow_observation", `${label} has unexpected or missing fields`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    fail("invalid_shadow_observation", `${label} must be a bounded identifier`);
  }
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) {
    fail("invalid_shadow_observation", `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function instant(value, label) {
  if (
    typeof value !== "string" ||
    !INSTANT.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    fail("invalid_shadow_observation", `${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function equal(actual, expected, label) {
  if (actual !== expected) fail("shadow_identity_mismatch", `${label} is outside the deployment profile`);
}

function surfaceAuthority(scope, source) {
  if (source === "slack_dm") {
    return Object.freeze({
      actorSurface: "slack",
      audienceRef: scope.profile.audiences.slack.audienceRef,
      surfacePrincipalRef: scope.profile.audiences.slack.principalRef,
      workspaceRef: scope.profile.anchors.slackTeamRef,
    });
  }
  if (source === "web_chat") {
    return Object.freeze({
      actorSurface: "web",
      audienceRef: scope.profile.audiences.qm.audienceRef,
      surfacePrincipalRef: scope.profile.audiences.qm.principalRef,
      workspaceRef: scope.profile.anchors.workspaceRef,
    });
  }
  fail("unsupported_shadow_source", "QM shadow source is not supported");
}

export function validateQmShadowObservation(value, runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  const input = exact(
    snapshot(value, scope, "QM shadow observation"),
    [
      "contractType",
      "contractVersion",
      "profileRef",
      "profileSha256",
      "source",
      "eventRef",
      "conversationRef",
      "humanPrincipalRef",
      "qmPrincipalRef",
      "surfacePrincipalRef",
      "audienceRef",
      "workspaceRef",
      "observedAt",
      "inputSha256",
    ],
    "QM shadow observation",
  );
  if (input.contractType !== "qm-shadow-observation" || input.contractVersion !== 1) {
    fail("invalid_shadow_observation", "QM shadow observation contract is not supported");
  }
  const authority = surfaceAuthority(scope, input.source);
  const observation = Object.freeze({
    contractType: "qm-shadow-observation",
    contractVersion: 1,
    profileRef: identifier(input.profileRef, "profileRef"),
    profileSha256: digest(input.profileSha256, "profileSha256"),
    source: input.source,
    eventRef: identifier(input.eventRef, "eventRef"),
    conversationRef: identifier(input.conversationRef, "conversationRef"),
    humanPrincipalRef: identifier(input.humanPrincipalRef, "humanPrincipalRef"),
    qmPrincipalRef: identifier(input.qmPrincipalRef, "qmPrincipalRef"),
    surfacePrincipalRef: identifier(input.surfacePrincipalRef, "surfacePrincipalRef"),
    audienceRef: identifier(input.audienceRef, "audienceRef"),
    workspaceRef: identifier(input.workspaceRef, "workspaceRef"),
    observedAt: instant(input.observedAt, "observedAt"),
    inputSha256: digest(input.inputSha256, "inputSha256"),
  });
  equal(observation.profileRef, scope.profileRef, "profileRef");
  equal(observation.profileSha256, scope.profileSha256, "profileSha256");
  equal(observation.humanPrincipalRef, scope.profile.identity.humanPrincipalRef, "humanPrincipalRef");
  equal(observation.qmPrincipalRef, scope.profile.identity.qmPrincipalRef, "qmPrincipalRef");
  equal(observation.surfacePrincipalRef, authority.surfacePrincipalRef, "surfacePrincipalRef");
  equal(observation.audienceRef, authority.audienceRef, "audienceRef");
  equal(observation.workspaceRef, authority.workspaceRef, "workspaceRef");
  return Object.freeze({ observation, authority });
}

function compileRun(scope, checked, startedAt) {
  const hash = scope.contracts.PrincipalBinding.hash;
  const observationSha256 = hash(checked.observation);
  const run = Object.freeze({
    contractType: "run",
    contractVersion: 1,
    runId: `qm-shadow-run:${hash({
      profileRef: scope.profileRef,
      profileSha256: scope.profileSha256,
      source: checked.observation.source,
      eventRef: checked.observation.eventRef,
    })}`,
    sessionId: `qm-shadow-session:${hash({
      profileRef: scope.profileRef,
      profileSha256: scope.profileSha256,
      source: checked.observation.source,
      conversationRef: checked.observation.conversationRef,
    })}`,
    actor: Object.freeze({
      contractType: "actor",
      contractVersion: 1,
      principalRef: scope.domainAuthority.principalRef,
      qmPrincipalId: scope.domainAuthority.qmPrincipalId,
      externalPrincipalRef: scope.domainAuthority.externalPrincipalRef,
      agent: Object.freeze({
        id: scope.domainAuthority.agentId,
        version: scope.domainAuthority.agentVersion,
      }),
      surface: checked.authority.actorSurface,
      scopeRef: scope.domainAuthority.scopeRef,
      audienceRef: checked.authority.audienceRef,
      credentialOwnerRef: scope.domainAuthority.credentialOwnerRef,
    }),
    trigger: "human",
    agentVersion: scope.profile.agent.agentVersion,
    policySnapshotHash: hash({ policy: qmShadowIngressPolicy, observationSha256 }),
    inputHash: checked.observation.inputSha256,
    startedAt,
  });
  return Object.freeze({
    run,
    runSha256: hash(run),
    observationSha256,
  });
}

function storedPayload(record, scope) {
  if (!record || typeof record !== "object" || types.isProxy(record)) {
    fail("invalid_stored_shadow_run", "Stored QM shadow run is invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(record);
  const descriptor = descriptors.payload ?? descriptors.run;
  if (!descriptor || !("value" in descriptor)) {
    fail("invalid_stored_shadow_run", "Stored QM shadow run is invalid");
  }
  return snapshot(descriptor.value, scope, "stored QM shadow run");
}

function sameRun(scope, left, right) {
  if (!left || !right) return false;
  const { startedAt: _leftStartedAt, ...leftInvariant } = left;
  const { startedAt: _rightStartedAt, ...rightInvariant } = right;
  return scope.contracts.PrincipalBinding.hash(leftInvariant) === scope.contracts.PrincipalBinding.hash(rightInvariant);
}

function observationReceipt(scope, checked, compiled, status) {
  return Object.freeze({
    contractType: "qm-shadow-observation-receipt",
    contractVersion: 1,
    status,
    mode: "private_read_only_shadow",
    source: checked.observation.source,
    runId: compiled.run.runId,
    sessionId: compiled.run.sessionId,
    observationSha256: compiled.observationSha256,
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    retainedContent: "digest_only",
    providerInvocationAllowed: false,
    providerEffectBudget: 0,
  });
}

function exactOptions(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) {
    throw new TypeError("QM shadow ingress configuration is invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).sort();
  if (
    (keys.length !== 2 && keys.length !== 3) ||
    !keys.includes("scope") ||
    !keys.includes("store") ||
    keys.some((key) => key !== "scope" && key !== "store" && key !== "now") ||
    Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set || !descriptor.enumerable)
  ) {
    throw new TypeError("QM shadow ingress configuration is invalid");
  }
  if (descriptors.now && typeof descriptors.now.value !== "function") {
    throw new TypeError("QM shadow ingress configuration is invalid");
  }
  return Object.freeze({
    scope: descriptors.scope.value,
    store: descriptors.store.value,
    now: descriptors.now?.value ?? Date.now,
  });
}

function captureStorePort(store, scope) {
  if (!store || typeof store !== "object" || types.isProxy(store)) {
    throw new TypeError("QM shadow ingress requires a durable workflow run store");
  }
  const ownDescriptors = Object.getOwnPropertyDescriptors(store);
  const scopeDescriptor = ownDescriptors.runtimeScope;
  if (scopeDescriptor && (!("value" in scopeDescriptor) || scopeDescriptor.value !== scope)) {
    throw new TypeError("QM shadow ingress store does not match its runtime scope");
  }
  const prototype = Object.getPrototypeOf(store);
  if (!prototype || types.isProxy(prototype)) {
    throw new TypeError("QM shadow ingress requires a durable workflow run store");
  }
  const capture = (name) => {
    if (Object.hasOwn(ownDescriptors, name)) {
      throw new TypeError("QM shadow ingress requires a durable workflow run store");
    }
    const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
    if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "function") {
      throw new TypeError("QM shadow ingress requires a durable workflow run store");
    }
    return (...args) => Reflect.apply(descriptor.value, store, args);
  };
  return Object.freeze({ createRun: capture("createRun"), readRun: capture("readRun") });
}

export function createQmShadowIngress(options) {
  const { store, scope: runtimeScope, now } = exactOptions(options);
  const scope = assertRuntimeScope(runtimeScope);
  const port = captureStorePort(store, scope);
  const context = (requestHash) => {
    digest(requestHash, "requestHash");
    return Object.freeze({ principalRef: scope.domainAuthority.principalRef, requestHash });
  };
  const readExisting = async (runId, requestContext) => {
    try {
      return await port.readRun(runId, requestContext);
    } catch (error) {
      if (error?.code === "run_not_found") return null;
      throw error;
    }
  };
  return Object.freeze({
    runtimeScope: scope,
    activation: Object.freeze({
      mode: "private_read_only_shadow",
      providerInvocationAllowed: false,
      blockers: qmShadowActivationBlockers,
    }),
    async observe(value, requestHash) {
      const checked = validateQmShadowObservation(value, scope);
      const acceptedAt = now();
      if (!Number.isSafeInteger(acceptedAt) || acceptedAt < 0) {
        fail("invalid_shadow_clock", "QM shadow ingress clock is invalid");
      }
      const compiled = compileRun(scope, checked, new Date(acceptedAt).toISOString());
      const requestContext = context(requestHash);
      let existing = await readExisting(compiled.run.runId, requestContext);
      if (existing) {
        if (!sameRun(scope, storedPayload(existing, scope), compiled.run)) {
          fail("shadow_observation_conflict", "QM event identifier is already bound to another observation");
        }
        return observationReceipt(scope, checked, compiled, "duplicate");
      }
      try {
        await port.createRun(compiled.run, compiled.runSha256, requestContext);
      } catch (error) {
        if (error?.code !== "run_already_exists") throw error;
        existing = await readExisting(compiled.run.runId, requestContext);
        if (!sameRun(scope, storedPayload(existing, scope), compiled.run)) {
          fail("shadow_observation_conflict", "QM event identifier is already bound to another observation");
        }
        return observationReceipt(scope, checked, compiled, "duplicate");
      }
      return observationReceipt(scope, checked, compiled, "accepted");
    },
  });
}
