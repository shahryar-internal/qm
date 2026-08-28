import { randomUUID } from "node:crypto";
import { types } from "node:util";
import { canonicalSnapshot, sha256Canonical } from "./canonical.mjs";
import { assertRuntimeScope } from "../../../runtime-scope/index.mjs";
import { createRuntimeDomain } from "./domain.mjs";

const HASH = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;

export class CanaryServiceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CanaryServiceError";
    this.code = code;
  }
}

function exactObject(value, required, optional = []) {
  let input;
  try {
    input = canonicalSnapshot(value);
  } catch {
    throw new CanaryServiceError("invalid_request", "Request body must be canonical plain data");
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new CanaryServiceError("invalid_request", "Request body must be an object");
  }
  const keys = Object.keys(input).sort();
  const allowed = [...required, ...optional].sort();
  if (
    required.some((key) => !Object.hasOwn(input, key)) ||
    keys.length > allowed.length ||
    keys.some((key) => !allowed.includes(key))
  ) {
    throw new CanaryServiceError("invalid_request", "Request body has unexpected or missing fields");
  }
  return input;
}

function expectedBindings(value) {
  const body = exactObject(value, ["expectedRevision", "expectedStateHash", "proposalHash", "effectKey"]);
  if (
    !Number.isInteger(body.expectedRevision) ||
    body.expectedRevision < 0 ||
    !HASH.test(body.expectedStateHash) ||
    !HASH.test(body.proposalHash) ||
    !HASH.test(body.effectKey)
  ) {
    throw new CanaryServiceError("invalid_request", "Action bindings are invalid");
  }
  return body;
}

export class CanaryService {
  constructor(options) {
    if (!options || typeof options !== "object" || Array.isArray(options) || types.isProxy(options)) {
      throw new TypeError("CanaryService configuration is invalid");
    }
    const descriptors = Object.getOwnPropertyDescriptors(options);
    const optionKeys = Object.keys(descriptors).sort();
    if (
      optionKeys.some((key) => !["idFactory", "scope", "store"].includes(key)) ||
      Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set || !descriptor.enumerable)
    ) {
      throw new TypeError("CanaryService configuration contains unsupported authority switches");
    }
    const store = descriptors.store?.value;
    const idFactory = descriptors.idFactory?.value ?? randomUUID;
    let scope;
    try {
      scope = assertRuntimeScope(descriptors.scope?.value);
    } catch {
      throw new TypeError("Canary runtime scope is invalid");
    }
    if (!store) throw new TypeError("CanaryService requires a durable store");
    if (typeof idFactory !== "function" || types.isProxy(idFactory))
      throw new TypeError("CanaryService id factory is invalid");
    if (store.runtimeScope !== scope) throw new TypeError("Canary store runtime scope does not match");
    this.store = store;
    this.runtimeScope = scope;
    this.authority = scope.domainAuthority;
    this.domain = createRuntimeDomain(scope);
    this.idFactory = idFactory;
  }

  context(requestHash) {
    return { principalRef: this.authority.principalRef, requestHash };
  }

  assertMutationsEnabled() {
    throw new CanaryServiceError("mutations_disabled", "CEO canary mutation endpoints are disabled");
  }

  async createRun(value, requestHash) {
    this.assertMutationsEnabled();
    const run = this.domain.assertRun(value);
    const payloadHash = sha256Canonical(run);
    return this.store.createRun(run, payloadHash, this.context(requestHash));
  }

  async readRun(runId, requestHash) {
    if (!ID.test(runId)) throw new CanaryServiceError("invalid_id", "Workflow run identifier is invalid");
    return this.store.readRun(runId, this.context(requestHash));
  }

  async createAction(value, requestHash) {
    this.assertMutationsEnabled();
    const proposal = this.domain.assertProposal(value);
    return this.store.createAction(proposal, this.context(requestHash));
  }

  async readAction(proposalId, requestHash) {
    if (!ID.test(proposalId)) throw new CanaryServiceError("invalid_id", "Action proposal identifier is invalid");
    return this.store.readAction(proposalId, this.context(requestHash));
  }

  async transitionAction(proposalId, value, requestHash) {
    this.assertMutationsEnabled();
    if (!ID.test(proposalId)) throw new CanaryServiceError("invalid_id", "Action proposal identifier is invalid");
    const body = exactObject(
      value,
      ["expectedRevision", "expectedStateHash", "proposalHash", "effectKey", "event"],
      ["reconciliationLeaseId"],
    );
    const expected = expectedBindings({
      expectedRevision: body.expectedRevision,
      expectedStateHash: body.expectedStateHash,
      proposalHash: body.proposalHash,
      effectKey: body.effectKey,
    });
    if (["approve", "reject"].includes(body.event?.type)) {
      throw new CanaryServiceError(
        "identity_bridge_required",
        "Human approval transitions require a distinct verified identity bridge",
      );
    }
    if (body.reconciliationLeaseId !== undefined && !ID.test(body.reconciliationLeaseId)) {
      throw new CanaryServiceError("invalid_request", "Reconciliation lease identifier is invalid");
    }
    return this.store.transitionAction(
      proposalId,
      expected,
      body.event,
      body.reconciliationLeaseId,
      this.context(requestHash),
    );
  }

  async reserveAction(proposalId, value, requestHash) {
    this.assertMutationsEnabled();
    if (!ID.test(proposalId)) throw new CanaryServiceError("invalid_id", "Action proposal identifier is invalid");
    const body = exactObject(value, [
      "expectedRevision",
      "expectedStateHash",
      "proposalHash",
      "effectKey",
      "kind",
      "leaseDurationSeconds",
    ]);
    const expected = expectedBindings({
      expectedRevision: body.expectedRevision,
      expectedStateHash: body.expectedStateHash,
      proposalHash: body.proposalHash,
      effectKey: body.effectKey,
    });
    if (!["execution", "reconciliation"].includes(body.kind)) {
      throw new CanaryServiceError("invalid_request", "Reservation kind is invalid");
    }
    if (
      !Number.isInteger(body.leaseDurationSeconds) ||
      body.leaseDurationSeconds < 10 ||
      body.leaseDurationSeconds > 300
    ) {
      throw new CanaryServiceError("invalid_request", "Reservation duration must be between 10 and 300 seconds");
    }
    const leaseId = `lease:${this.idFactory()}`;
    if (body.kind === "execution") {
      throw new CanaryServiceError("live_actions_disabled", "Execution reservations remain disabled in the foundation");
    }
    return this.store.reserveReconciliation(
      proposalId,
      expected,
      leaseId,
      body.leaseDurationSeconds,
      this.context(requestHash),
    );
  }
}
