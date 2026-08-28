import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createActionState as createReferenceState,
  reduceActionState as reduceReferenceState,
} from "../../canary/actions/index.mjs";
import { sha256Canonical as referenceHash } from "../../canary/contracts/index.mjs";
import {
  ACTION_TRANSITIONS,
  assertProposal,
  assertRun,
  createActionState,
  createRuntimeDomain,
  reduceActionState,
} from "../../canary/service/ceo-canary/src/domain.mjs";
import { sha256Canonical } from "../../canary/service/ceo-canary/src/canonical.mjs";
import { CanaryService } from "../../canary/service/ceo-canary/src/service.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { actionProposal, approval, evidenceRef, receipt, run } from "../contracts/fixtures.mjs";

const EXECUTION_CLAIM = {
  type: "claim_execution",
  at: "2026-08-26T10:02:00Z",
  claimId: "claim:1",
  leaseExpiresAt: "2026-08-26T10:03:00Z",
};
const AUTHORITY = {
  principalRef: "principal:ceo",
  qmPrincipalId: "qm:principal:ceo-canary",
  externalPrincipalRef: "external-identity:risely:ceo",
  agentId: "agent:risely:ceo-team",
  agentVersion: "1.0.0",
  scopeRef: "principal-binding:risely:ceo:v1",
  audienceRef: "slack-audience:ceo-private",
  credentialOwnerRef: "credential-owner:ceo",
};
const RUNTIME_SCOPE = createRuntimeScope(ceoDeploymentProfile);
const RUNTIME_DOMAIN = createRuntimeDomain(RUNTIME_SCOPE);

test("service canonical hashing and action projections match the shared canary contract", () => {
  const proposal = actionProposal();
  const pluginProposal = assertProposal(proposal, AUTHORITY);
  const pluginState = createActionState(pluginProposal);
  const referenceState = createReferenceState(proposal);
  assert.equal(sha256Canonical(proposal), referenceHash(proposal));
  assert.deepEqual(pluginState, referenceState);
  assert.deepEqual(ACTION_TRANSITIONS, {
    pending: ["approve", "reject", "expire", "mark_stale"],
    approved: ["expire", "claim_execution", "mark_stale"],
    executing: ["record_receipt"],
    verified: [],
    refused: [],
    rejected: [],
    expired: [],
    stale: [],
    failed: [],
    outcome_unknown: ["record_receipt"],
  });
});

test("service reducer matches the shared canary reducer through approval, claim, and receipt", () => {
  const proposal = assertProposal(actionProposal(), AUTHORITY);
  const events = [
    { type: "approve", approval: approval(proposal) },
    EXECUTION_CLAIM,
    { type: "record_receipt", receipt: receipt(proposal) },
  ];
  let pluginState = createActionState(proposal);
  let referenceState = createReferenceState(proposal);
  for (const event of events) {
    pluginState = reduceActionState(pluginState, event);
    referenceState = reduceReferenceState(referenceState, event);
    assert.deepEqual(pluginState, referenceState);
  }
});

test("authority is deployment-controlled for runs and proposals", () => {
  assert.equal(assertRun(run(), AUTHORITY).actor.principalRef, "principal:ceo");
  assert.throws(
    () => assertRun(run(), { ...AUTHORITY, qmPrincipalId: "qm:other" }),
    (error) => error.code === "authority_mismatch",
  );
  assert.throws(
    () => assertProposal(actionProposal(), { ...AUTHORITY, audienceRef: "personal:other" }),
    (error) => error.code === "authority_mismatch",
  );
});

test("proposal evidence and Gmail effect fields are closed to the deployment audience and credential owner", () => {
  assert.throws(
    () => assertProposal(actionProposal({ evidenceRefs: [evidenceRef({ audienceRef: "personal:other" })] }), AUTHORITY),
    (error) => error.code === "invalid_proposal" || error.contractName === "actionProposal",
  );
  assert.throws(
    () =>
      assertProposal(
        actionProposal({
          evidenceRefs: [evidenceRef({ fetchedAt: "2098-08-26T10:00:00Z" })],
        }),
        AUTHORITY,
      ),
    (error) => error.code === "invalid_proposal" || error.contractName === "actionProposal",
  );
  assert.throws(
    () =>
      assertProposal(
        actionProposal({
          evidenceRefs: [evidenceRef({ observedAt: "2026-08-26T10:00:01Z", fetchedAt: "2026-08-26T10:00:00Z" })],
        }),
        AUTHORITY,
      ),
    (error) => error.code === "invalid_proposal" || error.contractName === "actionProposal",
  );
  assert.throws(
    () =>
      assertProposal(
        actionProposal({
          target: { to: ["<customer@example.com>"] },
        }),
        AUTHORITY,
      ),
    (error) => error.code === "invalid_proposal",
  );
  assert.throws(
    () =>
      assertProposal(
        actionProposal({
          payload: { subject: "Hello\r\nBcc: victim@example.com", body: "Body" },
        }),
        AUTHORITY,
      ),
    (error) => error.code === "invalid_proposal",
  );
  assert.throws(
    () =>
      RUNTIME_DOMAIN.assertProposal(
        actionProposal({
          target: { providerOwnerRef: "provider-owner:gmail:other", to: ["customer@example.com"] },
        }),
      ),
    (error) => error.code === "profile_authority_mismatch",
  );
  assert.throws(
    () => assertProposal(actionProposal({ capability: "slack.message.send", provider: "slack" }), AUTHORITY),
    (error) => error.code === "unsupported_capability",
  );
});

test("deployment grant policy accepts its exact lifetime and rejects one millisecond beyond it", () => {
  const proposal = RUNTIME_DOMAIN.assertProposal(actionProposal({ expiresAt: "2026-08-27T10:00:00.000Z" }));
  assert.equal(proposal.expiresAt, "2026-08-27T10:00:00.000Z");
  assert.throws(
    () => RUNTIME_DOMAIN.assertProposal(actionProposal({ expiresAt: "2026-08-27T10:00:00.001Z" })),
    (error) => error.code === "profile_authority_mismatch",
  );
  const state = RUNTIME_DOMAIN.createActionState(proposal);
  const exactApproval = approval(proposal, "approve_once", {
    decidedAt: "2026-08-26T10:00:00.000Z",
    expiresAt: "2026-08-27T10:00:00.000Z",
  });
  assert.equal(
    RUNTIME_DOMAIN.reduceActionState(state, { type: "approve", approval: exactApproval }).status,
    "approved",
  );
  assert.throws(
    () =>
      RUNTIME_DOMAIN.reduceActionState(state, {
        type: "approve",
        approval: { ...exactApproval, expiresAt: "2026-08-27T10:00:00.001Z" },
      }),
    (error) => error.code === "approval_lifetime_exceeded",
  );
});

test("domain trust boundaries reject nested proxies and accessors without invoking them", () => {
  let traps = 0;
  const nestedProxy = new Proxy(
    {},
    {
      ownKeys() {
        traps += 1;
        return [];
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        return undefined;
      },
    },
  );
  assert.throws(() => assertProposal({ ...actionProposal(), target: nestedProxy }, AUTHORITY));
  assert.equal(traps, 0);
  let getters = 0;
  const proposal = { ...actionProposal() };
  Object.defineProperty(proposal, "target", {
    enumerable: true,
    get() {
      getters += 1;
      return {};
    },
  });
  assert.throws(() => assertProposal(proposal, AUTHORITY));
  assert.equal(getters, 0);
  const authorityProxy = new Proxy(
    {},
    {
      ownKeys() {
        traps += 1;
        return [];
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
    },
  );
  assert.throws(() => assertProposal(actionProposal(), authorityProxy));
  assert.equal(traps, 0);
  const serviceOptionsProxy = new Proxy(
    { store: {}, authority: AUTHORITY },
    {
      ownKeys() {
        traps += 1;
        return [];
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        return undefined;
      },
    },
  );
  assert.throws(() => new CanaryService(serviceOptionsProxy));
  assert.equal(traps, 0);
  const serviceAuthorityProxy = new Proxy(AUTHORITY, {
    ownKeys() {
      traps += 1;
      return [];
    },
    getPrototypeOf() {
      traps += 1;
      return Object.prototype;
    },
    getOwnPropertyDescriptor() {
      traps += 1;
      return undefined;
    },
  });
  assert.throws(() => new CanaryService({ store: {}, authority: serviceAuthorityProxy }));
  assert.equal(traps, 0);
  const actionState = RUNTIME_DOMAIN.createActionState(actionProposal());
  const eventProxy = new Proxy(
    { type: "approve", approval: approval(actionProposal()) },
    {
      ownKeys() {
        traps += 1;
        return [];
      },
      get() {
        traps += 1;
        return undefined;
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        return undefined;
      },
    },
  );
  assert.throws(() => RUNTIME_DOMAIN.reduceActionState(actionState, eventProxy));
  assert.equal(traps, 0);
  const nestedApprovalProxy = new Proxy(approval(actionProposal()), {
    ownKeys() {
      traps += 1;
      return [];
    },
    get() {
      traps += 1;
      return undefined;
    },
    getPrototypeOf() {
      traps += 1;
      return Object.prototype;
    },
    getOwnPropertyDescriptor() {
      traps += 1;
      return undefined;
    },
  });
  assert.throws(() =>
    RUNTIME_DOMAIN.reduceActionState(actionState, { type: "approve", approval: nestedApprovalProxy }),
  );
  assert.equal(traps, 0);
  const nestedServiceAuthority = {
    ...AUTHORITY,
    principalRef: new Proxy(
      {},
      {
        ownKeys() {
          traps += 1;
          return [];
        },
        getPrototypeOf() {
          traps += 1;
          return Object.prototype;
        },
        getOwnPropertyDescriptor() {
          traps += 1;
          return undefined;
        },
        get() {
          traps += 1;
          return undefined;
        },
      },
    ),
  };
  assert.throws(() => new CanaryService({ store: {}, authority: nestedServiceAuthority }));
  assert.equal(traps, 0);
  const serviceOptionsAccessor = { store: {}, authority: AUTHORITY };
  Object.defineProperty(serviceOptionsAccessor, "authority", {
    enumerable: true,
    get() {
      getters += 1;
      return AUTHORITY;
    },
  });
  assert.throws(() => new CanaryService(serviceOptionsAccessor));
  assert.equal(getters, 0);
});

test("tampered payloads and illegal retries fail closed", () => {
  const proposal = actionProposal();
  assert.throws(
    () => assertProposal({ ...proposal, payload: { ...proposal.payload, body: "Changed" } }, AUTHORITY),
    (error) => error.code === "invalid_proposal",
  );
  const approved = reduceActionState(createActionState(proposal), {
    type: "approve",
    approval: approval(proposal),
  });
  const executing = reduceActionState(approved, EXECUTION_CLAIM);
  assert.throws(
    () => reduceActionState(executing, { ...EXECUTION_CLAIM, claimId: "claim:2" }),
    (error) => error.code === "illegal_transition",
  );
});

test("source-auth callers cannot construct an enabled service or reach any mutation store method", async () => {
  let storeCalls = 0;
  const store = {
    runtimeScope: RUNTIME_SCOPE,
    async transitionAction() {
      storeCalls += 1;
    },
    async reserveExecution() {
      storeCalls += 1;
    },
  };
  assert.throws(
    () => new CanaryService({ store, authority: AUTHORITY, mutationsEnabled: true }),
    /unsupported authority switches/,
  );
  const service = new CanaryService({ store, scope: RUNTIME_SCOPE, idFactory: () => "fixed" });
  const proposal = actionProposal();
  const bindings = {
    expectedRevision: 0,
    expectedStateHash: "a".repeat(64),
    proposalHash: proposal.proposalHash,
    effectKey: proposal.effectKey,
  };
  await assert.rejects(
    () =>
      service.transitionAction(
        proposal.proposalId,
        { ...bindings, event: { type: "approve", approval: approval(proposal) } },
        "b".repeat(64),
      ),
    (error) => error.code === "mutations_disabled",
  );
  await assert.rejects(
    () =>
      service.reserveAction(
        proposal.proposalId,
        { ...bindings, kind: "execution", leaseDurationSeconds: 30 },
        "c".repeat(64),
      ),
    (error) => error.code === "mutations_disabled",
  );
  assert.equal(storeCalls, 0);
});

test("production service mode blocks every mutation before store access", async () => {
  let storeCalls = 0;
  const store = {
    runtimeScope: RUNTIME_SCOPE,
    async createRun() {
      storeCalls += 1;
    },
  };
  const service = new CanaryService({ store, scope: RUNTIME_SCOPE });
  await assert.rejects(
    () => service.createRun(run(), "d".repeat(64)),
    (error) => error.code === "mutations_disabled",
  );
  assert.equal(storeCalls, 0);
});
