import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { spawn } from "node:child_process";
import test from "node:test";
import pg from "pg";
import { buildActionProposal } from "../../canary/contracts/index.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { syntheticDeploymentProfile } from "../../canary/deployment-profiles/testing.mjs";
import { createProviderEffectPolicySuite } from "../../canary/provider-effects/index.mjs";
import {
  PROVIDER_EFFECT_AUTHORITY_SCHEMA,
  providerEffectAuthoritySchemaSql,
} from "../../canary/provider-effects/storage-v1/schema.mjs";
import { createProviderEffectAuthorityStore } from "../../canary/provider-effects/storage-v1/store.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { canonicalJson } from "../../canary/shared-contracts/validation.mjs";
import { createInertProviderEffectExecutionAuthorityForTesting } from "./testing.mjs";

const { Pool } = pg;
const enabled = process.env.TEST_PROVIDER_EFFECT_AUTHORITY_PG16 === "1";
const skip = enabled
  ? false
  : "set TEST_PROVIDER_EFFECT_AUTHORITY_PG16=1 to run isolated PostgreSQL 16 authority storage";
const proofClasses = [
  "kill_switch",
  "evaluation_release",
  "provider_identity",
  "resource_ownership",
  "approval",
  "reconciliation_identity",
  "durable_receipt",
];

const docker = (args) =>
  new Promise((resolve) => {
    const child = spawn("docker", args, { stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("close", (exitCode) =>
      resolve({
        exitCode,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
    child.on("error", (error) => resolve({ exitCode: -1, stdout: "", stderr: error.message }));
  });

const requireDocker = async (args) => {
  const result = await docker(args);
  assert.equal(result.exitCode, 0, result.stderr);
  return result.stdout.trim();
};

const waitForPostgres = async (containerName) => {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const result = await docker(["exec", containerName, "pg_isready", "-U", "postgres", "-d", "postgres"]);
    if (result.exitCode === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert.fail("isolated PostgreSQL 16 did not become ready");
};

const iso = (milliseconds) => new Date(milliseconds).toISOString();

test(
  "isolated PostgreSQL 16 enforces provider-effect reservation, proof, receipt, and reconciliation semantics",
  { skip, timeout: 240_000 },
  async (t) => {
    const containerName = `risely-provider-authority-${process.pid}`;
    const password = `provider-authority-${process.pid}`;
    let pool;
    t.after(async () => {
      if (pool) await pool.end().catch(() => {});
      await docker(["rm", "--force", containerName]);
    });
    await requireDocker([
      "run",
      "--detach",
      "--name",
      containerName,
      "--publish",
      "127.0.0.1::5432",
      "--env",
      `POSTGRES_PASSWORD=${password}`,
      "postgres:16-alpine",
    ]);
    await waitForPostgres(containerName);
    const port = Number(
      await requireDocker([
        "inspect",
        "--format",
        '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}',
        containerName,
      ]),
    );
    pool = new Pool({ host: "127.0.0.1", port, database: "postgres", user: "postgres", password, max: 12 });
    let version;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      try {
        version = await pool.query("SHOW server_version");
        break;
      } catch (error) {
        if (attempt === 39) throw error;
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
    assert.match(version.rows[0].server_version, /^16\./u);
    await pool.query("BEGIN");
    try {
      await pool.query(providerEffectAuthoritySchemaSql());
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }

    const ceoScope = createRuntimeScope(ceoDeploymentProfile);
    const syntheticScope = createRuntimeScope(syntheticDeploymentProfile);
    const suites = new Map([
      [ceoScope.profileRef, createProviderEffectPolicySuite(ceoScope)],
      [syntheticScope.profileRef, createProviderEffectPolicySuite(syntheticScope)],
    ]);
    const signers = new Map(
      proofClasses.map((proofClass) => {
        const { publicKey, privateKey } = generateKeyPairSync("ed25519");
        return [
          proofClass,
          {
            privateKey,
            issuer: {
              keyId: `provider-proof-key:${proofClass}:pg16-test`,
              issuerRef: `provider-proof-issuer:${proofClass}:pg16-test`,
              proofClass,
              capabilities: suites.get(ceoScope.profileRef).capabilities,
              publicKey: publicKey.export({ format: "jwk" }),
            },
          },
        ];
      }),
    );
    const signProof = (scope, value, digestField, proofClass) => {
      const signer = signers.get(proofClass);
      const record = {
        ...value,
        keyId: signer.issuer.keyId,
        issuerRef: signer.issuer.issuerRef,
        signature: "",
      };
      const hashProjection = structuredClone(record);
      delete hashProjection[digestField];
      delete hashProjection.signature;
      record[digestField] = scope.contracts.PrincipalBinding.hash(hashProjection);
      const signingProjection = structuredClone(record);
      delete signingProjection.signature;
      return {
        ...record,
        signature: sign(null, Buffer.from(canonicalJson(signingProjection), "utf8"), signer.privateKey).toString(
          "base64url",
        ),
      };
    };
    const receiptSigner = signers.get("durable_receipt");
    const receiptAuthority = Object.freeze({
      keyId: receiptSigner.issuer.keyId,
      issuerRef: receiptSigner.issuer.issuerRef,
      authenticationSha256: "d".repeat(64),
      publicKey: receiptSigner.issuer.publicKey,
      async issue(semantic) {
        const record = {
          ...structuredClone(semantic),
          receiptSha256: "",
          keyId: receiptSigner.issuer.keyId,
          issuerRef: receiptSigner.issuer.issuerRef,
          signature: "",
        };
        const hashProjection = structuredClone(record);
        delete hashProjection.receiptSha256;
        delete hashProjection.signature;
        record.receiptSha256 = ceoScope.contracts.PrincipalBinding.hash(hashProjection);
        const signingProjection = structuredClone(record);
        delete signingProjection.signature;
        record.signature = sign(
          null,
          Buffer.from(canonicalJson(signingProjection), "utf8"),
          receiptSigner.privateKey,
        ).toString("base64url");
        return record;
      },
      isActive: () => true,
    });
    const activation = Object.freeze({ isActive: () => true });
    const storeFor = (scope, authority = receiptAuthority) =>
      createProviderEffectAuthorityStore({ pool, runtimeScope: scope, receiptAuthority: authority, activation });
    const proofIssuers = [...signers.values()].map(({ issuer }) => issuer);
    const reconcilerRef = (capability) => `provider-reconciler:pg16-test:${capability}`;

    const actorFor = (scope) => ({
      contractType: "actor",
      contractVersion: 1,
      principalRef: scope.domainAuthority.principalRef,
      qmPrincipalId: scope.domainAuthority.qmPrincipalId,
      externalPrincipalRef: scope.domainAuthority.externalPrincipalRef,
      agent: { id: scope.domainAuthority.agentId, version: scope.domainAuthority.agentVersion },
      surface: "system",
      scopeRef: scope.domainAuthority.scopeRef,
      audienceRef: scope.domainAuthority.audienceRef,
      credentialOwnerRef: scope.domainAuthority.credentialOwnerRef,
    });

    const draftProposal = (scope, proposalId, createdAt, expiresAt, semantic = "shared") => {
      const actor = actorFor(scope);
      const owner = scope.profile.providerOwners.find(({ provider }) => provider === "google").providerOwnerRef;
      const target = {
        providerOwnerRef: owner,
        mailbox: scope.profile.identity.humanEmail,
        to: [`${semantic}@example.com`],
      };
      const subject = `Provider storage ${semantic}`;
      const body = `Provider storage payload ${semantic}`;
      const evidenceSha256 = scope.contracts.PrincipalBinding.hash([]);
      return buildActionProposal({
        contractType: "action-proposal",
        contractVersion: 1,
        proposalId,
        runId: `run:${proposalId}`,
        actor,
        capability: "google.gmail.drafts.create",
        capabilityVersion: 1,
        provider: "google",
        credentialRef: actor.credentialOwnerRef,
        subjectRef: `artifact:${semantic}`,
        target,
        payload: {
          body,
          evidenceSha256,
          payloadSha256: scope.contracts.PrincipalBinding.hash({
            target,
            payload: { body, evidenceSha256, subject },
          }),
          subject,
        },
        artifactRefs: [{ artifactId: `artifact:${semantic}`, sha256: "a".repeat(64) }],
        evidenceRefs: [],
        capturedState: {},
        preconditions: [],
        createdAt,
        expiresAt,
      });
    };

    const sendProposal = (scope, proposalId, createdAt, expiresAt) => {
      const actor = actorFor(scope);
      const revision = "9".repeat(64);
      return buildActionProposal({
        contractType: "action-proposal",
        contractVersion: 1,
        proposalId,
        runId: `run:${proposalId}`,
        actor,
        capability: "google.gmail.drafts.send",
        capabilityVersion: 1,
        provider: "google",
        credentialRef: actor.credentialOwnerRef,
        subjectRef: "artifact:send-pg16",
        target: {
          providerOwnerRef: scope.profile.providerOwners.find(({ provider }) => provider === "google").providerOwnerRef,
          mailbox: scope.profile.identity.humanEmail,
          draftId: "gmail-draft:managed-pg16",
          draftRevisionSha256: revision,
        },
        payload: { expectedContentSha256: revision },
        artifactRefs: [{ artifactId: "artifact:send-pg16", sha256: "b".repeat(64) }],
        evidenceRefs: [],
        capturedState: {},
        preconditions: [],
        createdAt,
        expiresAt,
      });
    };

    const insertKillSwitch = async (scope, revision, checkedAt, engaged = false) => {
      const killSwitch = signProof(
        scope,
        {
          profileRef: scope.profileRef,
          profileSha256: scope.profileSha256,
          engaged,
          revision,
          checkedAt,
          stateSha256: "",
        },
        "stateSha256",
        "kill_switch",
      );
      await pool.query(
        `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states
           (profile_ref, profile_sha256, revision, engaged, checked_at, state_sha256, proof_json)
         VALUES ($1, $2, $3, $4, $5::timestamptz, $6, $7::jsonb)`,
        [
          scope.profileRef,
          scope.profileSha256,
          revision,
          engaged,
          checkedAt,
          killSwitch.stateSha256,
          canonicalJson(killSwitch),
        ],
      );
      return killSwitch;
    };

    const installAuthorization = async ({ scope, proposal, killSwitch, revision = 4, approval = false }) => {
      const suite = suites.get(scope.profileRef);
      const checked = suite.assertProposal(proposal);
      const policy = checked.policy;
      const checkedAt = killSwitch.checkedAt;
      const expiresAt = proposal.expiresAt;
      const evaluationRelease = signProof(
        scope,
        {
          releaseId: `evaluation-release:${proposal.proposalId}`,
          releaseSha256: "",
          profileRef: scope.profileRef,
          profileSha256: scope.profileSha256,
          proposalHash: proposal.proposalHash,
          intentSha256: checked.intent.intentSha256,
          policySha256: policy.policySha256,
          passed: true,
          providerReleaseEligible: true,
          evaluatedAt: proposal.createdAt,
          expiresAt,
        },
        "releaseSha256",
        "evaluation_release",
      );
      const providerIdentity = signProof(
        scope,
        {
          receiptId: `provider-identity:${proposal.proposalId}`,
          receiptSha256: "",
          verificationSha256: "b".repeat(64),
          profileRef: scope.profileRef,
          profileSha256: scope.profileSha256,
          provider: policy.provider,
          providerOwnerRef: policy.providerOwnerRef,
          providerAccountRef: `google-account:${scope.profileRef}`,
          credentialOwnerRef: proposal.actor.credentialOwnerRef,
          verifiedBy: signers.get("provider_identity").issuer.issuerRef,
          verifiedAt: proposal.createdAt,
          expiresAt,
        },
        "receiptSha256",
        "provider_identity",
      );
      const resourceOwnership = signProof(
        scope,
        {
          receiptId: `provider-resource:${proposal.proposalId}`,
          receiptSha256: "",
          verificationSha256: "c".repeat(64),
          profileRef: scope.profileRef,
          profileSha256: scope.profileSha256,
          provider: policy.provider,
          providerOwnerRef: policy.providerOwnerRef,
          providerAccountRef: providerIdentity.providerAccountRef,
          targetClass: policy.targetClass,
          resourceKey: scope.contracts.PrincipalBinding.hash({
            digestRevision: "ProviderEffectTargetBinding.sha256.v1",
            targetClass: policy.targetClass,
            target: proposal.target,
          }),
          providerResourceRef:
            proposal.capability === "google.gmail.drafts.send" ? proposal.target.draftId : "google-mailbox:ceo:pg16",
          verifiedBy: signers.get("resource_ownership").issuer.issuerRef,
          verifiedAt: proposal.createdAt,
          expiresAt,
        },
        "receiptSha256",
        "resource_ownership",
      );
      const approvalProof = approval
        ? signProof(
            scope,
            {
              approvalId: `approval:${proposal.proposalId}`,
              approvalSha256: "",
              proposalId: proposal.proposalId,
              proposalHash: proposal.proposalHash,
              intentSha256: checked.intent.intentSha256,
              approverPrincipalRef: proposal.actor.principalRef,
              decision: "approve_once",
              decidedAt: checkedAt,
              expiresAt,
              consumedAt: null,
            },
            "approvalSha256",
            "approval",
          )
        : null;
      const authorization = {
        profileRef: scope.profileRef,
        profileSha256: scope.profileSha256,
        proposal,
        intentSha256: checked.intent.intentSha256,
        prospectiveEffectKey: checked.intent.prospectiveEffectKey,
        policyRef: policy.policyRef,
        policySha256: policy.policySha256,
        capability: policy.capability,
        capabilityVersion: policy.capabilityVersion,
        provider: policy.provider,
        operation: policy.operation,
        providerOwnerRef: policy.providerOwnerRef,
        revision,
        attempts: 0,
        databaseNow: checkedAt,
        killSwitch,
        evaluationRelease,
        providerIdentity,
        resourceOwnership,
        approval: approvalProof,
      };
      await pool.query(
        `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles
           (profile_ref, profile_sha256, policy_ref, policy_sha256, profile_json, provider_execution_allowed)
         VALUES ($1, $2, $3, $4, $5::jsonb, false)
         ON CONFLICT DO NOTHING`,
        [scope.profileRef, scope.profileSha256, policy.policyRef, policy.policySha256, canonicalJson(scope.profile)],
      );
      await pool.query(
        `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.evaluation_releases
           (profile_ref, profile_sha256, release_sha256, proposal_hash, intent_sha256,
            policy_sha256, passed, provider_release_eligible, evaluated_at, expires_at, proof_json)
         VALUES ($1, $2, $3, $4, $5, $6, true, true, $7::timestamptz, $8::timestamptz, $9::jsonb)`,
        [
          scope.profileRef,
          scope.profileSha256,
          evaluationRelease.releaseSha256,
          proposal.proposalHash,
          authorization.intentSha256,
          policy.policySha256,
          evaluationRelease.evaluatedAt,
          evaluationRelease.expiresAt,
          canonicalJson(evaluationRelease),
        ],
      );
      await pool.query(
        `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.provider_identities
           (profile_ref, profile_sha256, receipt_sha256, provider, provider_owner_ref,
            provider_account_ref, credential_owner_ref, verified_at, expires_at, proof_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz, $10::jsonb)`,
        [
          scope.profileRef,
          scope.profileSha256,
          providerIdentity.receiptSha256,
          providerIdentity.provider,
          providerIdentity.providerOwnerRef,
          providerIdentity.providerAccountRef,
          providerIdentity.credentialOwnerRef,
          providerIdentity.verifiedAt,
          providerIdentity.expiresAt,
          canonicalJson(providerIdentity),
        ],
      );
      await pool.query(
        `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.resource_ownership_receipts
           (profile_ref, profile_sha256, receipt_sha256, provider, provider_owner_ref,
            provider_account_ref, target_class, resource_key, provider_resource_ref,
            verified_at, expires_at, proof_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11::timestamptz, $12::jsonb)`,
        [
          scope.profileRef,
          scope.profileSha256,
          resourceOwnership.receiptSha256,
          resourceOwnership.provider,
          resourceOwnership.providerOwnerRef,
          resourceOwnership.providerAccountRef,
          resourceOwnership.targetClass,
          resourceOwnership.resourceKey,
          resourceOwnership.providerResourceRef,
          resourceOwnership.verifiedAt,
          resourceOwnership.expiresAt,
          canonicalJson(resourceOwnership),
        ],
      );
      if (approvalProof) {
        await pool.query(
          `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.approvals
             (profile_ref, profile_sha256, approval_sha256, proposal_id, proposal_hash,
              intent_sha256, decided_at, expires_at, proof_json)
           VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, $9::jsonb)`,
          [
            scope.profileRef,
            scope.profileSha256,
            approvalProof.approvalSha256,
            proposal.proposalId,
            proposal.proposalHash,
            authorization.intentSha256,
            approvalProof.decidedAt,
            approvalProof.expiresAt,
            canonicalJson(approvalProof),
          ],
        );
      }
      await pool.query(
        `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.authorization_snapshots (
           profile_ref, profile_sha256, proposal_id, proposal_hash, intent_sha256,
           prospective_effect_key, policy_ref, policy_sha256, capability, capability_version,
           provider, operation, provider_owner_ref, provider_account_ref, authorization_mode, revision, authorized_at,
           proposal_created_at, proposal_expires_at, proposal_json, authorization_sha256,
           kill_switch_revision, evaluation_release_sha256, provider_identity_receipt_sha256,
           resource_ownership_receipt_sha256, approval_sha256
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
           $17::timestamptz, $18::timestamptz, $19::timestamptz, $20::jsonb, $21,
           $22, $23, $24, $25, $26
         )`,
        [
          scope.profileRef,
          scope.profileSha256,
          proposal.proposalId,
          proposal.proposalHash,
          authorization.intentSha256,
          authorization.prospectiveEffectKey,
          policy.policyRef,
          policy.policySha256,
          policy.capability,
          policy.capabilityVersion,
          policy.provider,
          policy.operation,
          policy.providerOwnerRef,
          providerIdentity.providerAccountRef,
          policy.authorizationMode,
          revision,
          checkedAt,
          proposal.createdAt,
          proposal.expiresAt,
          canonicalJson(proposal),
          scope.contracts.PrincipalBinding.hash(authorization),
          killSwitch.revision,
          evaluationRelease.releaseSha256,
          providerIdentity.receiptSha256,
          resourceOwnership.receiptSha256,
          approvalProof?.approvalSha256 ?? null,
        ],
      );
      return authorization;
    };

    const requestFor = (scope, authorization) => ({
      proposalId: authorization.proposal.proposalId,
      authorizationSha256: scope.contracts.PrincipalBinding.hash(authorization),
      expectedRevision: authorization.revision,
      killSwitchRevision: authorization.killSwitch.revision,
      evaluationReleaseSha256: authorization.evaluationRelease.releaseSha256,
      providerIdentityReceiptSha256: authorization.providerIdentity.receiptSha256,
      resourceOwnershipReceiptSha256: authorization.resourceOwnership.receiptSha256,
      approvalSha256: authorization.approval?.approvalSha256 ?? null,
    });

    const authorityFor = (scope, store, invoke, reconcile = async () => assert.fail("unexpected reconciliation")) => {
      const capability = "google.gmail.drafts.create";
      return createInertProviderEffectExecutionAuthorityForTesting({
        runtimeScope: scope,
        store,
        effectAdapters: Object.freeze({ [capability]: Object.freeze({ invoke, isActive: () => true }) }),
        reconciliationPorts: Object.freeze({
          [capability]: Object.freeze({
            queryStatus: reconcile,
            isActive: () => true,
            reconcilerPrincipalRef: reconcilerRef(capability),
          }),
        }),
        trustedProofIssuers: proofIssuers,
        allowedReconcilerPrincipals: [{ capability, reconcilerPrincipalRef: reconcilerRef(capability) }],
      });
    };

    const now = Date.now();
    const baseCreated = iso(now - 5_000);
    const baseExpires = iso(now + 120_000);
    await pool.query(
      `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles
         (profile_ref, profile_sha256, policy_ref, policy_sha256, profile_json, provider_execution_allowed)
       VALUES ($1, $2, $3, $4, $5::jsonb, false), ($6, $7, $8, $9, $10::jsonb, false)`,
      [
        ceoScope.profileRef,
        ceoScope.profileSha256,
        ceoScope.profile.providerEffectPolicyRef,
        ceoScope.profile.providerEffectPolicySha256,
        canonicalJson(ceoScope.profile),
        syntheticScope.profileRef,
        syntheticScope.profileSha256,
        syntheticScope.profile.providerEffectPolicyRef,
        syntheticScope.profile.providerEffectPolicySha256,
        canonicalJson(syntheticScope.profile),
      ],
    );

    const crossCheckedAt = iso(now - 1_000);
    const ceoKillOne = await insertKillSwitch(ceoScope, 1, crossCheckedAt);
    const syntheticKillOne = await insertKillSwitch(syntheticScope, 1, crossCheckedAt);
    const sharedProposalId = "proposal:cross-profile-pg16";
    const ceoCrossProposal = draftProposal(ceoScope, sharedProposalId, baseCreated, baseExpires, "ceo-cross-profile");
    const syntheticCrossProposal = draftProposal(
      syntheticScope,
      sharedProposalId,
      baseCreated,
      baseExpires,
      "synthetic-cross-profile",
    );
    await installAuthorization({ scope: ceoScope, proposal: ceoCrossProposal, killSwitch: ceoKillOne });
    await installAuthorization({
      scope: syntheticScope,
      proposal: syntheticCrossProposal,
      killSwitch: syntheticKillOne,
    });
    const ceoStore = storeFor(ceoScope);
    const syntheticStore = storeFor(syntheticScope);
    assert.equal(
      (await ceoStore.readAuthorization(sharedProposalId)).proposal.proposalHash,
      ceoCrossProposal.proposalHash,
    );
    assert.equal(
      (await syntheticStore.readAuthorization(sharedProposalId)).proposal.proposalHash,
      syntheticCrossProposal.proposalHash,
    );

    let crossProfileCalls = 0;
    const ceoAuthority = authorityFor(ceoScope, ceoStore, async ({ attempt }) => {
      crossProfileCalls += 1;
      return {
        status: "verified",
        provider: attempt.provider,
        operation: attempt.operation,
        providerOwnerRef: attempt.providerOwnerRef,
        providerResourceRef: "gmail-draft:ceo-cross-profile",
        responseSha256: "1".repeat(64),
        errorCode: null,
        observationMode: "effect_execution",
        providerMutationCount: 1,
      };
    });
    const syntheticAuthority = authorityFor(syntheticScope, syntheticStore, async ({ attempt }) => {
      crossProfileCalls += 1;
      return {
        status: "verified",
        provider: attempt.provider,
        operation: attempt.operation,
        providerOwnerRef: attempt.providerOwnerRef,
        providerResourceRef: "gmail-draft:synthetic-cross-profile",
        responseSha256: "2".repeat(64),
        errorCode: null,
        observationMode: "effect_execution",
        providerMutationCount: 1,
      };
    });
    assert.equal((await ceoAuthority.execute(sharedProposalId)).status, "verified");
    assert.equal((await syntheticAuthority.execute(sharedProposalId)).status, "verified");
    assert.equal(crossProfileCalls, 2);

    const raceCheckedAt = iso(now);
    const raceKill = await insertKillSwitch(ceoScope, 2, raceCheckedAt);
    const raceProposalOne = draftProposal(
      ceoScope,
      "proposal:semantic-race-one-pg16",
      baseCreated,
      baseExpires,
      "semantic-race",
    );
    const raceProposalTwo = draftProposal(
      ceoScope,
      "proposal:semantic-race-two-pg16",
      baseCreated,
      baseExpires,
      "semantic-race",
    );
    assert.equal(raceProposalOne.effectKey, raceProposalTwo.effectKey);
    const raceAuthorizationOne = await installAuthorization({
      scope: ceoScope,
      proposal: raceProposalOne,
      killSwitch: raceKill,
    });
    const raceAuthorizationTwo = await installAuthorization({
      scope: ceoScope,
      proposal: raceProposalTwo,
      killSwitch: raceKill,
    });
    const race = await Promise.allSettled([
      ceoStore.reserveAttempt(requestFor(ceoScope, raceAuthorizationOne)),
      ceoStore.reserveAttempt(requestFor(ceoScope, raceAuthorizationTwo)),
    ]);
    assert.equal(race.filter(({ status }) => status === "fulfilled").length, 1);
    assert.equal(race.filter(({ status }) => status === "rejected").length, 1);
    const semanticReservations = await pool.query(
      `SELECT count(*)::integer AS count
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND prospective_effect_key = $3`,
      [ceoScope.profileRef, ceoScope.profileSha256, raceAuthorizationOne.prospectiveEffectKey],
    );
    assert.equal(semanticReservations.rows[0].count, 1);

    const approvalCheckedAt = iso(Date.now());
    const approvalKill = await insertKillSwitch(ceoScope, 3, approvalCheckedAt);
    const approvalProposal = sendProposal(ceoScope, "proposal:approval-once-pg16", baseCreated, baseExpires);
    const approvalAuthorization = await installAuthorization({
      scope: ceoScope,
      proposal: approvalProposal,
      killSwitch: approvalKill,
      approval: true,
    });
    const approvalAttempt = await ceoStore.reserveAttempt(requestFor(ceoScope, approvalAuthorization));
    assert.equal(approvalAttempt.approvalSha256, approvalAuthorization.approval.approvalSha256);
    assert.equal(approvalAttempt.approvalConsumedAt, approvalAttempt.attemptedAt);
    await assert.rejects(() => ceoStore.reserveAttempt(requestFor(ceoScope, approvalAuthorization)));
    const consumptions = await pool.query(
      `SELECT count(*)::integer AS count
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.approval_consumptions
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND approval_sha256 = $3`,
      [ceoScope.profileRef, ceoScope.profileSha256, approvalAuthorization.approval.approvalSha256],
    );
    assert.equal(consumptions.rows[0].count, 1);

    const staleCheckedAt = iso(Date.now());
    const staleKill = await insertKillSwitch(ceoScope, 4, staleCheckedAt);
    const approvalUnknown = await ceoStore.completeAttempt({
      attempt: approvalAttempt,
      result: {
        status: "verified",
        provider: approvalAttempt.provider,
        operation: approvalAttempt.operation,
        providerOwnerRef: approvalAttempt.providerOwnerRef,
        providerResourceRef: approvalProposal.target.draftId,
        responseSha256: "3".repeat(64),
        errorCode: null,
        observationMode: "effect_execution",
        providerMutationCount: 1,
      },
    });
    assert.equal(approvalUnknown.status, "outcome_unknown");
    assert.equal(approvalUnknown.errorCode, "provider_kill_switch_changed_after_reservation");
    const staleProposal = draftProposal(
      ceoScope,
      "proposal:kill-switch-race-pg16",
      baseCreated,
      baseExpires,
      "kill-switch-race",
    );
    const staleAuthorization = await installAuthorization({
      scope: ceoScope,
      proposal: staleProposal,
      killSwitch: staleKill,
    });
    const staleRead = await ceoStore.readAuthorization(staleProposal.proposalId);
    await insertKillSwitch(ceoScope, 5, iso(Date.now()));
    await assert.rejects(() => ceoStore.reserveAttempt(requestFor(ceoScope, staleRead)), {
      code: "provider_effect_attempt_conflict",
    });
    const staleAttempts = await pool.query(
      `SELECT count(*)::integer AS count
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3`,
      [ceoScope.profileRef, ceoScope.profileSha256, staleAuthorization.proposal.proposalId],
    );
    assert.equal(staleAttempts.rows[0].count, 0);

    const expiredCreatedAt = iso(now - 20_000);
    const expiredAt = iso(now - 5_000);
    const expiredCheckedAt = iso(now - 10_000);
    const expiredKill = await insertKillSwitch(ceoScope, 6, expiredCheckedAt);
    const expiredProposal = draftProposal(ceoScope, "proposal:expired-pg16", expiredCreatedAt, expiredAt, "expired");
    const expiredAuthorization = await installAuthorization({
      scope: ceoScope,
      proposal: expiredProposal,
      killSwitch: expiredKill,
    });
    await assert.rejects(() => ceoStore.reserveAttempt(requestFor(ceoScope, expiredAuthorization)), {
      code: "provider_effect_authorization_expired",
    });

    const unknownStart = Date.now();
    const unknownCreated = iso(unknownStart - 1_000);
    const unknownExpires = iso(unknownStart + 1_500);
    const unknownCheckedAt = iso(unknownStart);
    const unknownKill = await insertKillSwitch(ceoScope, 7, unknownCheckedAt);
    const unknownProposal = draftProposal(
      ceoScope,
      "proposal:outcome-unknown-pg16",
      unknownCreated,
      unknownExpires,
      "outcome-unknown",
    );
    await installAuthorization({ scope: ceoScope, proposal: unknownProposal, killSwitch: unknownKill });
    let providerCalls = 0;
    const unknownAuthority = authorityFor(ceoScope, ceoStore, async () => {
      providerCalls += 1;
      throw new Error("socket closed after provider write");
    });
    const unknownReceipt = await unknownAuthority.execute(unknownProposal.proposalId);
    assert.equal(unknownReceipt.status, "outcome_unknown");
    assert.equal(unknownReceipt.completedAt, null);
    await assert.rejects(() => unknownAuthority.execute(unknownProposal.proposalId));
    assert.equal(providerCalls, 1);
    const unknownAttemptResult = await pool.query(
      `SELECT * FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3`,
      [ceoScope.profileRef, ceoScope.profileSha256, unknownProposal.proposalId],
    );
    const unknownAttempt = unknownAttemptResult.rows[0];
    const waitMs = Math.max(0, Date.parse(unknownAttempt.lease_expires_at) - Date.now() + 1_000);
    await new Promise((resolve) => setTimeout(resolve, waitMs));
    const reconciliationNow = iso(Date.now());
    const reconciliationKill = await insertKillSwitch(ceoScope, 8, reconciliationNow);
    const reconciliationIdentity = signProof(
      ceoScope,
      {
        profileRef: ceoScope.profileRef,
        profileSha256: ceoScope.profileSha256,
        capability: unknownAttempt.capability,
        attemptRef: unknownAttempt.attempt_ref,
        priorReceiptSha256: unknownReceipt.receiptSha256,
        reconcilerPrincipalRef: reconcilerRef(unknownAttempt.capability),
        authenticationSha256: "",
        authenticatedAt: reconciliationNow,
        expiresAt: iso(Date.now() + 120_000),
      },
      "authenticationSha256",
      "reconciliation_identity",
    );
    await pool.query(
      `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_identities
         (profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256,
          authentication_sha256, reconciler_principal_ref, authenticated_at, expires_at, proof_json)
       VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, $9::jsonb)`,
      [
        ceoScope.profileRef,
        ceoScope.profileSha256,
        unknownAttempt.attempt_ref,
        unknownReceipt.receiptSha256,
        reconciliationIdentity.authenticationSha256,
        reconciliationIdentity.reconcilerPrincipalRef,
        reconciliationIdentity.authenticatedAt,
        reconciliationIdentity.expiresAt,
        canonicalJson(reconciliationIdentity),
      ],
    );
    await pool.query(
      `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_authorizations
         (profile_ref, profile_sha256, proposal_id, attempt_ref, prior_receipt_sha256,
          authentication_sha256, kill_switch_revision, database_now, revision)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9)`,
      [
        ceoScope.profileRef,
        ceoScope.profileSha256,
        unknownProposal.proposalId,
        unknownAttempt.attempt_ref,
        unknownReceipt.receiptSha256,
        reconciliationIdentity.authenticationSha256,
        reconciliationKill.revision,
        reconciliationNow,
        Number(unknownAttempt.revision) + 1,
      ],
    );
    const reconciliation = await ceoStore.readReconciliation(unknownProposal.proposalId);
    const reconciliationRequest = {
      proposalId: reconciliation.proposal.proposalId,
      proposalHash: reconciliation.proposal.proposalHash,
      intentSha256: reconciliation.intentSha256,
      prospectiveEffectKey: reconciliation.prospectiveEffectKey,
      attemptRef: reconciliation.attemptRef,
      priorReceiptSha256: reconciliation.priorReceiptSha256,
      expectedRevision: reconciliation.revision,
      authenticationSha256: reconciliation.reconciliationIdentity.authenticationSha256,
      killSwitchRevision: reconciliation.killSwitch.revision,
      mode: "read_only_status_lookup",
    };
    const leaseRace = await Promise.allSettled([
      ceoStore.reserveReconciliation(reconciliationRequest),
      ceoStore.reserveReconciliation(reconciliationRequest),
    ]);
    assert.equal(
      leaseRace.filter(({ status }) => status === "fulfilled").length,
      1,
      leaseRace
        .filter(({ status }) => status === "rejected")
        .map(
          ({ reason }) => `${reason.code}:${reason.cause?.code ?? "none"}:${reason.cause?.message ?? reason.message}`,
        )
        .join("\n"),
    );
    const lease = leaseRace.find(({ status }) => status === "fulfilled").value;
    const reconciliationResult = {
      status: "verified",
      provider: reconciliation.provider,
      operation: reconciliation.operation,
      providerOwnerRef: reconciliation.providerOwnerRef,
      providerResourceRef: reconciliation.providerResourceRef,
      responseSha256: "8".repeat(64),
      errorCode: null,
      observationMode: "read_only_status_lookup",
      providerMutationCount: 0,
    };
    const reconciledReceipt = await ceoStore.completeReconciliation({
      reconciliation,
      lease,
      result: reconciliationResult,
    });
    assert.equal(reconciledReceipt.status, "verified");
    assert.equal(reconciledReceipt.observationMode, "read_only_status_lookup");
    assert.equal(reconciledReceipt.providerMutationCount, 0);
    assert.equal(reconciledReceipt.priorReceiptSha256, unknownReceipt.receiptSha256);
    assert.deepEqual(
      await ceoStore.completeReconciliation({ reconciliation, lease, result: reconciliationResult }),
      reconciledReceipt,
    );
    assert.equal(
      (
        await pool.query(
          `SELECT count(*)::integer AS count FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts
           WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3`,
          [ceoScope.profileRef, ceoScope.profileSha256, unknownProposal.proposalId],
        )
      ).rows[0].count,
      1,
    );
    await assert.rejects(() => ceoStore.readReconciliation(unknownProposal.proposalId), {
      code: "provider_effect_reconciliation_unavailable",
    });

    const tamper = await pool
      .query(
        `UPDATE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.authorization_snapshots
       SET proposal_hash = $4
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3`,
        [ceoScope.profileRef, ceoScope.profileSha256, unknownProposal.proposalId, "f".repeat(64)],
      )
      .catch((error) => error);
    assert.equal(tamper.code, "55000");

    const rollbackNow = Date.now();
    const rollbackCheckedAt = iso(rollbackNow);
    const rollbackKill = await insertKillSwitch(ceoScope, 9, rollbackCheckedAt);
    const rollbackProposal = draftProposal(
      ceoScope,
      "proposal:receipt-rollback-pg16",
      iso(rollbackNow - 1_000),
      iso(rollbackNow + 120_000),
      "receipt-rollback",
    );
    const rollbackAuthorization = await installAuthorization({
      scope: ceoScope,
      proposal: rollbackProposal,
      killSwitch: rollbackKill,
    });
    const invalidReceiptAuthority = Object.freeze({
      ...receiptAuthority,
      async issue(semantic) {
        const receipt = await receiptAuthority.issue(semantic);
        return { ...receipt, responseSha256: "f".repeat(64) };
      },
    });
    const rollbackStore = storeFor(ceoScope, invalidReceiptAuthority);
    const rollbackAttempt = await rollbackStore.reserveAttempt(requestFor(ceoScope, rollbackAuthorization));
    const rollbackResult = {
      status: "verified",
      provider: rollbackAttempt.provider,
      operation: rollbackAttempt.operation,
      providerOwnerRef: rollbackAttempt.providerOwnerRef,
      providerResourceRef: "gmail-draft:rollback-pg16",
      responseSha256: "7".repeat(64),
      errorCode: null,
      observationMode: "effect_execution",
      providerMutationCount: 1,
    };
    await assert.rejects(() => rollbackStore.completeAttempt({ attempt: rollbackAttempt, result: rollbackResult }), {
      code: "provider_effect_receipt_invalid",
    });
    const rolledBackReceipts = await pool.query(
      `SELECT count(*)::integer AS count FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND attempt_ref = $3`,
      [ceoScope.profileRef, ceoScope.profileSha256, rollbackAttempt.attemptRef],
    );
    assert.equal(rolledBackReceipts.rows[0].count, 0);

    const catalog = await pool.query(
      `SELECT
         count(*) FILTER (WHERE relation.relkind = 'r')::integer AS tables,
         count(trigger_record.oid)::integer AS triggers
       FROM pg_catalog.pg_class relation
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
       LEFT JOIN pg_catalog.pg_trigger trigger_record
         ON trigger_record.tgrelid = relation.oid AND NOT trigger_record.tgisinternal
       WHERE namespace.nspname = $1`,
      [PROVIDER_EFFECT_AUTHORITY_SCHEMA],
    );
    assert.equal(catalog.rows[0].tables, 14);
    assert.equal(catalog.rows[0].triggers, 14);
  },
);
