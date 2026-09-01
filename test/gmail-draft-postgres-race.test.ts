import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { sha256Bytes } from "../src/gmail-drafts/contracts.ts";

const databaseUrl = process.env.GMAIL_DRAFT_BROKER_TEST_DATABASE_URL;

test(
  "[postgres] races bindings, effect claims, lineage reclamation, reconciliation leases, and privilege drift",
  { skip: databaseUrl ? false : "set GMAIL_DRAFT_BROKER_TEST_DATABASE_URL to a dedicated privileged database" },
  async () => {
    const pg = (await import("pg")).default;
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const migration = await readFile(
      fileURLToPath(new URL("../src/gmail-drafts/migration.sql", import.meta.url)),
      "utf8",
    );
    const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const digest = (name: string) => sha256Bytes(`${suffix}:${name}`);
    const organizationId = `org-${suffix}`;
    const ownerPrincipalId = `owner-${suffix}`;
    const issuer = `issuer-${suffix}`;
    const keyId = `key-${suffix}`;
    const slackTeamId = "T12345678";
    const slackUserId = "U12345678";
    const channelId = "D12345678";
    const logicalConnectionId = `connection-${suffix}`;
    const googleSubject = `subject-${suffix}`;
    const mailbox = `owner-${suffix}@example.test`;
    const now = Date.now();
    const seconds = Math.floor(now / 1_000);
    const threadTs = `${seconds}.000001`;
    const actionTs = `${seconds}.000002`;
    const admitIntent = async (input: {
      effectProposalId: string;
      draftRevision: number;
      operation: "create" | "update";
      draftId: string | null;
      priorReceiptSha256: string | null;
      gmailThreadId: string | null;
    }) =>
      pool.query<{ outcome: string }>(
        `SELECT gmail_draft_broker.admit_intent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40::text[],$41,$42::jsonb) AS outcome`,
        [
          input.effectProposalId,
          1,
          input.draftRevision,
          digest(`proposal:${input.effectProposalId}`),
          `approval-${input.effectProposalId}`,
          `approval-receipt-${input.effectProposalId}`,
          issuer,
          keyId,
          digest(`signed:${input.effectProposalId}`),
          digest(`verified:${input.effectProposalId}`),
          organizationId,
          ownerPrincipalId,
          ownerPrincipalId,
          slackUserId,
          slackTeamId,
          slackUserId,
          channelId,
          threadTs,
          threadTs,
          actionTs,
          now,
          now + 120_000,
          input.operation,
          logicalConnectionId,
          1,
          googleSubject,
          mailbox,
          digest(`payload:${input.effectProposalId}`),
          digest(`recipients:${input.effectProposalId}`),
          digest(`subject:${input.effectProposalId}`),
          digest(`body:${input.effectProposalId}`),
          digest(`thread-binding:${input.effectProposalId}`),
          digest(`business:${input.effectProposalId}`),
          digest(`sources:${input.effectProposalId}`),
          input.draftId,
          input.priorReceiptSha256,
          input.gmailThreadId,
          null,
          null,
          null,
          null,
          JSON.stringify({ ciphertext: `sealed-${input.effectProposalId}` }),
        ],
      );
    const seedCreatedDraft = async (name: string) => {
      const effectProposalId = `create-${name}-${suffix}`;
      const priorReceiptSha256 = digest(`created-receipt:${name}`);
      const safeName = `${name}_${suffix}`.replaceAll("-", "_");
      const draftId = `draft_${safeName}`;
      const gmailThreadId = `thread_${safeName}`;
      assert.equal(
        (
          await admitIntent({
            effectProposalId,
            draftRevision: 1,
            operation: "create",
            draftId: null,
            priorReceiptSha256: null,
            gmailThreadId: null,
          })
        ).rows[0]?.outcome,
        "admitted",
      );
      const claim = await pool.query<{ intent: { attempt_id: string; approved_payload_sha256: string } }>(
        `SELECT gmail_draft_broker.claim_effect($1,$2) AS intent`,
        [effectProposalId, 30_000],
      );
      const attemptId = claim.rows[0]!.intent.attempt_id;
      const requestSha256 = digest(`create-request:${name}`);
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.arm_effect($1,$2,$3,$4,$5,$6,$7,$8) AS accepted`,
            [
              effectProposalId,
              1,
              attemptId,
              digest(`unknown-receipt:${name}`),
              requestSha256,
              `<qm.${claim.rows[0]!.intent.approved_payload_sha256}@drafts.invalid>`,
              "network_failure",
              now,
            ],
          )
        ).rows[0]?.accepted,
        true,
      );
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.record_created($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) AS accepted`,
            [
              effectProposalId,
              1,
              attemptId,
              priorReceiptSha256,
              draftId,
              `message_${safeName}`,
              gmailThreadId,
              digest(`mime:${name}`),
              requestSha256,
              digest(`response:${name}`),
              digest(`credential:${name}`),
              now,
              false,
              null,
            ],
          )
        ).rows[0]?.accepted,
        true,
      );
      return { effectProposalId, priorReceiptSha256, draftId, gmailThreadId };
    };
    try {
      await pool.query(migration);
      assert.equal(
        (
          await pool.query<{ outcome: string }>(
            `SELECT gmail_draft_broker.admit_owner_slack_binding($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) AS outcome`,
            [
              issuer,
              keyId,
              `binding-${suffix}`,
              `binding-receipt-${suffix}`,
              organizationId,
              ownerPrincipalId,
              slackTeamId,
              slackUserId,
              now,
              now + 86_400_000,
              digest("binding-signed"),
              digest("binding-verified"),
            ],
          )
        ).rows[0]?.outcome,
        "admitted",
      );
      const raceOrganizationId = `binding-race-org-${suffix}`;
      const raceOwnerPrincipalId = `binding-race-owner-${suffix}`;
      const admitBinding = async (name: string, issuedAt: number) =>
        pool.query<{ outcome: string }>(
          `SELECT gmail_draft_broker.admit_owner_slack_binding($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) AS outcome`,
          [
            issuer,
            keyId,
            `binding-race-${name}-${suffix}`,
            `binding-race-receipt-${name}-${suffix}`,
            raceOrganizationId,
            raceOwnerPrincipalId,
            slackTeamId,
            slackUserId,
            issuedAt,
            now + 86_400_000,
            digest(`binding-race-signed:${name}`),
            digest(`binding-race-verified:${name}`),
          ],
        );
      const olderIssuedAt = now - 1_000;
      const newerIssuedAt = now;
      const bindingRace = await Promise.all([
        admitBinding("older", olderIssuedAt),
        admitBinding("newer", newerIssuedAt),
      ]);
      assert(bindingRace.every((result) => ["admitted", "rejected"].includes(result.rows[0]!.outcome)));
      const winningBinding = await pool.query<{
        binding_jti: string;
        issued_at: string;
        verified_receipt_sha256: string;
      }>(
        `SELECT binding_jti, issued_at::text, verified_receipt_sha256
         FROM gmail_draft_broker.owner_slack_bindings
         WHERE organization_id = $1 AND owner_principal_id = $2`,
        [raceOrganizationId, raceOwnerPrincipalId],
      );
      assert.equal(winningBinding.rows[0]?.binding_jti, `binding-race-newer-${suffix}`);
      assert.equal(winningBinding.rows[0]?.issued_at, String(newerIssuedAt));
      assert.equal((await admitBinding("newer", newerIssuedAt)).rows[0]?.outcome, "replayed");
      assert.equal((await admitBinding("tie-conflict", newerIssuedAt)).rows[0]?.outcome, "rejected");
      const bindingAfterTie = await pool.query<{ binding_jti: string }>(
        `SELECT binding_jti FROM gmail_draft_broker.owner_slack_bindings
         WHERE organization_id = $1 AND owner_principal_id = $2`,
        [raceOrganizationId, raceOwnerPrincipalId],
      );
      assert.equal(bindingAfterTie.rows[0]?.binding_jti, `binding-race-newer-${suffix}`);
      const effectClaimRaceId = `effect-claim-race-${suffix}`;
      assert.equal(
        (
          await admitIntent({
            effectProposalId: effectClaimRaceId,
            draftRevision: 1,
            operation: "create",
            draftId: null,
            priorReceiptSha256: null,
            gmailThreadId: null,
          })
        ).rows[0]?.outcome,
        "admitted",
      );
      const effectClaims = await Promise.all(
        [0, 1].map(() =>
          pool.query<{
            intent: { attempt_id: string; _claimAcquired: boolean; reconciliation_nonce: string | null };
          }>(`SELECT gmail_draft_broker.claim_effect($1,$2) AS intent`, [effectClaimRaceId, 30_000]),
        ),
      );
      assert.equal(effectClaims.filter((claim) => claim.rows[0]?.intent._claimAcquired).length, 1);
      assert.equal(new Set(effectClaims.map((claim) => claim.rows[0]?.intent.attempt_id)).size, 1);
      assert(effectClaims.every((claim) => claim.rows[0]?.intent.reconciliation_nonce === null));
      const parent = await seedCreatedDraft("lineage");
      const childIds = ["a", "b"].map((child) => `update-${child}-${suffix}`);
      const children = childIds.map((effectProposalId) =>
        admitIntent({
          effectProposalId,
          draftRevision: 2,
          operation: "update",
          draftId: parent.draftId,
          priorReceiptSha256: parent.priorReceiptSha256,
          gmailThreadId: parent.gmailThreadId,
        }),
      );
      const childResults = await Promise.all(children);
      const outcomes = childResults.map((result) => result.rows[0]?.outcome).sort();
      assert.deepEqual(outcomes, ["admitted", "rejected"]);
      const admittedChild = childIds[childResults.findIndex((result) => result.rows[0]?.outcome === "admitted")]!;
      const lineage = await pool.query<{ child_count: string; active_child: string }>(
        `SELECT count(*)::text AS child_count, max(child_effect_proposal_id) AS active_child
         FROM gmail_draft_broker.active_lineage_claims
         WHERE parent_effect_proposal_id = $1`,
        [parent.effectProposalId],
      );
      assert.equal(lineage.rows[0]?.child_count, "1");
      assert.equal(lineage.rows[0]!.active_child, admittedChild);
      const claimChild = async (effectProposalId: string) => {
        const result = await pool.query<{
          intent: { attempt_id: string; approved_payload_sha256: string; status: string };
        }>(`SELECT gmail_draft_broker.claim_effect($1,$2) AS intent`, [effectProposalId, 30_000]);
        return result.rows[0]!.intent;
      };
      const activeChild = async (priorReceiptSha256: string) =>
        (
          await pool.query<{ child_effect_proposal_id: string }>(
            `SELECT child_effect_proposal_id FROM gmail_draft_broker.active_lineage_claims
             WHERE prior_draft_receipt_sha256 = $1`,
            [priorReceiptSha256],
          )
        ).rows[0]?.child_effect_proposal_id ?? null;
      const armChild = async (
        effectProposalId: string,
        claim: { attempt_id: string; approved_payload_sha256: string },
        name: string,
      ) =>
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.arm_effect($1,$2,$3,$4,$5,$6,$7,$8) AS accepted`,
            [
              effectProposalId,
              1,
              claim.attempt_id,
              digest(`unknown:${name}`),
              digest(`request:${name}`),
              `<qm.${claim.approved_payload_sha256}@drafts.invalid>`,
              "network_failure",
              now,
            ],
          )
        ).rows[0]?.accepted === true;

      const firstClaim = await claimChild(admittedChild);
      const competingChild = `update-competing-${suffix}`;
      const [released, competingAdmission] = await Promise.all([
        pool.query<{ accepted: boolean }>(`SELECT gmail_draft_broker.reject_before_effect($1,$2,$3,$4) AS accepted`, [
          admittedChild,
          1,
          firstClaim.attempt_id,
          "proposal_invalid",
        ]),
        admitIntent({
          effectProposalId: competingChild,
          draftRevision: 2,
          operation: "update",
          draftId: parent.draftId,
          priorReceiptSha256: parent.priorReceiptSha256,
          gmailThreadId: parent.gmailThreadId,
        }),
      ]);
      assert.equal(released.rows[0]?.accepted, true);
      if (competingAdmission.rows[0]?.outcome === "rejected") {
        assert.equal(
          (
            await admitIntent({
              effectProposalId: competingChild,
              draftRevision: 2,
              operation: "update",
              draftId: parent.draftId,
              priorReceiptSha256: parent.priorReceiptSha256,
              gmailThreadId: parent.gmailThreadId,
            })
          ).rows[0]?.outcome,
          "admitted",
        );
      } else {
        assert.equal(competingAdmission.rows[0]?.outcome, "admitted");
      }
      assert.equal(await activeChild(parent.priorReceiptSha256), competingChild);
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.reject_before_effect($1,$2,$3,$4) AS accepted`,
            [admittedChild, 1, firstClaim.attempt_id, "proposal_invalid"],
          )
        ).rows[0]?.accepted,
        false,
      );
      assert.equal(await activeChild(parent.priorReceiptSha256), competingChild);

      const competingClaim = await claimChild(competingChild);
      const armRace = armChild(competingChild, competingClaim, "arm-race");
      const rejectRace = pool.query<{ accepted: boolean }>(
        `SELECT gmail_draft_broker.reject_before_effect($1,$2,$3,$4) AS accepted`,
        [competingChild, 1, competingClaim.attempt_id, "proposal_invalid"],
      );
      const [armedInRace, rejectedInRaceResult] = await Promise.all([armRace, rejectRace]);
      const rejectedInRace = rejectedInRaceResult.rows[0]?.accepted === true;
      assert.notEqual(armedInRace, rejectedInRace);
      let armedChild = competingChild;
      let armedClaim = competingClaim;
      if (rejectedInRace) {
        armedChild = `update-armed-${suffix}`;
        assert.equal(
          (
            await admitIntent({
              effectProposalId: armedChild,
              draftRevision: 2,
              operation: "update",
              draftId: parent.draftId,
              priorReceiptSha256: parent.priorReceiptSha256,
              gmailThreadId: parent.gmailThreadId,
            })
          ).rows[0]?.outcome,
          "admitted",
        );
        armedClaim = await claimChild(armedChild);
        assert.equal(await armChild(armedChild, armedClaim, "armed"), true);
      }
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.reject_definitive_no_write($1,$2,$3,$4) AS accepted`,
            [armedChild, 1, armedClaim.attempt_id, "gmail_rejected"],
          )
        ).rows[0]?.accepted,
        true,
      );
      assert.equal(await activeChild(parent.priorReceiptSha256), null);

      const unknownChild = `update-unknown-${suffix}`;
      assert.equal(
        (
          await admitIntent({
            effectProposalId: unknownChild,
            draftRevision: 2,
            operation: "update",
            draftId: parent.draftId,
            priorReceiptSha256: parent.priorReceiptSha256,
            gmailThreadId: parent.gmailThreadId,
          })
        ).rows[0]?.outcome,
        "admitted",
      );
      const unknownClaim = await claimChild(unknownChild);
      const unknownRequest = digest("request:unknown");
      const unknownReceipt = digest("receipt:unknown");
      const unknownMarker = `<qm.${unknownClaim.approved_payload_sha256}@drafts.invalid>`;
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.arm_effect($1,$2,$3,$4,$5,$6,$7,$8) AS accepted`,
            [
              unknownChild,
              1,
              unknownClaim.attempt_id,
              unknownReceipt,
              unknownRequest,
              unknownMarker,
              "network_failure",
              now,
            ],
          )
        ).rows[0]?.accepted,
        true,
      );
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.record_unknown($1,$2,$3,$4,$5,$6,$7,$8) AS accepted`,
            [
              unknownChild,
              1,
              unknownClaim.attempt_id,
              unknownReceipt,
              unknownRequest,
              unknownMarker,
              "network_failure",
              now,
            ],
          )
        ).rows[0]?.accepted,
        true,
      );
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.reject_definitive_no_write($1,$2,$3,$4) AS accepted`,
            [unknownChild, 1, unknownClaim.attempt_id, "gmail_rejected"],
          )
        ).rows[0]?.accepted,
        false,
      );
      assert.equal(await activeChild(parent.priorReceiptSha256), unknownChild);
      assert.equal(
        (
          await admitIntent({
            effectProposalId: `update-after-unknown-${suffix}`,
            draftRevision: 2,
            operation: "update",
            draftId: parent.draftId,
            priorReceiptSha256: parent.priorReceiptSha256,
            gmailThreadId: parent.gmailThreadId,
          })
        ).rows[0]?.outcome,
        "rejected",
      );
      const claimReconciliation = async () =>
        (
          await pool.query<{
            intent: {
              status: string;
              attempt_id: string;
              reconciliation_nonce: string | null;
              _claimAcquired: boolean;
            };
          }>(`SELECT gmail_draft_broker.claim_reconciliation($1,$2) AS intent`, [unknownChild, 30_000])
        ).rows[0]!.intent;
      const simultaneousReconciliationClaims = await Promise.all([claimReconciliation(), claimReconciliation()]);
      const acquiredReconciliation = simultaneousReconciliationClaims.find((claim) => claim._claimAcquired);
      const observedReconciliation = simultaneousReconciliationClaims.find((claim) => !claim._claimAcquired);
      assert(acquiredReconciliation?.reconciliation_nonce);
      assert.equal(observedReconciliation?.reconciliation_nonce, acquiredReconciliation.reconciliation_nonce);
      await pool.query(
        `UPDATE gmail_draft_broker.approved_intents
         SET claim_expires_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT - 1
         WHERE effect_proposal_id = $1`,
        [unknownChild],
      );
      const reclaimedReconciliation = await claimReconciliation();
      assert.equal(reclaimedReconciliation._claimAcquired, true);
      assert(reclaimedReconciliation.reconciliation_nonce);
      assert.notEqual(reclaimedReconciliation.reconciliation_nonce, acquiredReconciliation.reconciliation_nonce);
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.record_created($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) AS accepted`,
            [
              unknownChild,
              1,
              unknownClaim.attempt_id,
              digest("reconciled-receipt:stale"),
              parent.draftId,
              `message_reconciled_${suffix}`.replaceAll("-", "_"),
              parent.gmailThreadId,
              digest("reconciled-mime:stale"),
              unknownRequest,
              digest("reconciled-response:stale"),
              digest("reconciled-credential:stale"),
              now,
              true,
              acquiredReconciliation.reconciliation_nonce,
            ],
          )
        ).rows[0]?.accepted,
        false,
      );
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.retain_unknown($1,$2,$3,$4,$5,$6,$7,$8,$9) AS accepted`,
            [
              unknownChild,
              1,
              unknownClaim.attempt_id,
              unknownReceipt,
              unknownRequest,
              unknownMarker,
              "network_failure",
              now,
              acquiredReconciliation.reconciliation_nonce,
            ],
          )
        ).rows[0]?.accepted,
        false,
      );
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.retain_unknown($1,$2,$3,$4,$5,$6,$7,$8,$9) AS accepted`,
            [
              unknownChild,
              1,
              unknownClaim.attempt_id,
              unknownReceipt,
              unknownRequest,
              unknownMarker,
              "network_failure",
              now,
              reclaimedReconciliation.reconciliation_nonce,
            ],
          )
        ).rows[0]?.accepted,
        true,
      );
      const finalReconciliation = await claimReconciliation();
      assert.equal(finalReconciliation._claimAcquired, true);
      assert.notEqual(finalReconciliation.reconciliation_nonce, reclaimedReconciliation.reconciliation_nonce);
      assert.equal(
        (
          await pool.query<{ accepted: boolean }>(
            `SELECT gmail_draft_broker.record_created($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) AS accepted`,
            [
              unknownChild,
              1,
              unknownClaim.attempt_id,
              digest("reconciled-receipt:current"),
              parent.draftId,
              `message_reconciled_${suffix}`.replaceAll("-", "_"),
              parent.gmailThreadId,
              digest("reconciled-mime:current"),
              unknownRequest,
              digest("reconciled-response:current"),
              digest("reconciled-credential:current"),
              now,
              true,
              finalReconciliation.reconciliation_nonce,
            ],
          )
        ).rows[0]?.accepted,
        true,
      );

      const expiringParent = await seedCreatedDraft("expired");
      const expiredChild = `update-expired-${suffix}`;
      assert.equal(
        (
          await admitIntent({
            effectProposalId: expiredChild,
            draftRevision: 2,
            operation: "update",
            draftId: expiringParent.draftId,
            priorReceiptSha256: expiringParent.priorReceiptSha256,
            gmailThreadId: expiringParent.gmailThreadId,
          })
        ).rows[0]?.outcome,
        "admitted",
      );
      await pool.query(
        `UPDATE gmail_draft_broker.approved_intents
         SET approval_expires_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT - 1
         WHERE effect_proposal_id = $1`,
        [expiredChild],
      );
      const afterExpiredChild = `update-after-expired-${suffix}`;
      assert.equal(
        (
          await admitIntent({
            effectProposalId: afterExpiredChild,
            draftRevision: 2,
            operation: "update",
            draftId: expiringParent.draftId,
            priorReceiptSha256: expiringParent.priorReceiptSha256,
            gmailThreadId: expiringParent.gmailThreadId,
          })
        ).rows[0]?.outcome,
        "admitted",
      );
      assert.equal(await activeChild(expiringParent.priorReceiptSha256), afterExpiredChild);
      assert.equal(
        (
          await pool.query<{ status: string; rejection_code: string }>(
            `SELECT status, rejection_code FROM gmail_draft_broker.approved_intents WHERE effect_proposal_id = $1`,
            [expiredChild],
          )
        ).rows[0]?.status,
        "rejected",
      );

      const preEffectParent = await seedCreatedDraft("expired-pre-effect");
      const expiredPreEffectChild = `update-expired-pre-effect-${suffix}`;
      assert.equal(
        (
          await admitIntent({
            effectProposalId: expiredPreEffectChild,
            draftRevision: 2,
            operation: "update",
            draftId: preEffectParent.draftId,
            priorReceiptSha256: preEffectParent.priorReceiptSha256,
            gmailThreadId: preEffectParent.gmailThreadId,
          })
        ).rows[0]?.outcome,
        "admitted",
      );
      assert.equal((await claimChild(expiredPreEffectChild)).status, "pre_effect");
      await pool.query(
        `UPDATE gmail_draft_broker.approved_intents
         SET approval_expires_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT - 1
         WHERE effect_proposal_id = $1`,
        [expiredPreEffectChild],
      );
      assert.equal(
        (
          await admitIntent({
            effectProposalId: `update-after-expired-pre-effect-${suffix}`,
            draftRevision: 2,
            operation: "update",
            draftId: preEffectParent.draftId,
            priorReceiptSha256: preEffectParent.priorReceiptSha256,
            gmailThreadId: preEffectParent.gmailThreadId,
          })
        ).rows[0]?.outcome,
        "admitted",
      );

      const effectStartedParent = await seedCreatedDraft("expired-effect-started");
      const effectStartedChild = `update-expired-effect-started-${suffix}`;
      assert.equal(
        (
          await admitIntent({
            effectProposalId: effectStartedChild,
            draftRevision: 2,
            operation: "update",
            draftId: effectStartedParent.draftId,
            priorReceiptSha256: effectStartedParent.priorReceiptSha256,
            gmailThreadId: effectStartedParent.gmailThreadId,
          })
        ).rows[0]?.outcome,
        "admitted",
      );
      const effectStartedClaim = await claimChild(effectStartedChild);
      assert.equal(await armChild(effectStartedChild, effectStartedClaim, "expired-effect-started"), true);
      await pool.query(
        `UPDATE gmail_draft_broker.approved_intents
         SET approval_expires_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT - 1,
             claim_expires_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT - 1
         WHERE effect_proposal_id = $1`,
        [effectStartedChild],
      );
      assert.equal(
        (
          await admitIntent({
            effectProposalId: `update-after-effect-started-${suffix}`,
            draftRevision: 2,
            operation: "update",
            draftId: effectStartedParent.draftId,
            priorReceiptSha256: effectStartedParent.priorReceiptSha256,
            gmailThreadId: effectStartedParent.gmailThreadId,
          })
        ).rows[0]?.outcome,
        "rejected",
      );
      const privileges = await pool.query<{
        admission_can_admit: boolean;
        admission_can_claim: boolean;
        broker_can_admit: boolean;
        broker_can_claim: boolean;
      }>(`SELECT
        has_function_privilege('qm_gmail_draft_admission', 'gmail_draft_broker.admit_intent(text,integer,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,text,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text[],text,jsonb)', 'EXECUTE') AS admission_can_admit,
        has_function_privilege('qm_gmail_draft_admission', 'gmail_draft_broker.claim_effect(text,integer)', 'EXECUTE') AS admission_can_claim,
        has_function_privilege('qm_gmail_draft_broker', 'gmail_draft_broker.admit_intent(text,integer,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,text,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text[],text,jsonb)', 'EXECUTE') AS broker_can_admit,
        has_function_privilege('qm_gmail_draft_broker', 'gmail_draft_broker.claim_effect(text,integer)', 'EXECUTE') AS broker_can_claim`);
      assert.deepEqual(privileges.rows[0], {
        admission_can_admit: true,
        admission_can_claim: false,
        broker_can_admit: false,
        broker_can_claim: true,
      });
      await pool.query(migration);
      await pool.query(`ALTER ROLE qm_gmail_draft_admission INHERIT`);
      try {
        try {
          await assert.rejects(pool.query(migration), /NOLOGIN least-privilege precondition/u);
        } finally {
          await pool.query(`ROLLBACK`);
        }
      } finally {
        await pool.query(`ALTER ROLE qm_gmail_draft_admission NOINHERIT`);
      }
      const driftRole = `gmail_drift_${suffix}`.replaceAll(/[^A-Za-z0-9_]/gu, "_").slice(0, 60);
      await pool.query(`CREATE ROLE ${driftRole} NOLOGIN NOINHERIT`);
      try {
        await pool.query(`GRANT ${driftRole} TO qm_gmail_draft_admission`);
        try {
          try {
            await assert.rejects(pool.query(migration), /protected roles must not be members/u);
          } finally {
            await pool.query(`ROLLBACK`);
          }
        } finally {
          await pool.query(`REVOKE ${driftRole} FROM qm_gmail_draft_admission`);
        }
        await pool.query(`GRANT USAGE ON SCHEMA gmail_draft_broker TO ${driftRole}`);
        try {
          try {
            await assert.rejects(pool.query(migration), /privilege drift/u);
          } finally {
            await pool.query(`ROLLBACK`);
          }
        } finally {
          await pool.query(`REVOKE ALL ON SCHEMA gmail_draft_broker FROM ${driftRole}`);
        }
      } finally {
        await pool.query(`DROP ROLE ${driftRole}`);
      }
    } finally {
      await pool.end();
    }
  },
);

test(
  "[postgres] rejects same-name definition tampering and repairs exact membership options and function bodies",
  {
    skip: databaseUrl ? false : "set GMAIL_DRAFT_BROKER_TEST_DATABASE_URL to a dedicated privileged database",
  },
  async () => {
    const pg = (await import("pg")).default;
    const pool = new pg.Pool({ connectionString: databaseUrl, max: 1 });
    const client = await pool.connect();
    const migration = await readFile(
      fileURLToPath(new URL("../src/gmail-drafts/migration.sql", import.meta.url)),
      "utf8",
    );
    const runtimeRoleBindings = await readFile(
      fileURLToPath(new URL("../src/gmail-drafts/runtime-role-bindings.sql", import.meta.url)),
      "utf8",
    );
    const suffix = `${Date.now()}_${Math.random().toString(16).slice(2)}`.replaceAll(/[^A-Za-z0-9_]/gu, "_");
    const admissionLogin = `gmail_admission_${suffix}`.slice(0, 60);
    const brokerLogin = `gmail_broker_${suffix}`.slice(0, 60);
    const deploymentLogin = `gmail_deploy_${suffix}`.slice(0, 60);
    const extraLogin = `gmail_extra_${suffix}`.slice(0, 60);
    const driftSchema = `gmail_catalog_${suffix}`.slice(0, 60);
    const rollbackRejectedMigration = async (pattern: RegExp) => {
      try {
        await assert.rejects(client.query(migration), pattern);
      } finally {
        await client.query(`ROLLBACK`);
      }
    };
    const rollbackRejectedBinding = async (pattern: RegExp) => {
      try {
        await assert.rejects(client.query(runtimeRoleBindings), pattern);
      } finally {
        await client.query(`ROLLBACK`);
      }
    };
    try {
      await client.query(migration);
      await client.query(
        `CREATE ROLE ${admissionLogin} LOGIN INHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS`,
      );
      await client.query(
        `CREATE ROLE ${brokerLogin} LOGIN INHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS`,
      );
      await client.query(
        `CREATE ROLE ${deploymentLogin} LOGIN NOINHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS`,
      );
      await client.query(`SELECT pg_catalog.set_config('gmail_draft_broker.admission_login_role', $1, FALSE)`, [
        admissionLogin,
      ]);
      await client.query(`SELECT pg_catalog.set_config('gmail_draft_broker.broker_login_role', $1, FALSE)`, [
        brokerLogin,
      ]);
      await client.query(`SELECT pg_catalog.set_config('gmail_draft_broker.owner_login_role', $1, FALSE)`, [
        deploymentLogin,
      ]);
      await client.query(runtimeRoleBindings);
      const runtimeMemberships = async () =>
        client.query<{
          admin_option: boolean;
          granted_role: string;
          inherit_option: boolean;
          member_role: string;
          set_option: boolean;
        }>(
          `SELECT granted.rolname AS granted_role, member.rolname AS member_role,
             membership.admin_option, membership.inherit_option, membership.set_option
           FROM pg_catalog.pg_auth_members membership
           JOIN pg_catalog.pg_roles granted ON granted.oid = membership.roleid
           JOIN pg_catalog.pg_roles member ON member.oid = membership.member
           WHERE granted.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
           ORDER BY granted.rolname`,
        );
      assert.deepEqual((await runtimeMemberships()).rows, [
        {
          admin_option: false,
          granted_role: "qm_gmail_draft_admission",
          inherit_option: true,
          member_role: admissionLogin,
          set_option: false,
        },
        {
          admin_option: false,
          granted_role: "qm_gmail_draft_broker",
          inherit_option: true,
          member_role: brokerLogin,
          set_option: false,
        },
        {
          admin_option: false,
          granted_role: "qm_gmail_draft_owner",
          inherit_option: false,
          member_role: deploymentLogin,
          set_option: true,
        },
      ]);

      await client.query(
        `CREATE ROLE ${extraLogin} LOGIN INHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS`,
      );
      await client.query(`GRANT qm_gmail_draft_admission TO ${extraLogin} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE`);
      await rollbackRejectedMigration(/exactly one intended direct isolated login binding/u);
      await client.query(runtimeRoleBindings);
      assert.equal((await runtimeMemberships()).rows.length, 3);

      await client.query(`GRANT SELECT (status) ON gmail_draft_broker.approved_intents TO ${brokerLogin}`);
      await rollbackRejectedBinding(/owns objects or has direct privileges/u);
      await rollbackRejectedMigration(/intended login .* direct or default privileges/u);
      await client.query(`REVOKE SELECT (status) ON gmail_draft_broker.approved_intents FROM ${brokerLogin}`);

      await client.query(`ALTER TABLE gmail_draft_broker.owner_slack_bindings SET UNLOGGED`);
      await rollbackRejectedBinding(/binding table postflight/u);
      await rollbackRejectedMigration(/permanent logged tables/u);
      await client.query(`ALTER TABLE gmail_draft_broker.owner_slack_bindings SET LOGGED`);

      const internalTrigger = await client.query<{ tgname: string }>(
        `SELECT trigger.tgname
         FROM pg_catalog.pg_trigger trigger
         JOIN pg_catalog.pg_class relation ON relation.oid = trigger.tgrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relname = 'approved_intents'
           AND trigger.tgisinternal
         ORDER BY trigger.tgname LIMIT 1`,
      );
      assert(internalTrigger.rows[0]);
      const triggerName = `"${internalTrigger.rows[0].tgname.replaceAll('"', '""')}"`;
      await client.query(`ALTER TABLE gmail_draft_broker.approved_intents DISABLE TRIGGER ${triggerName}`);
      await rollbackRejectedBinding(/binding internal trigger postflight/u);
      await rollbackRejectedMigration(/trigger preconditions/u);
      await client.query(`ALTER TABLE gmail_draft_broker.approved_intents ENABLE TRIGGER ${triggerName}`);

      const currentDatabase = (await client.query<{ name: string }>(`SELECT pg_catalog.current_database() AS name`))
        .rows[0]!.name;
      const databaseIdentifier = `"${currentDatabase.replaceAll('"', '""')}"`;
      await client.query(
        `CREATE SCHEMA ${driftSchema};
         CREATE TABLE ${driftSchema}.relation_drift(value INTEGER);
         CREATE SEQUENCE ${driftSchema}.sequence_drift;
         CREATE TYPE ${driftSchema}.type_drift AS ENUM ('value');
         CREATE FUNCTION ${driftSchema}.function_drift() RETURNS INTEGER LANGUAGE sql AS 'SELECT 1'`,
      );
      const outsidePrivilegeCases = [
        [`GRANT CONNECT ON DATABASE ${databaseIdentifier} TO qm_gmail_draft_broker`, /direct privileges outside/u],
        [`GRANT USAGE ON SCHEMA ${driftSchema} TO qm_gmail_draft_broker`, /direct privileges outside/u],
        [`GRANT SELECT ON ${driftSchema}.relation_drift TO qm_gmail_draft_broker`, /direct privileges outside/u],
        [
          `GRANT SELECT (value) ON ${driftSchema}.relation_drift TO qm_gmail_draft_broker`,
          /direct privileges outside/u,
        ],
        [
          `GRANT USAGE ON SEQUENCE ${driftSchema}.sequence_drift TO qm_gmail_draft_broker`,
          /direct privileges outside/u,
        ],
        [
          `GRANT EXECUTE ON FUNCTION ${driftSchema}.function_drift() TO qm_gmail_draft_broker`,
          /direct privileges outside/u,
        ],
        [`GRANT USAGE ON TYPE ${driftSchema}.type_drift TO qm_gmail_draft_broker`, /direct privileges outside/u],
      ] as const;
      const outsidePrivilegeRevokes = [
        `REVOKE CONNECT ON DATABASE ${databaseIdentifier} FROM qm_gmail_draft_broker`,
        `REVOKE USAGE ON SCHEMA ${driftSchema} FROM qm_gmail_draft_broker`,
        `REVOKE SELECT ON ${driftSchema}.relation_drift FROM qm_gmail_draft_broker`,
        `REVOKE SELECT (value) ON ${driftSchema}.relation_drift FROM qm_gmail_draft_broker`,
        `REVOKE USAGE ON SEQUENCE ${driftSchema}.sequence_drift FROM qm_gmail_draft_broker`,
        `REVOKE EXECUTE ON FUNCTION ${driftSchema}.function_drift() FROM qm_gmail_draft_broker`,
        `REVOKE USAGE ON TYPE ${driftSchema}.type_drift FROM qm_gmail_draft_broker`,
      ] as const;
      for (const [index, [grant, pattern]] of outsidePrivilegeCases.entries()) {
        await client.query(grant);
        if (index === 1) await rollbackRejectedBinding(pattern);
        await rollbackRejectedMigration(pattern);
        await client.query(outsidePrivilegeRevokes[index]!);
      }
      await client.query(`ALTER TABLE ${driftSchema}.relation_drift OWNER TO qm_gmail_draft_owner`);
      await rollbackRejectedBinding(/own objects outside/u);
      await rollbackRejectedMigration(/own objects outside/u);
      await client.query(`ALTER TABLE ${driftSchema}.relation_drift OWNER TO CURRENT_USER`);
      await client.query(
        `ALTER DEFAULT PRIVILEGES FOR ROLE qm_gmail_draft_owner GRANT SELECT ON TABLES TO qm_gmail_draft_broker`,
      );
      await rollbackRejectedBinding(/owner-wide default ACLs/u);
      await rollbackRejectedMigration(/owner-wide default ACLs/u);
      await client.query(
        `ALTER DEFAULT PRIVILEGES FOR ROLE qm_gmail_draft_owner REVOKE SELECT ON TABLES FROM qm_gmail_draft_broker`,
      );
      await client.query(`DROP SCHEMA ${driftSchema} CASCADE`);

      await client.query(`GRANT qm_gmail_draft_broker TO ${brokerLogin} WITH ADMIN TRUE, INHERIT FALSE, SET TRUE`);
      await rollbackRejectedMigration(/exactly one intended direct isolated login binding/u);
      await client.query(runtimeRoleBindings);
      assert.deepEqual((await runtimeMemberships()).rows[1], {
        admin_option: false,
        granted_role: "qm_gmail_draft_broker",
        inherit_option: true,
        member_role: brokerLogin,
        set_option: false,
      });

      await client.query(`GRANT qm_gmail_draft_owner TO ${deploymentLogin} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE`);
      await client.query(migration);
      await client.query(`GRANT qm_gmail_draft_owner TO ${deploymentLogin} WITH ADMIN TRUE, INHERIT TRUE, SET TRUE`);
      await rollbackRejectedMigration(/exactly one intended direct isolated login binding/u);
      await client.query(runtimeRoleBindings);

      await client.query(`DROP INDEX gmail_draft_broker.gmail_draft_created_receipt_idx`);
      await client.query(
        `CREATE INDEX gmail_draft_created_receipt_idx
         ON gmail_draft_broker.approved_intents(terminal_receipt_sha256)
         WHERE status = 'created'`,
      );
      await rollbackRejectedMigration(/unexpected index definitions/u);
      await client.query(`DROP INDEX gmail_draft_broker.gmail_draft_created_receipt_idx`);
      await client.query(
        `CREATE UNIQUE INDEX gmail_draft_created_receipt_idx
         ON gmail_draft_broker.approved_intents(terminal_receipt_sha256)
         WHERE status = 'created'`,
      );

      await client.query(
        `ALTER TABLE gmail_draft_broker.approved_intents
         DROP CONSTRAINT approved_intents_reconciliation_nonce_check,
         ADD CONSTRAINT approved_intents_reconciliation_nonce_check CHECK (TRUE)`,
      );
      await rollbackRejectedMigration(/unexpected constraints/u);
      await client.query(
        `ALTER TABLE gmail_draft_broker.approved_intents
         DROP CONSTRAINT approved_intents_reconciliation_nonce_check,
         ADD CONSTRAINT approved_intents_reconciliation_nonce_check
         CHECK ((status = 'reconciling' AND reconciliation_nonce ~
             '^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$')
           OR (status <> 'reconciling' AND reconciliation_nonce IS NULL))`,
      );

      await client.query(
        `CREATE OR REPLACE FUNCTION gmail_draft_broker.reject_before_effect(TEXT,INTEGER,TEXT,TEXT)
         RETURNS BOOLEAN LANGUAGE sql SECURITY INVOKER
         SET search_path = pg_catalog, gmail_draft_broker
         AS 'SELECT TRUE'`,
      );
      await client.query(migration);
      const repairedFunction = await client.query<{ proconfig: string[]; prosecdef: boolean; prosrc: string }>(
        `SELECT routine.proconfig, routine.prosecdef, routine.prosrc
         FROM pg_catalog.pg_proc routine
         WHERE routine.oid =
           'gmail_draft_broker.reject_before_effect(text,integer,text,text)'::pg_catalog.regprocedure`,
      );
      assert.equal(repairedFunction.rows[0]?.prosecdef, true);
      assert.deepEqual(repairedFunction.rows[0]?.proconfig, ["search_path=pg_catalog, gmail_draft_broker"]);
      assert(repairedFunction.rows[0]?.prosrc.includes("status = 'pre_effect'"));
      assert(!repairedFunction.rows[0]?.prosrc.includes("SELECT TRUE"));
    } finally {
      await client.query(`ROLLBACK`).catch(() => undefined);
      await client
        .query(
          `ALTER DEFAULT PRIVILEGES FOR ROLE qm_gmail_draft_owner REVOKE SELECT ON TABLES FROM qm_gmail_draft_broker`,
        )
        .catch(() => undefined);
      await client.query(`DROP SCHEMA IF EXISTS ${driftSchema} CASCADE`).catch(() => undefined);
      await client
        .query(
          `REVOKE qm_gmail_draft_admission FROM ${admissionLogin} CASCADE;
           REVOKE qm_gmail_draft_broker FROM ${brokerLogin} CASCADE;
           REVOKE qm_gmail_draft_owner FROM ${deploymentLogin} CASCADE;
           REVOKE qm_gmail_draft_admission FROM ${extraLogin} CASCADE`,
        )
        .catch(() => undefined);
      await client
        .query(`DROP ROLE IF EXISTS ${admissionLogin}, ${brokerLogin}, ${deploymentLogin}, ${extraLogin}`)
        .catch(() => undefined);
      client.release();
      await pool.end();
    }
  },
);
