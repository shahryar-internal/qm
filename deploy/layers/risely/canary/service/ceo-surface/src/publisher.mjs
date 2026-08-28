import { buildPrivateCeoSurface } from "../../../presentation/index.mjs";
import { renderPrivateCeoSlackBlockKitFromSurface } from "../../../slack/index.mjs";
import { PrincipalBinding } from "../../../shared-contracts/index.mjs";
import {
  fixedCeoSurface,
  liveReceiptAuthorityRequirements,
  receiptOptionalFields,
  receiptRequiredFields,
  reservationConflictFields,
} from "./constants.mjs";
import { compileDeploymentBinding, validateIdentityResolution, validateOutboxItem } from "./contracts.mjs";
import { exactKeys, timestamp } from "./validation.mjs";

const deepFreeze = PrincipalBinding.freeze;
const sha256Canonical = PrincipalBinding.hash;
const snapshot = PrincipalBinding.snapshot;

function surfaceArtifact(artifact) {
  return Object.freeze({
    schemaVersion: 1,
    artifactRef: artifact.id,
    revision: artifact.revision,
    kind: artifact.kind === "meeting_followup" ? "post_meeting" : artifact.kind,
    state: artifact.state === "expired" ? "superseded" : artifact.state,
    evidence: Object.freeze(
      artifact.evidence.map((entry) =>
        Object.freeze({
          evidenceRef: `evidence:${sha256Canonical(entry)}`,
          trust: "untrusted_source_data",
          availability: "available",
        }),
      ),
    ),
    links: Object.freeze([]),
  });
}

function assertActionless(message) {
  if (message.blocks.some((block) => block.type === "actions"))
    throw new TypeError("CEO shadow delivery must be actionless");
  const serialized = JSON.stringify(message);
  if (/"action_id"|"value"\s*:|"type"\s*:\s*"button"/.test(serialized))
    throw new TypeError("CEO shadow delivery contains an interaction surface");
}

function assertOnlyQmRootLink(message) {
  const qmLink = `<${fixedCeoSurface.qmRootUrl}|Open in QM>`;
  const linkLike =
    /(?:(?:[a-z][a-z0-9+.-]*:\/\/|(?:mailto|tel):)|www\.|(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+(?:[\p{L}]{2,63}|xn--[a-z0-9-]{2,59})\b|(?:\d{1,3}\.){3}\d{1,3})/iu;
  const values = [];
  const visit = (value) => {
    if (typeof value === "string") values.push(value);
    else if (Array.isArray(value)) value.forEach(visit);
    else if (value && typeof value === "object") Object.values(value).forEach(visit);
  };
  visit(message);
  let qmLinkCount = 0;
  for (const value of values) {
    const withoutQmLink = value.replaceAll(qmLink, () => {
      qmLinkCount += 1;
      return "";
    });
    if (/[<>]/u.test(withoutQmLink) || linkLike.test(withoutQmLink))
      throw new TypeError("CEO shadow delivery contains a non-QM auto-link target");
  }
  if (qmLinkCount !== 1) throw new TypeError("CEO shadow delivery must contain exactly one authenticated QM root link");
}

function compilePublication(value, authorityTime) {
  const input = exactKeys(
    snapshot(value, "publicationInput"),
    ["deploymentBinding", "outboxItem", "identityResolution"],
    ["deploymentBinding", "outboxItem", "identityResolution"],
    "publicationInput",
  );
  const deployment = compileDeploymentBinding(input.deploymentBinding);
  const outbox = validateOutboxItem(input.outboxItem, deployment, authorityTime);
  const identity = validateIdentityResolution(input.identityResolution, deployment, authorityTime);
  const surface = buildPrivateCeoSurface(surfaceArtifact(outbox.artifact));
  const rendered = renderPrivateCeoSlackBlockKitFromSurface(surface);
  const message = deepFreeze({
    text: rendered.text,
    blocks: [
      ...rendered.blocks,
      {
        type: "context",
        elements: [{ type: "mrkdwn", text: `<${fixedCeoSurface.qmRootUrl}|Open in QM>` }],
      },
    ],
  });
  assertActionless(message);
  assertOnlyQmRootLink(message);
  const messageSha256 = sha256Canonical(message);
  const deliveryKey = sha256Canonical({
    deploymentBindingSha256: deployment.bindingSha256,
    outboxEventId: outbox.eventId,
  });
  const target = {
    teamRef: deployment.teamRef,
    audienceRef: deployment.audienceRef,
    ceoUserRef: deployment.ceoUserRef,
    ceoEmail: deployment.ceoEmail,
    qmPrincipalRef: deployment.qmPrincipalRef,
    credentialOwnerRef: deployment.credentialOwnerRef,
    slackTeamId: identity.slackTeamId,
    slackUserId: identity.slackUserId,
    slackDirectMessageId: identity.slackDirectMessageId,
  };
  const targetBindingSha256 = sha256Canonical({
    deploymentBindingSha256: deployment.bindingSha256,
    target,
  });
  return deepFreeze({
    contractType: "ceo-surface-shadow-publication",
    contractVersion: 1,
    mode: fixedCeoSurface.deliveryMode,
    providerInvocationAllowed: false,
    outboxEventId: outbox.eventId,
    outboxPayloadSha256: outbox.payloadSha256,
    artifactId: outbox.artifact.id,
    artifactRevision: outbox.artifact.revision,
    artifactSha256: outbox.artifactSha256,
    evalReceiptSha256: outbox.evalRelease.receiptSha256,
    deploymentBindingSha256: deployment.bindingSha256,
    identityResolutionSha256: identity.resolutionSha256,
    targetBindingSha256,
    deliveryKey,
    target,
    message,
    messageSha256,
    receiptContract: {
      durability: "postgres",
      atomicReservationRequired: true,
      uniqueKey: deliveryKey,
      conflictFields: reservationConflictFields,
      requiredFields: receiptRequiredFields,
      optionalFields: receiptOptionalFields,
      authorityRequirements: liveReceiptAuthorityRequirements,
    },
  });
}

export function compileShadowPublication(value) {
  return compilePublication(value, new Date().toISOString());
}

export function reconstructShadowPublication(value, authorityTime) {
  return compilePublication(value, timestamp(authorityTime, "publicationAuthorityTime"));
}
