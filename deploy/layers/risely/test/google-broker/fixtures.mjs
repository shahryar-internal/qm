import { generateKeyPairSync, sign } from "node:crypto";
import {
  canonicalBytes,
  createAuthorityInspector,
  createReadRequest,
  sha256,
  snapshotProviderJson,
} from "../../canary/google-broker/index.mjs";

export const nonce = (octet) => Buffer.alloc(32, octet).toString("base64url");

export const clock = Object.freeze({
  grantIssued: "2026-08-26T12:00:00.000Z",
  leaseIssued: "2026-08-26T12:01:00.000Z",
  authorityAsserted: "2026-08-26T12:01:30.000Z",
  received: "2026-08-26T12:02:01.000Z",
  completed: "2026-08-26T12:02:02.000Z",
  leaseExpires: "2026-08-26T12:06:00.000Z",
  grantExpires: "2026-08-26T13:00:00.000Z",
});

export const binding = Object.freeze({
  organizationId: "org:risely-0001",
  deploymentId: "deployment:ceo-canary-0001",
  servicePrincipal: "service:ceo-canary",
  qmPrincipalId: "person:principal-0001",
  credentialOwnerId: "person:principal-0001",
  provider: "google",
  providerAccountSubject: "google-subject-0001",
  mailbox: "ceo@example.com",
  accountType: "personal",
  credentialId: "credential_0001",
  credentialVersion: 7,
  grantId: "grant_00000001",
  grantVersion: 3,
  leaseId: "lease_00000001",
  leaseExpiresAt: clock.leaseExpires,
  leaseNonce: nonce(1),
  jobId: "job_000000001",
  jobClass: "ceo_canary_read",
});

const identity = Object.freeze({
  organizationId: binding.organizationId,
  deploymentId: binding.deploymentId,
  servicePrincipal: binding.servicePrincipal,
  qmPrincipalId: binding.qmPrincipalId,
  credentialOwnerId: binding.credentialOwnerId,
  provider: binding.provider,
  providerAccountSubject: binding.providerAccountSubject,
  mailbox: binding.mailbox,
  accountType: binding.accountType,
  credentialId: binding.credentialId,
  credentialVersion: binding.credentialVersion,
  grantId: binding.grantId,
  grantVersion: binding.grantVersion,
});

export const makeGrant = (overrides = {}) => ({
  version: 1,
  ...identity,
  jobClass: binding.jobClass,
  operations: ["google.calendar.events.list", "google.gmail.messages.get", "google.gmail.messages.list"],
  purpose: "Bounded CEO canary source verification",
  state: "active",
  issuedAt: clock.grantIssued,
  expiresAt: clock.grantExpires,
  serverClock: "postgresql",
  ...overrides,
});

export const makeLease = (overrides = {}) => ({
  version: 1,
  ...identity,
  leaseId: binding.leaseId,
  jobId: binding.jobId,
  jobClass: binding.jobClass,
  operations: ["google.calendar.events.list", "google.gmail.messages.get", "google.gmail.messages.list"],
  state: "active",
  stateReason: null,
  nonce: binding.leaseNonce,
  issuedAt: clock.leaseIssued,
  expiresAt: clock.leaseExpires,
  serverClock: "postgresql",
  ...overrides,
});

export const parameters = Object.freeze({
  calendar: Object.freeze({
    timeMin: "2026-08-26T00:00:00.000Z",
    timeMax: "2026-08-27T00:00:00.000Z",
    maxResults: 20,
    singleEvents: true,
    orderBy: "startTime",
    pageToken: null,
  }),
  gmailList: Object.freeze({
    labelIds: Object.freeze(["INBOX"]),
    maxResults: 20,
    includeSpamTrash: false,
    pageToken: null,
  }),
  gmailGet: Object.freeze({
    messageId: "message_0001",
    format: "full",
    listingReceiptId: "listing_receipt_0001",
    listingRequestHash: "1".repeat(64),
    listingResponseHash: "2".repeat(64),
  }),
});

export const makeRequest = ({
  operation = "google.calendar.events.list",
  requestBinding = binding,
  requestNonce = nonce(2),
  idempotencyKey = "idempotency_0001",
  requestParameters,
} = {}) =>
  createReadRequest({
    version: 1,
    operation,
    binding: requestBinding,
    parameters:
      requestParameters ??
      (operation === "google.calendar.events.list"
        ? parameters.calendar
        : operation === "google.gmail.messages.list"
          ? parameters.gmailList
          : parameters.gmailGet),
    requestNonce,
    idempotencyKey,
  });

export const makeKeys = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return Object.freeze({
    keyId: "google-broker-key-0001",
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
    privateKey,
  });
};

export const signPayload = (payload, privateKey) =>
  sign(null, canonicalBytes(payload), privateKey).toString("base64url");

export const makeAuthorityEnvelope = ({ keys, grant = makeGrant(), lease = makeLease(), overrides = {} }) => {
  const base = {
    version: 1,
    keyId: keys.keyId,
    algorithm: "Ed25519",
    grant,
    lease,
    serverAssertedAt: clock.authorityAsserted,
    ...overrides,
  };
  return Object.freeze({ ...base, signature: signPayload(base, keys.privateKey) });
};

export const inspectAuthority = ({ keys, envelope = makeAuthorityEnvelope({ keys }) }) =>
  createAuthorityInspector({ keyId: keys.keyId, publicKey: keys.publicKey }).inspect(envelope);

export const makeReadReceipt = ({ request, response, keys, authorityEnvelope, overrides = {} }) => {
  const normalizedResponse = snapshotProviderJson(response);
  const base = {
    version: 1,
    receiptId: request.operation === "google.gmail.messages.list" ? "listing_receipt_0001" : "receipt_0000001",
    keyId: keys.keyId,
    algorithm: "Ed25519",
    authorityEnvelopeHash: sha256(authorityEnvelope),
    organizationId: request.binding.organizationId,
    deploymentId: request.binding.deploymentId,
    servicePrincipal: request.binding.servicePrincipal,
    qmPrincipalId: request.binding.qmPrincipalId,
    credentialOwnerId: request.binding.credentialOwnerId,
    provider: request.binding.provider,
    providerAccountSubject: request.binding.providerAccountSubject,
    mailbox: request.binding.mailbox,
    accountType: request.binding.accountType,
    credentialId: request.binding.credentialId,
    credentialVersion: request.binding.credentialVersion,
    grantId: request.binding.grantId,
    grantVersion: request.binding.grantVersion,
    grantExpiresAt: clock.grantExpires,
    leaseId: request.binding.leaseId,
    leaseExpiresAt: request.binding.leaseExpiresAt,
    leaseNonce: request.binding.leaseNonce,
    jobId: request.binding.jobId,
    jobClass: request.binding.jobClass,
    operation: request.operation,
    requestNonce: request.requestNonce,
    idempotencyKey: request.idempotencyKey,
    requestHash: request.requestHash,
    serverClock: "postgresql",
    serverReceivedAt: clock.received,
    serverCompletedAt: clock.completed,
    providerStatus: 200,
    redirected: false,
    responseHash: sha256(normalizedResponse),
    responseBytes: canonicalBytes(normalizedResponse).byteLength,
    outcome: "succeeded",
    outcomeReason: null,
    ...overrides,
  };
  return Object.freeze({ ...base, signature: signPayload(base, keys.privateKey) });
};

export const calendarResponse = Object.freeze({
  kind: "calendar#events",
  accessToken: "provider-secret-must-not-project",
  authorization: "Bearer provider-secret",
  items: Object.freeze([
    Object.freeze({
      id: "event_0001",
      status: "confirmed",
      summary: "Board review",
      htmlLink: "https://calendar.google.com/secret-link",
      start: Object.freeze({ dateTime: "2026-08-26T10:00:00.000-07:00", timeZone: "America/Los_Angeles" }),
      end: Object.freeze({ dateTime: "2026-08-26T11:00:00.000-07:00", timeZone: "America/Los_Angeles" }),
      organizer: Object.freeze({ email: "ceo@example.com", displayName: "CEO", self: true }),
    }),
  ]),
  nextPageToken: null,
});
