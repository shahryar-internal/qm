import { sha256Canonical } from "../contracts/index.mjs";
import {
  assertHash,
  assertInteger,
  assertRecord,
  assertRef,
  parseInstant,
  snapshotPlainJson,
  fail,
} from "./validation.mjs";

const calendarHost = "https://www.googleapis.com";
const gmailHost = "https://gmail.googleapis.com";
const operations = Object.freeze({
  "calendar.events.read": Object.freeze({
    provider: "google_calendar",
    audience: calendarHost,
    method: "GET",
    path: "/calendar/v3/calendars/primary/events",
    resourceRoot: "primary",
  }),
  "gmail.messages.list": Object.freeze({
    provider: "google_gmail",
    audience: gmailHost,
    method: "GET",
    path: "/gmail/v1/users/me/messages",
    resourceRoot: "me",
  }),
  "gmail.messages.read": Object.freeze({
    provider: "google_gmail",
    audience: gmailHost,
    method: "GET",
    path: "/gmail/v1/users/me/messages/{messageId}",
    resourceRoot: "me",
  }),
});
const proposalInputKeys = [
  "deploymentRef",
  "organizationRef",
  "automationGrantRef",
  "principalRef",
  "credentialOwnerRef",
  "connectionRef",
  "calendarAccountRef",
  "audienceRef",
  "destinationRef",
  "deliveryAudience",
  "deliveryDestination",
  "providerAccountSubject",
  "jobId",
  "scheduleRevision",
  "requestPlanHash",
  "operation",
  "nonce",
  "requestedTtlSeconds",
];
const requestPlanKeys = ["method", "url", "query", "responseProjection"];
const proposalBrands = new WeakSet();

const operationContract = (operation) => {
  const contract = operations[operation];
  if (!contract) fail("unsupported_provider_operation");
  return contract;
};

export const createProviderExecutionProposal = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(value, proposalInputKeys, "invalid_provider_execution_proposal");
  const operation = operationContract(value.operation);
  const identity = Object.freeze({
    organizationRef: assertRef(value.organizationRef),
    deploymentRef: assertRef(value.deploymentRef),
    automationGrantRef: assertRef(value.automationGrantRef),
    principalRef: assertRef(value.principalRef),
    credentialOwnerRef: assertRef(value.credentialOwnerRef),
    connectionRef: assertRef(value.connectionRef),
    calendarAccountRef: assertRef(value.calendarAccountRef),
    audienceRef: assertRef(value.audienceRef),
    destinationRef: assertRef(value.destinationRef),
    deliveryAudience: value.deliveryAudience,
    deliveryDestination: value.deliveryDestination,
    providerAccountSubject: assertRef(value.providerAccountSubject),
    jobId: assertHash(value.jobId),
    scheduleRevision: assertHash(value.scheduleRevision),
    requestPlanHash: assertHash(value.requestPlanHash),
    operation: value.operation,
    audience: operation.audience,
    resourceRoot: operation.resourceRoot,
    nonce: assertRef(value.nonce),
    requestedTtlSeconds: assertInteger(value.requestedTtlSeconds, 1, 60),
  });
  if (
    identity.deliveryAudience !== "ceo_private" ||
    !["slack_ceo_dm", "qm_ceo_inbox"].includes(identity.deliveryDestination)
  ) {
    fail("invalid_provider_execution_destination");
  }
  const proposal = Object.freeze({
    schemaVersion: 1,
    proposalId: sha256Canonical(identity),
    ...identity,
    authorizationState: "unresolved",
    durableBrokerConsumptionRequired: true,
    replayProtectionProvided: false,
    credentialMaterialAllowed: false,
    providerExecutionAllowed: false,
  });
  proposalBrands.add(proposal);
  return proposal;
};

export const assertProviderExecutionProposal = (proposal, operation) => {
  if (!proposalBrands.has(proposal) || proposal.operation !== operation) {
    fail("untrusted_provider_execution_proposal");
  }
  return proposal;
};

const normalizeQuery = (query) => {
  const value = snapshotPlainJson(query);
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length > 16) {
    fail("invalid_provider_query");
  }
  const normalized = Object.create(null);
  for (const [key, entry] of Object.entries(value)) {
    if (!/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(key) || typeof entry !== "string" || entry.length > 512) {
      fail("invalid_provider_query");
    }
    normalized[key] = entry;
  }
  return Object.freeze(normalized);
};

const executionPlan = (proposal, operation, requestPlan) => {
  assertProviderExecutionProposal(proposal, operation);
  const contract = operationContract(operation);
  const request = snapshotPlainJson(requestPlan);
  assertRecord(request, requestPlanKeys, "invalid_provider_request_plan");
  let url;
  try {
    url = new URL(request.url);
  } catch {
    fail("provider_host_mismatch");
  }
  if (
    request.method !== contract.method ||
    url.origin !== contract.audience ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    fail("provider_host_mismatch");
  }
  const normalizedRequest = Object.freeze({
    method: request.method,
    url: request.url,
    query: normalizeQuery(request.query),
    responseProjection: assertRef(request.responseProjection),
  });
  const requestPlanHash = sha256Canonical(normalizedRequest);
  if (proposal.requestPlanHash !== requestPlanHash) fail("provider_request_plan_mismatch");
  return Object.freeze({
    schemaVersion: 1,
    executionPlanId: sha256Canonical({ proposalId: proposal.proposalId, requestPlanHash }),
    proposal,
    request: normalizedRequest,
    requestPlanHash,
    authorizationState: "unresolved",
    durableBrokerConsumptionRequired: true,
    replayProtectionProvided: false,
    providerExecutionAllowed: false,
  });
};

export const planCalendarUpcomingRead = (proposal, input) => {
  const value = snapshotPlainJson(input);
  assertRecord(value, ["from", "to", "maxResults"], "invalid_calendar_window");
  const from = parseInstant(value.from);
  const to = parseInstant(value.to);
  const maxResults = assertInteger(value.maxResults, 1, 100);
  if (to <= from || to.valueOf() - from.valueOf() > 31 * 86_400_000) fail("invalid_calendar_window");
  return executionPlan(proposal, "calendar.events.read", {
    method: "GET",
    url: `${calendarHost}/calendar/v3/calendars/primary/events`,
    query: {
      timeMin: from.toISOString(),
      timeMax: to.toISOString(),
      maxResults: String(maxResults),
      singleEvents: "true",
      orderBy: "startTime",
      showDeleted: "true",
    },
    responseProjection: "calendar.events.strict.v1",
  });
};

export const planGmailMessageListRead = (proposal, input) => {
  const value = snapshotPlainJson(input);
  assertRecord(value, ["query", "maxResults"], "invalid_gmail_query");
  if (
    typeof value.query !== "string" ||
    value.query.length < 1 ||
    value.query.length > 256 ||
    /[\r\n]/.test(value.query)
  ) {
    fail("invalid_gmail_query");
  }
  return executionPlan(proposal, "gmail.messages.list", {
    method: "GET",
    url: `${gmailHost}/gmail/v1/users/me/messages`,
    query: {
      q: value.query,
      maxResults: String(assertInteger(value.maxResults, 1, 10)),
      includeSpamTrash: "false",
    },
    responseProjection: "gmail.message-refs.strict.v1",
  });
};

export const planGmailMessageRead = (proposal, input) => {
  const value = snapshotPlainJson(input);
  assertRecord(value, ["messageId"], "invalid_gmail_message");
  const messageId = assertRef(value.messageId);
  if (!/^[A-Za-z0-9_-]{3,160}$/.test(messageId)) fail("invalid_gmail_message");
  return executionPlan(proposal, "gmail.messages.read", {
    method: "GET",
    url: `${gmailHost}/gmail/v1/users/me/messages/${messageId}`,
    query: { format: "metadata" },
    responseProjection: "gmail.metadata-only.strict.v1",
  });
};

export const coreTokenResolverContract = Object.freeze({
  serverClockRequired: true,
  monotonicConsumptionRequired: true,
  durableSingleUseReservationRequired: true,
  exactProposalIdentityRequired: true,
  rawCredentialResponseAllowed: false,
  implementationPresent: false,
});

export const googleProviderBoundary = Object.freeze({
  calendarHost,
  gmailHost,
  operations,
  credentialMaterialAllowed: false,
  providerExecutionAllowed: false,
});
