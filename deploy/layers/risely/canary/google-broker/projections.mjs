import { TextDecoder } from "node:util";
import { boundedText, canonicalBytes, GoogleBrokerContractError, integer, sha256 } from "./canonical.mjs";
import { snapshotProviderJson } from "./contracts.mjs";
import { assertVerifiedRead } from "./receipts.mjs";

const headerNames = new Map([
  ["from", "from"],
  ["to", "to"],
  ["subject", "subject"],
  ["date", "date"],
  ["reply-to", "replyTo"],
]);

const text = (value, label, maximumBytes, pattern) => boundedText(value, label, maximumBytes, pattern);

const optionalText = (value, label, maximumBytes, pattern) =>
  value === undefined || value === null ? null : text(value, label, maximumBytes, pattern);

const bodyText = (value) => {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 16_384 || value.includes("\u0000")) {
    throw new GoogleBrokerContractError("gmail_body_invalid");
  }
  return value;
};

const providerDateTime = (value, label) => {
  text(value, label, 40, /^(?:20|21)\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/);
  providerDate(value.slice(0, 10), `${label}_date`);
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch)) throw new GoogleBrokerContractError(`${label}_invalid`);
  return new Date(epoch).toISOString();
};

const providerDate = (value, label) => {
  text(value, label, 10, /^(?:20|21)\d{2}-\d{2}-\d{2}$/);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) {
    throw new GoogleBrokerContractError(`${label}_invalid`);
  }
  return value;
};

const dateOrDateTime = (value, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new GoogleBrokerContractError(`${label}_invalid`);
  const hasDateTime = typeof value.dateTime === "string";
  const hasDate = typeof value.date === "string";
  if (hasDateTime === hasDate) throw new GoogleBrokerContractError(`${label}_invalid`);
  if (hasDateTime) {
    return Object.freeze({
      kind: "dateTime",
      value: providerDateTime(value.dateTime, `${label}_date_time`),
      timeZone: optionalText(value.timeZone, `${label}_time_zone`, 128, /^(?:UTC|[A-Za-z_+-]+(?:\/[A-Za-z0-9_+-]+)+)$/),
    });
  }
  return Object.freeze({
    kind: "date",
    value: providerDate(value.date, `${label}_date`),
    timeZone: null,
  });
};

const projectCalendar = (response) => {
  const items = response.items === undefined ? [] : response.items;
  if (!Array.isArray(items) || items.length > 100) {
    throw new GoogleBrokerContractError("calendar_result_bounds_exceeded");
  }
  const events = items.map((event) => {
    if (!event || typeof event !== "object" || Array.isArray(event))
      throw new GoogleBrokerContractError("calendar_event_invalid");
    const cancelledWithoutTimes = event.status === "cancelled" && event.start === undefined && event.end === undefined;
    return Object.freeze({
      id: text(event.id, "calendar_event_id", 1024),
      status: optionalText(event.status, "calendar_event_status", 32, /^(confirmed|tentative|cancelled)$/),
      summary: optionalText(event.summary, "calendar_event_summary", 500),
      start: cancelledWithoutTimes ? null : dateOrDateTime(event.start, "calendar_start"),
      end: cancelledWithoutTimes ? null : dateOrDateTime(event.end, "calendar_end"),
      organizer:
        event.organizer && typeof event.organizer === "object" && !Array.isArray(event.organizer)
          ? Object.freeze({
              email: optionalText(event.organizer.email, "calendar_organizer_email", 320),
              displayName: optionalText(event.organizer.displayName, "calendar_organizer_name", 320),
              self: event.organizer.self === true,
            })
          : null,
    });
  });
  return Object.freeze({
    events: Object.freeze(events),
    nextPageToken: optionalText(response.nextPageToken, "calendar_next_page_token", 512),
  });
};

const projectGmailList = (response) => {
  const messages = response.messages === undefined ? [] : response.messages;
  if (!Array.isArray(messages) || messages.length > 20)
    throw new GoogleBrokerContractError("gmail_result_bounds_exceeded");
  return Object.freeze({
    messages: Object.freeze(
      messages.map((message) => {
        if (!message || typeof message !== "object" || Array.isArray(message)) {
          throw new GoogleBrokerContractError("gmail_message_invalid");
        }
        return Object.freeze({
          id: text(message.id, "gmail_message_id", 160, /^[A-Za-z0-9_-]{3,160}$/),
          threadId: text(message.threadId, "gmail_thread_id", 160, /^[A-Za-z0-9_-]{3,160}$/),
        });
      }),
    ),
    nextPageToken: optionalText(response.nextPageToken, "gmail_next_page_token", 512),
    resultSizeEstimate:
      response.resultSizeEstimate === undefined
        ? null
        : integer(response.resultSizeEstimate, "gmail_result_size_estimate", 0, 1_000_000),
  });
};

const decodePart = (data) => {
  text(data, "gmail_body_data", 24_000, /^[A-Za-z0-9_-]+$/);
  const bytes = Buffer.from(data, "base64url");
  if (bytes.toString("base64url") !== data || bytes.byteLength > 16_384) {
    throw new GoogleBrokerContractError("gmail_body_invalid");
  }
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new GoogleBrokerContractError("gmail_body_invalid");
  }
  return bodyText(decoded);
};

const collectPlainText = (payload) => {
  const bodies = [];
  const visit = (part, depth) => {
    if (!part || typeof part !== "object" || Array.isArray(part) || depth > 8) {
      throw new GoogleBrokerContractError("gmail_payload_invalid");
    }
    if (part.mimeType === "text/plain" && part.filename !== undefined && part.filename !== "") {
      throw new GoogleBrokerContractError("gmail_attachment_rejected");
    }
    if (part.mimeType === "text/plain" && part.body && typeof part.body === "object" && !Array.isArray(part.body)) {
      if (part.body.attachmentId !== undefined) throw new GoogleBrokerContractError("gmail_attachment_rejected");
      if (part.body.data !== undefined) bodies.push(decodePart(part.body.data));
    }
    if (part.parts !== undefined) {
      if (!Array.isArray(part.parts)) throw new GoogleBrokerContractError("gmail_payload_invalid");
      for (const child of part.parts) {
        if (bodies.length >= 64) throw new GoogleBrokerContractError("gmail_payload_bounds_exceeded");
        visit(child, depth + 1);
      }
    }
  };
  visit(payload, 0);
  const combined = bodies.join("\n");
  return bodyText(combined);
};

const projectHeaders = (headers) => {
  if (!Array.isArray(headers) || headers.length > 64) throw new GoogleBrokerContractError("gmail_headers_invalid");
  const projected = Object.create(null);
  for (const header of headers) {
    if (!header || typeof header !== "object" || Array.isArray(header))
      throw new GoogleBrokerContractError("gmail_headers_invalid");
    const name = text(header.name, "gmail_header_name", 64).toLowerCase();
    const outputName = headerNames.get(name);
    if (outputName && projected[outputName] === undefined) {
      projected[outputName] = text(header.value, "gmail_header_value", 2_048);
    }
  }
  return Object.freeze({
    from: projected.from ?? null,
    to: projected.to ?? null,
    subject: projected.subject ?? null,
    date: projected.date ?? null,
    replyTo: projected.replyTo ?? null,
  });
};

const projectGmailGet = (response, messageId) => {
  if (!response || typeof response !== "object" || Array.isArray(response) || response.id !== messageId) {
    throw new GoogleBrokerContractError("gmail_message_binding_mismatch");
  }
  if (!response.payload || typeof response.payload !== "object" || Array.isArray(response.payload)) {
    throw new GoogleBrokerContractError("gmail_payload_invalid");
  }
  return Object.freeze({
    id: text(response.id, "gmail_message_id", 160, /^[A-Za-z0-9_-]{3,160}$/),
    threadId: text(response.threadId, "gmail_thread_id", 160, /^[A-Za-z0-9_-]{3,160}$/),
    internalDate: optionalText(response.internalDate, "gmail_internal_date", 20, /^\d{1,20}$/),
    headers: projectHeaders(response.payload.headers ?? []),
    textPlain: collectPlainText(response.payload),
  });
};

export const inspectUntrustedProjectionShape = ({ operation, response: responseValue, messageId }) => {
  const response = snapshotProviderJson(responseValue);
  let data;
  if (operation === "google.calendar.events.list") data = projectCalendar(response);
  else if (operation === "google.gmail.messages.list") data = projectGmailList(response);
  else if (operation === "google.gmail.messages.get") {
    data = projectGmailGet(response, boundedText(messageId, "gmail_message_id", 160, /^[A-Za-z0-9_-]{3,160}$/));
  } else throw new GoogleBrokerContractError("operation_unsupported");
  return Object.freeze({ usable: false, reason: "verified_authority_required", data });
};

export const projectVerifiedRead = (verifiedValue) => {
  const verified = assertVerifiedRead(verifiedValue);
  if (verified.receipt.outcome !== "succeeded")
    throw new GoogleBrokerContractError(`provider_${verified.receipt.outcome}`);
  let data;
  if (verified.receipt.operation === "google.calendar.events.list") data = projectCalendar(verified.response);
  else if (verified.receipt.operation === "google.gmail.messages.list") data = projectGmailList(verified.response);
  else if (verified.receipt.operation === "google.gmail.messages.get") {
    throw new GoogleBrokerContractError("request_context_required");
  } else throw new GoogleBrokerContractError("operation_unsupported");
  const evidence = Object.freeze({
    version: 1,
    source: "google_broker",
    contentTrust: "external_untrusted",
    operation: verified.receipt.operation,
    organizationId: verified.receipt.organizationId,
    deploymentId: verified.receipt.deploymentId,
    servicePrincipal: verified.receipt.servicePrincipal,
    qmPrincipalId: verified.receipt.qmPrincipalId,
    credentialOwnerId: verified.receipt.credentialOwnerId,
    provider: verified.receipt.provider,
    providerAccountSubject: verified.receipt.providerAccountSubject,
    mailbox: verified.receipt.mailbox,
    accountType: verified.receipt.accountType,
    credentialId: verified.receipt.credentialId,
    credentialVersion: verified.receipt.credentialVersion,
    grantId: verified.receipt.grantId,
    grantVersion: verified.receipt.grantVersion,
    grantExpiresAt: verified.receipt.grantExpiresAt,
    leaseId: verified.receipt.leaseId,
    leaseExpiresAt: verified.receipt.leaseExpiresAt,
    leaseNonce: verified.receipt.leaseNonce,
    jobId: verified.receipt.jobId,
    jobClass: verified.receipt.jobClass,
    requestNonce: verified.receipt.requestNonce,
    idempotencyKey: verified.receipt.idempotencyKey,
    requestHash: verified.receipt.requestHash,
    responseHash: verified.receipt.responseHash,
    authorityEnvelopeHash: verified.receipt.authorityEnvelopeHash,
    receiptId: verified.receipt.receiptId,
    keyId: verified.receipt.keyId,
    observedAt: verified.receipt.serverCompletedAt,
    data,
  });
  if (canonicalBytes(evidence).byteLength > 131_072) throw new GoogleBrokerContractError("evidence_bounds_exceeded");
  return Object.freeze({ ...evidence, evidenceHash: sha256(evidence) });
};

export const projectVerifiedGmailMessage = (verifiedValue) => {
  const verified = assertVerifiedRead(verifiedValue);
  if (verified.receipt.operation !== "google.gmail.messages.get" || verified.receipt.outcome !== "succeeded") {
    throw new GoogleBrokerContractError("gmail_get_receipt_required");
  }
  const data = projectGmailGet(verified.response, verified.request.parameters.messageId);
  const base = Object.freeze({
    version: 1,
    source: "google_broker",
    contentTrust: "external_untrusted",
    operation: verified.receipt.operation,
    organizationId: verified.receipt.organizationId,
    deploymentId: verified.receipt.deploymentId,
    servicePrincipal: verified.receipt.servicePrincipal,
    qmPrincipalId: verified.receipt.qmPrincipalId,
    credentialOwnerId: verified.receipt.credentialOwnerId,
    provider: verified.receipt.provider,
    providerAccountSubject: verified.receipt.providerAccountSubject,
    mailbox: verified.receipt.mailbox,
    accountType: verified.receipt.accountType,
    credentialId: verified.receipt.credentialId,
    credentialVersion: verified.receipt.credentialVersion,
    grantId: verified.receipt.grantId,
    grantVersion: verified.receipt.grantVersion,
    grantExpiresAt: verified.receipt.grantExpiresAt,
    leaseId: verified.receipt.leaseId,
    leaseExpiresAt: verified.receipt.leaseExpiresAt,
    leaseNonce: verified.receipt.leaseNonce,
    jobId: verified.receipt.jobId,
    jobClass: verified.receipt.jobClass,
    requestNonce: verified.receipt.requestNonce,
    idempotencyKey: verified.receipt.idempotencyKey,
    requestHash: verified.receipt.requestHash,
    responseHash: verified.receipt.responseHash,
    authorityEnvelopeHash: verified.receipt.authorityEnvelopeHash,
    receiptId: verified.receipt.receiptId,
    keyId: verified.receipt.keyId,
    observedAt: verified.receipt.serverCompletedAt,
    data,
  });
  if (canonicalBytes(base).byteLength > 131_072) throw new GoogleBrokerContractError("evidence_bounds_exceeded");
  return Object.freeze({ ...base, evidenceHash: sha256(base) });
};
