import assert from "node:assert/strict";
import test from "node:test";
import {
  createAuthorityInspector,
  createReadReceiptInspector,
  GoogleBrokerContractError,
  inspectReadLineage,
  inspectUntrustedProjectionShape,
  projectVerifiedGmailMessage,
  projectVerifiedRead,
} from "../../canary/google-broker/index.mjs";
import {
  binding,
  calendarResponse,
  clock,
  inspectAuthority,
  makeAuthorityEnvelope,
  makeGrant,
  makeKeys,
  makeLease,
  makeReadReceipt,
  makeRequest,
  nonce,
} from "./fixtures.mjs";

const code = (expected) => (error) => error instanceof GoogleBrokerContractError && error.code === expected;

const inspectRead = ({ keys, envelope, authority, request, response, receipt, listing }) =>
  createReadReceiptInspector({ keyId: keys.keyId, publicKey: keys.publicKey }).inspect({
    authority,
    request,
    response,
    receipt,
    listing,
  });

const readFixture = ({
  operation = "google.calendar.events.list",
  response = calendarResponse,
  requestParameters,
} = {}) => {
  const keys = makeKeys();
  const envelope = makeAuthorityEnvelope({ keys });
  const authority = inspectAuthority({ keys, envelope });
  const request = makeRequest({ operation, requestParameters });
  const receipt = makeReadReceipt({ request, response, keys, authorityEnvelope: envelope });
  return { keys, envelope, authority, request, response, receipt };
};

test("signed authority inspection is cryptographically positive but permanently unusable without trusted time", () => {
  const keys = makeKeys();
  const envelope = makeAuthorityEnvelope({ keys });
  const inspected = inspectAuthority({ keys, envelope });
  assert.equal(inspected.cryptographicallyVerified, true);
  assert.equal(inspected.usable, false);
  assert.equal(inspected.reason, "trusted_current_time_unavailable");
  assert.equal(inspected.envelopeHash.length, 64);
  assert.throws(() => projectVerifiedRead(inspected), code("trusted_current_time_unavailable"));
  assert.throws(() => projectVerifiedGmailMessage(inspected), code("trusted_current_time_unavailable"));
});

test("authority signatures reject independent signature, key, and signed-field mutations", () => {
  const keys = makeKeys();
  const envelope = makeAuthorityEnvelope({ keys });
  const inspector = createAuthorityInspector({ keyId: keys.keyId, publicKey: keys.publicKey });
  const tamperedSignature = {
    ...envelope,
    signature: `${envelope.signature[0] === "A" ? "B" : "A"}${envelope.signature.slice(1)}`,
  };
  assert.throws(() => inspector.inspect(tamperedSignature), code("signature_invalid"));
  const changedGrant = { ...envelope, grant: { ...envelope.grant, purpose: "Changed after signing" } };
  assert.throws(() => inspector.inspect(changedGrant), code("signature_invalid"));
  const changedKeyId = { ...envelope, keyId: "google-broker-key-0002" };
  assert.throws(() => inspector.inspect(changedKeyId), code("signature_key_id_mismatch"));
});

test("signed authority rejects revoked, quarantined, and unavailable grant and lease states", () => {
  const keys = makeKeys();
  for (const state of ["revoked", "quarantined", "unavailable"]) {
    const grantEnvelope = makeAuthorityEnvelope({ keys, grant: makeGrant({ state }) });
    assert.throws(
      () => inspectAuthority({ keys, envelope: grantEnvelope }),
      code("authority_server_assertion_invalid"),
    );
    const leaseEnvelope = makeAuthorityEnvelope({
      keys,
      lease: makeLease({ state, stateReason: `${state}.test` }),
    });
    assert.throws(
      () => inspectAuthority({ keys, envelope: leaseEnvelope }),
      code("authority_server_assertion_invalid"),
    );
  }
});

test("signed authority rejects before-issue, exact-expiry, and after-expiry server assertions", () => {
  const keys = makeKeys();
  for (const serverAssertedAt of ["2026-08-26T12:00:59.999Z", clock.leaseExpires, "2026-08-26T12:06:00.001Z"]) {
    const envelope = makeAuthorityEnvelope({ keys, overrides: { serverAssertedAt } });
    assert.throws(() => inspectAuthority({ keys, envelope }), code("authority_server_assertion_invalid"));
  }
  assert.equal(
    inspectAuthority({
      keys,
      envelope: makeAuthorityEnvelope({ keys, overrides: { serverAssertedAt: clock.leaseIssued } }),
    }).usable,
    false,
  );
});

test("signed read receipt is inspectable but cannot become Calendar, Gmail-list, or Gmail-get evidence", () => {
  const calendar = readFixture();
  const calendarInspection = inspectRead(calendar);
  assert.equal(calendarInspection.cryptographicallyVerified, true);
  assert.equal(calendarInspection.usable, false);
  assert.throws(() => projectVerifiedRead(calendarInspection), code("trusted_current_time_unavailable"));

  const listResponse = { messages: [{ id: "message_0001", threadId: "thread_0001" }] };
  const listing = readFixture({ operation: "google.gmail.messages.list", response: listResponse });
  const listingInspection = inspectRead(listing);
  assert.throws(() => projectVerifiedRead(listingInspection), code("trusted_current_time_unavailable"));

  const getResponse = {
    id: "message_0001",
    threadId: "thread_0001",
    labelIds: ["INBOX"],
    payload: { headers: [], mimeType: "text/plain", filename: "", body: { data: "QQ" } },
  };
  const request = makeRequest({
    operation: "google.gmail.messages.get",
    requestParameters: {
      messageId: "message_0001",
      format: "full",
      listingReceiptId: listingInspection.receipt.receiptId,
      listingRequestHash: listingInspection.receipt.requestHash,
      listingResponseHash: listingInspection.receipt.responseHash,
    },
  });
  const receipt = makeReadReceipt({
    request,
    response: getResponse,
    keys: listing.keys,
    authorityEnvelope: listing.envelope,
  });
  const getInspection = inspectRead({
    ...listing,
    request,
    response: getResponse,
    receipt,
    listing: listingInspection,
  });
  assert.throws(() => projectVerifiedGmailMessage(getInspection), code("trusted_current_time_unavailable"));
});

test("unusable signed lineage preserves every non-secret evidence binding", () => {
  for (const fixture of [
    readFixture(),
    readFixture({
      operation: "google.gmail.messages.list",
      response: { messages: [{ id: "message_0001", threadId: "thread_0001" }] },
    }),
  ]) {
    const inspection = inspectRead(fixture);
    const lineage = inspectReadLineage(inspection);
    assert.equal(lineage.usable, false);
    assert.equal(lineage.contentTrust, "external_untrusted");
    for (const field of [
      "organizationId",
      "deploymentId",
      "servicePrincipal",
      "qmPrincipalId",
      "credentialOwnerId",
      "provider",
      "providerAccountSubject",
      "mailbox",
      "accountType",
      "credentialId",
      "credentialVersion",
      "grantId",
      "grantVersion",
      "grantExpiresAt",
      "leaseId",
      "leaseExpiresAt",
      "leaseNonce",
      "jobId",
      "jobClass",
      "operation",
      "requestNonce",
      "idempotencyKey",
      "requestHash",
      "responseHash",
      "authorityEnvelopeHash",
      "receiptId",
      "keyId",
      "observedAt",
    ]) {
      assert.notEqual(lineage[field], undefined);
    }
    assert.doesNotMatch(JSON.stringify(lineage), /accessToken|refreshToken|authorization|Bearer/);
  }
  assert.throws(() => inspectReadLineage({}), code("signed_read_inspection_required"));
});

test("receipt validation rejects independent signature, authority-hash, and response mutations", () => {
  const fixture = readFixture();
  const tampered = {
    ...fixture.receipt,
    signature: `${fixture.receipt.signature[0] === "A" ? "B" : "A"}${fixture.receipt.signature.slice(1)}`,
  };
  assert.throws(() => inspectRead({ ...fixture, receipt: tampered }), code("signature_invalid"));
  const wrongAuthorityHash = makeReadReceipt({
    request: fixture.request,
    response: fixture.response,
    keys: fixture.keys,
    authorityEnvelope: fixture.envelope,
    overrides: { authorityEnvelopeHash: "0".repeat(64) },
  });
  assert.throws(() => inspectRead({ ...fixture, receipt: wrongAuthorityHash }), code("receipt_authority_mismatch"));
  assert.throws(
    () => inspectRead({ ...fixture, response: { ...fixture.response, nextPageToken: "changed_0001" } }),
    code("response_binding_mismatch"),
  );
});

test("authority and receipt inspectors reject same-key-id material substitution", () => {
  const fixture = readFixture();
  const substitute = makeKeys();
  const receipt = makeReadReceipt({
    request: fixture.request,
    response: fixture.response,
    keys: substitute,
    authorityEnvelope: fixture.envelope,
  });
  assert.throws(
    () =>
      inspectRead({
        ...fixture,
        keys: substitute,
        receipt,
      }),
    code("receipt_pin_mismatch"),
  );
  const another = makeKeys();
  assert.throws(
    () =>
      inspectRead({
        ...fixture,
        keys: another,
        receipt: makeReadReceipt({
          request: fixture.request,
          response: fixture.response,
          keys: another,
          authorityEnvelope: fixture.envelope,
        }),
      }),
    code("receipt_pin_mismatch"),
  );
  const aliased = { ...fixture.keys, keyId: "google-broker-key-0002" };
  assert.throws(
    () =>
      inspectRead({
        ...fixture,
        keys: aliased,
        receipt: makeReadReceipt({
          request: fixture.request,
          response: fixture.response,
          keys: aliased,
          authorityEnvelope: fixture.envelope,
        }),
      }),
    code("receipt_pin_mismatch"),
  );
});

test("receipt schema independently rejects noncanonical lease and request nonces", () => {
  const fixture = readFixture();
  for (const [field, value, expected] of [
    ["leaseNonce", "short", "lease_nonce_invalid"],
    ["requestNonce", `${nonce(2)}=`, "request_nonce_invalid"],
    ["requestNonce", Buffer.alloc(31, 2).toString("base64url"), "request_nonce_invalid"],
  ]) {
    const receipt = makeReadReceipt({
      request: fixture.request,
      response: fixture.response,
      keys: fixture.keys,
      authorityEnvelope: fixture.envelope,
      overrides: { [field]: value },
    });
    assert.throws(() => inspectRead({ ...fixture, receipt }), code(expected));
  }
});

test("receipt schema rejects signed redirect and non-boolean redirect variants", () => {
  const fixture = readFixture();
  const redirected = makeReadReceipt({
    request: fixture.request,
    response: fixture.response,
    keys: fixture.keys,
    authorityEnvelope: fixture.envelope,
    overrides: { redirected: true },
  });
  assert.throws(() => inspectRead({ ...fixture, receipt: redirected }), code("provider_redirect_rejected"));
  for (const redirectedValue of ["false", 0]) {
    const receipt = makeReadReceipt({
      request: fixture.request,
      response: fixture.response,
      keys: fixture.keys,
      authorityEnvelope: fixture.envelope,
      overrides: { redirected: redirectedValue },
    });
    assert.throws(() => inspectRead({ ...fixture, receipt }), code("receipt_invalid"));
  }
});

test("receipt schema rejects raw token, authorization header, and provider URL fields", () => {
  const fixture = readFixture();
  for (const [field, value] of [
    ["accessToken", "secret"],
    ["headers", { authorization: "Bearer secret" }],
    ["url", "https://gmail.googleapis.com/gmail/v1/users/me/messages"],
  ]) {
    assert.throws(
      () => inspectRead({ ...fixture, receipt: { ...fixture.receipt, [field]: value } }),
      code("receipt_shape_invalid"),
    );
  }
});

test("receipt time accepts late completion but rejects three unauthorized receive times", () => {
  const fixture = readFixture();
  const lateCompletion = makeReadReceipt({
    request: fixture.request,
    response: fixture.response,
    keys: fixture.keys,
    authorityEnvelope: fixture.envelope,
    overrides: { serverCompletedAt: "2026-08-26T12:06:01.000Z" },
  });
  assert.equal(inspectRead({ ...fixture, receipt: lateCompletion }).usable, false);
  for (const serverReceivedAt of ["2026-08-26T12:01:29.999Z", clock.leaseExpires, "2026-08-26T12:06:00.001Z"]) {
    const receipt = makeReadReceipt({
      request: fixture.request,
      response: fixture.response,
      keys: fixture.keys,
      authorityEnvelope: fixture.envelope,
      overrides: { serverReceivedAt, serverCompletedAt: "2026-08-26T12:06:01.000Z" },
    });
    assert.throws(() => inspectRead({ ...fixture, receipt }), code("receipt_time_invalid"));
  }
});

test("signed receipts enforce requested Calendar, Gmail-list, and Gmail-get cardinality bindings", () => {
  const calendarEvents = [
    { id: "event_0001", start: { date: "2026-08-26" }, end: { date: "2026-08-27" } },
    { id: "event_0002", start: { date: "2026-08-27" }, end: { date: "2026-08-28" } },
  ];
  const calendar = readFixture({
    response: { items: calendarEvents },
    requestParameters: {
      timeMin: "2026-08-26T00:00:00.000Z",
      timeMax: "2026-08-27T00:00:00.000Z",
      maxResults: 1,
      singleEvents: true,
      orderBy: "startTime",
      pageToken: null,
    },
  });
  assert.throws(() => inspectRead(calendar), code("calendar_result_bounds_exceeded"));

  const gmail = readFixture({
    operation: "google.gmail.messages.list",
    response: {
      messages: [
        { id: "message_0001", threadId: "thread_0001" },
        { id: "message_0002", threadId: "thread_0002" },
      ],
    },
    requestParameters: { labelIds: ["INBOX"], maxResults: 1, includeSpamTrash: false, pageToken: null },
  });
  assert.throws(() => inspectRead(gmail), code("gmail_result_bounds_exceeded"));

  const listing = readFixture({
    operation: "google.gmail.messages.list",
    response: { messages: [{ id: "message_0001", threadId: "thread_0001" }] },
  });
  const listingInspection = inspectRead(listing);
  const request = makeRequest({
    operation: "google.gmail.messages.get",
    requestParameters: {
      messageId: "message_0001",
      format: "full",
      listingReceiptId: listingInspection.receipt.receiptId,
      listingRequestHash: listingInspection.receipt.requestHash,
      listingResponseHash: listingInspection.receipt.responseHash,
    },
  });
  const response = { id: "message_9999", threadId: "thread_0001", labelIds: ["INBOX"], payload: { headers: [] } };
  const receipt = makeReadReceipt({ request, response, keys: listing.keys, authorityEnvelope: listing.envelope });
  assert.throws(
    () => inspectRead({ ...listing, request, response, receipt, listing: listingInspection }),
    code("gmail_message_binding_mismatch"),
  );
});

test("Gmail get requires same-account signed listing and exact membership/linkage", () => {
  const listingResponse = { messages: [{ id: "message_0001", threadId: "thread_0001" }] };
  const listing = readFixture({ operation: "google.gmail.messages.list", response: listingResponse });
  const listingInspection = inspectRead(listing);
  const getResponse = {
    id: "message_0001",
    threadId: "thread_0001",
    labelIds: ["INBOX"],
    payload: { headers: [], mimeType: "text/plain", filename: "", body: { data: "QQ" } },
  };
  const linked = {
    messageId: "message_0001",
    format: "full",
    listingReceiptId: listingInspection.receipt.receiptId,
    listingRequestHash: listingInspection.receipt.requestHash,
    listingResponseHash: listingInspection.receipt.responseHash,
  };
  const request = makeRequest({ operation: "google.gmail.messages.get", requestParameters: linked });
  const receipt = makeReadReceipt({
    request,
    response: getResponse,
    keys: listing.keys,
    authorityEnvelope: listing.envelope,
  });
  assert.equal(
    inspectRead({ ...listing, request, response: getResponse, receipt, listing: listingInspection }).usable,
    false,
  );

  for (const change of [
    { listingReceiptId: "different_receipt_0001" },
    { listingRequestHash: "a".repeat(64) },
    { listingResponseHash: "b".repeat(64) },
  ]) {
    const changedRequest = makeRequest({
      operation: "google.gmail.messages.get",
      requestNonce: nonce(7),
      requestParameters: { ...linked, ...change },
    });
    const changedReceipt = makeReadReceipt({
      request: changedRequest,
      response: getResponse,
      keys: listing.keys,
      authorityEnvelope: listing.envelope,
    });
    assert.throws(
      () =>
        inspectRead({
          ...listing,
          request: changedRequest,
          response: getResponse,
          receipt: changedReceipt,
          listing: listingInspection,
        }),
      code("gmail_listing_membership_missing"),
    );
  }
});

test("Gmail get rejects missing membership and two independent wrong-account listings", () => {
  const keys = makeKeys();
  const envelope = makeAuthorityEnvelope({ keys });
  const authority = inspectAuthority({ keys, envelope });
  const missingResponse = { messages: [{ id: "message_other", threadId: "thread_other" }] };
  const listRequest = makeRequest({ operation: "google.gmail.messages.list" });
  const listReceipt = makeReadReceipt({
    request: listRequest,
    response: missingResponse,
    keys,
    authorityEnvelope: envelope,
  });
  const missingListing = inspectRead({
    keys,
    envelope,
    authority,
    request: listRequest,
    response: missingResponse,
    receipt: listReceipt,
  });
  const params = {
    messageId: "message_0001",
    format: "full",
    listingReceiptId: missingListing.receipt.receiptId,
    listingRequestHash: missingListing.receipt.requestHash,
    listingResponseHash: missingListing.receipt.responseHash,
  };
  const getRequest = makeRequest({ operation: "google.gmail.messages.get", requestParameters: params });
  const getResponse = { id: "message_0001", threadId: "thread_0001", labelIds: ["INBOX"], payload: { headers: [] } };
  const getReceipt = makeReadReceipt({ request: getRequest, response: getResponse, keys, authorityEnvelope: envelope });
  assert.throws(
    () =>
      inspectRead({
        keys,
        envelope,
        authority,
        request: getRequest,
        response: getResponse,
        receipt: getReceipt,
        listing: missingListing,
      }),
    code("gmail_listing_membership_missing"),
  );

  for (const accountMutation of [
    { mailbox: "other@example.com", providerAccountSubject: "google-subject-0002" },
    { accountType: "company", credentialId: "credential_0002" },
  ]) {
    const otherBinding = { ...binding, ...accountMutation, leaseNonce: nonce(8) };
    const otherGrant = makeGrant({ ...accountMutation });
    const otherLease = makeLease({ ...accountMutation, nonce: otherBinding.leaseNonce });
    const otherEnvelope = makeAuthorityEnvelope({ keys, grant: otherGrant, lease: otherLease });
    const otherAuthority = inspectAuthority({ keys, envelope: otherEnvelope });
    const otherRequest = makeRequest({ operation: "google.gmail.messages.list", requestBinding: otherBinding });
    const otherResponse = { messages: [{ id: "message_0001", threadId: "thread_0001" }] };
    const otherReceipt = makeReadReceipt({
      request: otherRequest,
      response: otherResponse,
      keys,
      authorityEnvelope: otherEnvelope,
    });
    const otherListing = inspectRead({
      keys,
      envelope: otherEnvelope,
      authority: otherAuthority,
      request: otherRequest,
      response: otherResponse,
      receipt: otherReceipt,
    });
    assert.throws(
      () =>
        inspectRead({
          keys,
          envelope,
          authority,
          request: getRequest,
          response: getResponse,
          receipt: getReceipt,
          listing: otherListing,
        }),
      code("gmail_listing_account_mismatch"),
    );
  }
});

test("Gmail get rejects SPAM, TRASH, and missing-INBOX label variants", () => {
  const listingResponse = { messages: [{ id: "message_0001", threadId: "thread_0001" }] };
  const listing = readFixture({ operation: "google.gmail.messages.list", response: listingResponse });
  const listingInspection = inspectRead(listing);
  const params = {
    messageId: "message_0001",
    format: "full",
    listingReceiptId: listingInspection.receipt.receiptId,
    listingRequestHash: listingInspection.receipt.requestHash,
    listingResponseHash: listingInspection.receipt.responseHash,
  };
  const request = makeRequest({ operation: "google.gmail.messages.get", requestParameters: params });
  for (const labelIds of [["INBOX", "SPAM"], ["INBOX", "TRASH"], ["IMPORTANT"]]) {
    const response = { id: "message_0001", threadId: "thread_0001", labelIds, payload: { headers: [] } };
    const receipt = makeReadReceipt({ request, response, keys: listing.keys, authorityEnvelope: listing.envelope });
    assert.throws(
      () => inspectRead({ ...listing, request, response, receipt, listing: listingInspection }),
      code("gmail_message_not_inbox"),
    );
  }
});

test("Gmail get rejects independently non-successful listing and get receipts", () => {
  const listingResponse = { messages: [{ id: "message_0001", threadId: "thread_0001" }] };
  const listing = readFixture({ operation: "google.gmail.messages.list", response: listingResponse });
  const failedListingReceipt = makeReadReceipt({
    request: listing.request,
    response: listingResponse,
    keys: listing.keys,
    authorityEnvelope: listing.envelope,
    overrides: { providerStatus: 503, outcome: "unavailable", outcomeReason: "provider.unavailable" },
  });
  const failedListing = inspectRead({ ...listing, receipt: failedListingReceipt });
  const successfulListing = inspectRead(listing);
  for (const [source, getFailure] of [
    [failedListing, false],
    [successfulListing, true],
  ]) {
    const request = makeRequest({
      operation: "google.gmail.messages.get",
      requestParameters: {
        messageId: "message_0001",
        format: "full",
        listingReceiptId: source.receipt.receiptId,
        listingRequestHash: source.receipt.requestHash,
        listingResponseHash: source.receipt.responseHash,
      },
    });
    const response = getFailure
      ? { error: "temporarily_unavailable" }
      : { id: "message_0001", threadId: "thread_0001", labelIds: ["INBOX"], payload: { headers: [] } };
    const receipt = makeReadReceipt({
      request,
      response,
      keys: listing.keys,
      authorityEnvelope: listing.envelope,
      overrides: getFailure
        ? { providerStatus: 503, outcome: "unavailable", outcomeReason: "provider.unavailable" }
        : {},
    });
    assert.throws(
      () => inspectRead({ ...listing, request, response, receipt, listing: source }),
      code("gmail_successful_inbox_receipts_required"),
    );
  }
});

test("untrusted projection inspection enforces three independent provider result bounds", () => {
  const events = Array.from({ length: 101 }, (_, index) => ({
    id: `event_${String(index).padStart(4, "0")}`,
    start: { date: "2026-08-26" },
    end: { date: "2026-08-27" },
  }));
  assert.throws(
    () => inspectUntrustedProjectionShape({ operation: "google.calendar.events.list", response: { items: events } }),
    code("calendar_result_bounds_exceeded"),
  );
  assert.throws(
    () =>
      inspectUntrustedProjectionShape({
        operation: "google.gmail.messages.list",
        response: {
          messages: Array.from({ length: 21 }, (_, index) => ({ id: `message_${index}`, threadId: `thread_${index}` })),
        },
      }),
    code("gmail_result_bounds_exceeded"),
  );
  assert.throws(
    () =>
      inspectUntrustedProjectionShape({
        operation: "google.calendar.events.list",
        response: { value: "x".repeat(262_145) },
      }),
    code("json_string_too_large"),
  );
});

test("provider secret, accessor, and proxy surfaces never enter an untrusted projection", () => {
  const preview = inspectUntrustedProjectionShape({
    operation: "google.calendar.events.list",
    response: calendarResponse,
  });
  assert.equal(preview.usable, false);
  assert.doesNotMatch(
    JSON.stringify(preview),
    /provider-secret|Bearer|calendar\.google\.com|accessToken|authorization|htmlLink/,
  );
  let getterCalls = 0;
  const accessor = { items: [] };
  Object.defineProperty(accessor, "token", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "secret";
    },
  });
  assert.throws(
    () => inspectUntrustedProjectionShape({ operation: "google.calendar.events.list", response: accessor }),
    code("json_object_invalid"),
  );
  assert.equal(getterCalls, 0);
  assert.throws(
    () =>
      inspectUntrustedProjectionShape({
        operation: "google.calendar.events.list",
        response: new Proxy({ items: [] }, {}),
      }),
    code("json_shape_invalid"),
  );
});
