import assert from "node:assert/strict";
import test from "node:test";
import * as broker from "../../canary/google-broker/index.mjs";
import {
  canonicalJson,
  createReadRequest,
  evaluateReadHistory,
  GoogleBrokerContractError,
  inspectUntrustedAuthorityRequest,
  snapshotJson,
  timestamp,
  validateGrantRequest,
  validateLeaseRequest,
  validateReadRequest,
} from "../../canary/google-broker/index.mjs";
import { binding, makeGrant, makeLease, makeRequest, nonce, parameters } from "./fixtures.mjs";

const code = (expected) => (error) => error instanceof GoogleBrokerContractError && error.code === expected;

test("canonicalization rejects three executable or inherited object variants", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 } }), '{"a":{"b":3,"y":2},"z":1}');
  let getterCalls = 0;
  const accessor = {};
  Object.defineProperty(accessor, "token", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "secret";
    },
  });
  assert.throws(() => snapshotJson(accessor), code("json_object_invalid"));
  assert.equal(getterCalls, 0);
  assert.throws(() => snapshotJson(new Proxy({ value: 1 }, {})), code("json_shape_invalid"));
  assert.throws(
    () => snapshotJson(Object.assign(Object.create({ inherited: true }), { own: true })),
    code("json_shape_invalid"),
  );
});

test("timestamps require exact milliseconds and reject malformed calendar values", () => {
  assert.equal(timestamp("2026-08-26T12:00:00.123Z", "time").epoch, Date.parse("2026-08-26T12:00:00.123Z"));
  for (const value of ["2026-08-26T12:00:00Z", "2026-08-26T12:00:00.123456Z", "2026-02-30T12:00:00.000Z"]) {
    assert.throws(() => timestamp(value, "time"), code("time_invalid"));
  }
});

test("lease and request nonces require canonical 32-byte base64url values", () => {
  assert.equal(validateLeaseRequest(makeLease()).nonce, nonce(1));
  for (const badNonce of ["short", `${nonce(1)}=`, Buffer.alloc(31, 1).toString("base64url")]) {
    assert.throws(() => validateLeaseRequest(makeLease({ nonce: badNonce })), code("lease_nonce_invalid"));
    assert.throws(() => makeRequest({ requestNonce: badNonce }), code("request_nonce_invalid"));
  }
});

test("raw grant and lease remain untrusted and cannot mint usable authority", () => {
  const request = makeRequest();
  const inspected = inspectUntrustedAuthorityRequest({ grant: makeGrant(), lease: makeLease(), request });
  assert.equal(inspected.usable, false);
  assert.equal(inspected.reason, "broker_signature_and_trusted_clock_required");
  assert.equal(broker.bindReadAuthority, undefined);
  assert.equal(broker.assertBoundReadAuthority, undefined);
  for (const field of ["now", "currentTime", "acceptedAt"]) {
    assert.throws(
      () =>
        inspectUntrustedAuthorityRequest({
          grant: { ...makeGrant(), [field]: "2026-08-26T12:02:00.000Z" },
          lease: makeLease(),
          request,
        }),
      code("grant_shape_invalid"),
    );
  }
});

test("request hash is stable across key order and fresh replay nonce", () => {
  const first = makeRequest();
  const second = makeRequest({
    requestBinding: Object.fromEntries(Object.entries(binding).reverse()),
    requestNonce: nonce(3),
  });
  assert.equal(first.requestHash, second.requestHash);
  assert.notEqual(first.requestNonce, second.requestNonce);
  assert.deepEqual(evaluateReadHistory(first, { usedRequestNonces: [], idempotency: null }), { decision: "fresh" });
  assert.deepEqual(evaluateReadHistory(first, { usedRequestNonces: [first.requestNonce], idempotency: null }), {
    decision: "replayed",
  });
  assert.deepEqual(
    evaluateReadHistory(second, {
      usedRequestNonces: [],
      idempotency: { key: first.idempotencyKey, requestHash: first.requestHash },
    }),
    { decision: "idempotent_retry" },
  );
});

test("replay history rejects malformed nonce and changed idempotency variants", () => {
  const request = makeRequest();
  for (const usedRequestNonces of [["short"], [`${nonce(2)}=`], [Buffer.alloc(33).toString("base64url")]]) {
    assert.throws(
      () => evaluateReadHistory(request, { usedRequestNonces, idempotency: null }),
      code("history_shape_invalid"),
    );
  }
  const changedBounds = makeRequest({
    requestNonce: nonce(4),
    requestParameters: { ...parameters.calendar, maxResults: 19 },
  });
  const changedWindow = makeRequest({
    requestNonce: nonce(5),
    requestParameters: { ...parameters.calendar, timeMax: "2026-08-27T00:00:01.000Z" },
  });
  for (const changed of [changedBounds, changedWindow]) {
    assert.deepEqual(
      evaluateReadHistory(changed, {
        usedRequestNonces: [],
        idempotency: { key: request.idempotencyKey, requestHash: request.requestHash },
      }),
      { decision: "changed_hash" },
    );
  }
});

test("request surface independently rejects secret and transport controls", () => {
  const request = makeRequest();
  for (const [field, value] of [
    ["accessToken", "secret"],
    ["refreshToken", "secret"],
    ["headers", { authorization: "Bearer secret" }],
    ["url", "https://evil.example/"],
    ["method", "GET"],
    ["redirect", "follow"],
  ]) {
    assert.throws(() => validateReadRequest({ ...request, [field]: value }), code("request_shape_invalid"));
  }
});

test("unsupported operations and independent Calendar bounds fail closed", () => {
  for (const operation of ["google.drive.files.list", "google.gmail.messages.send", "google.calendar.events.insert"]) {
    assert.throws(
      () =>
        createReadRequest({
          version: 1,
          operation,
          binding,
          parameters: {},
          requestNonce: nonce(6),
          idempotencyKey: "idempotency_0006",
        }),
      code("operation_unsupported"),
    );
  }
  assert.throws(
    () => makeRequest({ requestParameters: { ...parameters.calendar, maxResults: 101 } }),
    code("calendar_max_results_invalid"),
  );
  assert.throws(
    () => makeRequest({ requestParameters: { ...parameters.calendar, timeMax: "2026-09-27T00:00:00.000Z" } }),
    code("calendar_window_invalid"),
  );
  assert.throws(
    () => makeRequest({ requestParameters: { ...parameters.calendar, singleEvents: false } }),
    code("calendar_parameters_invalid"),
  );
});

test("two-account, credential-version, and job mutations fail raw binding inspection", () => {
  const request = makeRequest();
  for (const mutation of [
    { mailbox: "other@example.com" },
    { providerAccountSubject: "google-subject-0002" },
    { credentialVersion: 8 },
    { deploymentId: "deployment:other-0001" },
    { jobClass: "other_job_class" },
    { leaseNonce: nonce(9) },
  ]) {
    const requestBinding = { ...binding, ...mutation };
    assert.throws(
      () =>
        inspectUntrustedAuthorityRequest({
          grant: makeGrant(),
          lease: makeLease(),
          request: makeRequest({ requestBinding }),
        }),
      (error) => error instanceof GoogleBrokerContractError,
    );
  }
});

test("31-day grants and five-minute leases enforce exact boundaries", () => {
  assert.doesNotThrow(() =>
    inspectUntrustedAuthorityRequest({ grant: makeGrant(), lease: makeLease(), request: makeRequest() }),
  );
  assert.throws(
    () => validateLeaseRequest(makeLease({ expiresAt: "2026-08-26T12:06:00.001Z" })),
    code("lease_expiry_invalid"),
  );
  assert.throws(
    () => validateLeaseRequest(makeLease({ issuedAt: "2026-08-26T12:06:00.000Z" })),
    code("lease_expiry_invalid"),
  );
  assert.throws(
    () =>
      inspectUntrustedAuthorityRequest({
        grant: makeGrant({ expiresAt: "2026-08-26T12:05:59.999Z" }),
        lease: makeLease(),
        request: makeRequest(),
      }),
    code("authority_binding_mismatch"),
  );
  assert.doesNotThrow(() =>
    validateGrantRequest(makeGrant({ issuedAt: "2026-08-01T00:00:00.000Z", expiresAt: "2026-09-01T00:00:00.000Z" })),
  );
  for (const expiresAt of ["2026-09-01T00:00:00.001Z", "2026-08-01T00:00:00.000Z"]) {
    assert.throws(
      () => validateGrantRequest(makeGrant({ issuedAt: "2026-08-01T00:00:00.000Z", expiresAt })),
      code("grant_expiry_invalid"),
    );
  }
});
