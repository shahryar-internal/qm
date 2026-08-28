import { types } from "node:util";
import { OutboxEvent, PrincipalBinding, PublicationEnvelope } from "../shared-contracts/index.mjs";

const snapshot = PrincipalBinding.snapshot;
const hash = PrincipalBinding.hash;
const freeze = PrincipalBinding.freeze;
const storeInstances = new WeakSet();
const providerEffectNames = Object.freeze(["gmailDraftsCreate", "googleCalendarRead", "notionCreatePage", "slackPost"]);
const storeMethodNames = Object.freeze([
  "initialize",
  "enqueueValidated",
  "readValidated",
  "expireValidated",
  "readTombstone",
  "providerEffectStatus",
]);

function exact(value, fields, label) {
  const input = snapshot(value, label);
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some((field) => !fields.includes(field)) ||
    fields.some((field) => !Object.hasOwn(input, field))
  ) {
    throw new TypeError(`${label} has an unsupported shape`);
  }
  return input;
}

function instant(value, label) {
  if (typeof value !== "string" || new Date(value).toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical instant`);
  }
  return value;
}

function immutableRecord(event, envelope) {
  return freeze({
    schemaVersion: 6,
    eventId: event.eventId,
    eventSha256: event.eventSha256,
    envelopeSha256: envelope.envelopeSha256,
    evalReleaseSha256: event.evalRelease.releaseSha256,
    outboxEvent: event,
    publicationEnvelope: envelope,
    status: "pending",
    revision: 1,
    providerInvocationAllowed: false,
  });
}

function tombstoneFor(record, expiredAt) {
  const projection = {
    schemaVersion: 6,
    eventId: record.eventId,
    eventSha256: record.eventSha256,
    envelopeSha256: record.envelopeSha256,
    evalReleaseSha256: record.evalReleaseSha256,
    expiredAt,
    immutable: true,
  };
  return freeze({ ...projection, tombstoneSha256: hash(projection) });
}

function defaultProviderEffects() {
  return Object.freeze(
    Object.fromEntries(
      providerEffectNames.map((name) => [
        name,
        () => {
          throw new Error(`provider_effect_forbidden:${name}`);
        },
      ]),
    ),
  );
}

function bindProviderEffects(value) {
  if (value === undefined) return defaultProviderEffects();
  if (
    !value ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw new TypeError("Provider effect sentinels must be a plain exact port");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.keys(descriptors).length !== providerEffectNames.length ||
    providerEffectNames.some((name) => {
      const descriptor = descriptors[name];
      return (
        !descriptor ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value") ||
        typeof descriptor.value !== "function" ||
        types.isProxy(descriptor.value)
      );
    })
  ) {
    throw new TypeError("Provider effect sentinels must expose exact data methods");
  }
  return Object.freeze(Object.fromEntries(providerEffectNames.map((name) => [name, descriptors[name].value])));
}

export class ProviderFreeV6AcceptanceStore {
  #initialized = false;
  #records = new Map();
  #payloadOwners = new Map();
  #tombstones = new Map();
  #providerEffects;

  constructor(providerEffects) {
    this.#providerEffects = bindProviderEffects(providerEffects);
    storeInstances.add(this);
  }

  async initialize() {
    this.#initialized = true;
    return true;
  }

  async enqueueValidated(value, authorityNow) {
    if (!this.#initialized) throw new Error("acceptance_store_not_initialized");
    const input = exact(value, ["outboxEvent", "publicationEnvelope"], "Provider-free v6 enqueue");
    const event = OutboxEvent.validate(input.outboxEvent);
    const envelope = PublicationEnvelope.validate(input.publicationEnvelope, event);
    const now = instant(authorityNow, "Provider-free v6 authority time");
    if (Date.parse(now) < Date.parse(event.queuedAt)) throw new Error("authority_time_predates_queue");
    const tombstone = this.#tombstones.get(event.eventId);
    if (tombstone) {
      if (
        tombstone.eventSha256 !== event.eventSha256 ||
        tombstone.envelopeSha256 !== envelope.envelopeSha256 ||
        tombstone.evalReleaseSha256 !== event.evalRelease.releaseSha256
      ) {
        throw new Error("v6_event_identity_tombstone_conflict");
      }
      throw new Error("v6_event_identity_expired");
    }
    const existing = this.#records.get(event.eventId);
    if (existing) {
      if (
        existing.eventSha256 !== event.eventSha256 ||
        existing.envelopeSha256 !== envelope.envelopeSha256 ||
        existing.evalReleaseSha256 !== event.evalRelease.releaseSha256
      ) {
        throw new Error("outbox_conflict");
      }
      if (Date.parse(now) >= Date.parse(existing.outboxEvent.evalRelease.expiresAt)) {
        this.#expireStoredRecord(existing, now);
        throw new Error("evaluation_release_expired");
      }
      return freeze({ disposition: "replayed", record: existing });
    }
    if (Date.parse(now) >= Date.parse(event.evalRelease.expiresAt)) {
      throw new Error("evaluation_release_expired_unstored");
    }
    const payloadOwner = this.#payloadOwners.get(envelope.envelopeSha256);
    if (payloadOwner && payloadOwner !== event.eventId) throw new Error("outbox_payload_conflict");
    const record = immutableRecord(event, envelope);
    this.#records.set(event.eventId, record);
    this.#payloadOwners.set(envelope.envelopeSha256, event.eventId);
    return freeze({ disposition: "inserted", record });
  }

  async readValidated(eventId) {
    if (!this.#initialized) throw new Error("acceptance_store_not_initialized");
    return this.#records.get(eventId) ?? null;
  }

  async expireValidated(eventId, authorityNow) {
    if (!this.#initialized) throw new Error("acceptance_store_not_initialized");
    const now = instant(authorityNow, "Provider-free v6 expiry time");
    const existingTombstone = this.#tombstones.get(eventId);
    if (existingTombstone) return existingTombstone;
    const record = this.#records.get(eventId);
    if (!record) throw new Error("outbox_event_not_found");
    if (Date.parse(now) < Date.parse(record.outboxEvent.evalRelease.expiresAt)) {
      throw new Error("evaluation_release_not_expired");
    }
    return this.#expireStoredRecord(record, now);
  }

  async readTombstone(eventId) {
    if (!this.#initialized) throw new Error("acceptance_store_not_initialized");
    return this.#tombstones.get(eventId) ?? null;
  }

  async providerEffectStatus() {
    if (!this.#initialized) throw new Error("acceptance_store_not_initialized");
    return freeze({
      installedNames: Object.keys(this.#providerEffects).sort(),
      providerInvocationAllowed: false,
    });
  }

  #expireStoredRecord(record, now) {
    if (this.#records.get(record.eventId) !== record || this.#tombstones.has(record.eventId)) {
      throw new Error("v6_expiry_state_conflict");
    }
    const tombstone = tombstoneFor(record, now);
    this.#records.delete(record.eventId);
    this.#tombstones.set(record.eventId, tombstone);
    return tombstone;
  }
}

const fixedStoreMethods = Object.freeze(
  Object.fromEntries(
    storeMethodNames.map((name) => [
      name,
      Object.getOwnPropertyDescriptor(ProviderFreeV6AcceptanceStore.prototype, name).value,
    ]),
  ),
);

export function bindProviderFreeV6AcceptanceFacade(store) {
  if (!store || typeof store !== "object" || types.isProxy(store) || !storeInstances.has(store)) {
    throw new TypeError("Provider-free v6 acceptance facade requires its fixed acceptance store");
  }
  const prototype = Object.getPrototypeOf(store);
  if (
    types.isProxy(prototype) ||
    prototype !== ProviderFreeV6AcceptanceStore.prototype ||
    Object.getPrototypeOf(prototype) !== Object.prototype ||
    Object.getOwnPropertyNames(store).length !== 0 ||
    Object.getOwnPropertySymbols(store).length !== 0
  ) {
    throw new TypeError("Provider-free v6 acceptance facade requires its fixed acceptance store");
  }
  const descriptors = Object.getOwnPropertyDescriptors(prototype);
  const captured = Object.fromEntries(
    storeMethodNames.map((name) => {
      const descriptor = descriptors[name];
      if (
        !descriptor ||
        descriptor.get ||
        descriptor.set ||
        descriptor.value !== fixedStoreMethods[name] ||
        types.isProxy(descriptor.value)
      ) {
        throw new TypeError(`Provider-free v6 acceptance store requires a prototype data method ${name}`);
      }
      return [name, descriptor.value];
    }),
  );
  const invoke = (name, values = []) => Reflect.apply(captured[name], store, values);
  return Object.freeze({
    initialize() {
      return invoke("initialize");
    },
    async enqueuePublication(value, authorityNow) {
      const input = exact(value, ["outboxEvent", "publicationEnvelope"], "Canonical acceptance publication");
      const event = OutboxEvent.validate(input.outboxEvent);
      const envelope = PublicationEnvelope.validate(input.publicationEnvelope, event);
      return invoke("enqueueValidated", [{ outboxEvent: event, publicationEnvelope: envelope }, authorityNow]);
    },
    async readPublication(eventId) {
      return invoke("readValidated", [eventId]);
    },
    async expirePublication(eventId, authorityNow) {
      return invoke("expireValidated", [eventId, authorityNow]);
    },
    async readTombstone(eventId) {
      return invoke("readTombstone", [eventId]);
    },
    async providerEffectStatus() {
      return invoke("providerEffectStatus");
    },
  });
}
