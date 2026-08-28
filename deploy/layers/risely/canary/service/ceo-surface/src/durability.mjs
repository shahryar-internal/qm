import { types } from "node:util";
import { durableOutboxMethods, durableReceiptMethods } from "./constants.mjs";
import { exactKeys, hash, sha256Canonical, snapshot } from "./validation.mjs";

export function deliveryReceiptHash(value) {
  const payload = { ...snapshot(value, "deliveryReceipt") };
  delete payload.receiptSha256;
  return sha256Canonical(payload);
}

function rejectProxy(value, label) {
  if (types.isProxy(value)) throw new TypeError(`${label} must not be a Proxy`);
}

function capturedMethods(input, names, label) {
  return Object.fromEntries(
    names.map((name) => {
      const method = input[name];
      if (typeof method !== "function") throw new TypeError(`${label}.${name} must be a function`);
      rejectProxy(method, `${label}.${name}`);
      const captured = (...args) => Reflect.apply(method, undefined, args);
      return [name, Object.freeze(captured)];
    }),
  );
}

export function assertDurableOutboxAdapter(value, deploymentBindingSha256) {
  rejectProxy(value, "outboxAdapter");
  const allowed = [
    "contractType",
    "contractVersion",
    "durability",
    "atomicClaims",
    "deploymentBindingSha256",
    ...durableOutboxMethods,
  ];
  const input = exactKeys(value, allowed, allowed, "outboxAdapter");
  if (
    input.contractType !== "ceo-surface-outbox-adapter" ||
    input.contractVersion !== 1 ||
    input.durability !== "postgres" ||
    input.atomicClaims !== true
  ) {
    throw new TypeError("outboxAdapter does not satisfy the durable contract");
  }
  const expectedBinding = hash(deploymentBindingSha256, "deploymentBindingSha256");
  const adapterBinding = hash(input.deploymentBindingSha256, "outboxAdapter.deploymentBindingSha256");
  if (adapterBinding !== expectedBinding) throw new TypeError("outboxAdapter deployment binding does not match");
  return Object.freeze({
    contractType: "ceo-surface-outbox-adapter",
    contractVersion: 1,
    durability: "postgres",
    atomicClaims: true,
    deploymentBindingSha256: adapterBinding,
    ...capturedMethods(input, durableOutboxMethods, "outboxAdapter"),
  });
}

export function assertDurableReceiptStoreAdapter(value, deploymentBindingSha256) {
  rejectProxy(value, "receiptStoreAdapter");
  const allowed = [
    "contractType",
    "contractVersion",
    "durability",
    "atomicReservations",
    "deploymentBindingSha256",
    ...durableReceiptMethods,
  ];
  const input = exactKeys(value, allowed, allowed, "receiptStoreAdapter");
  if (
    input.contractType !== "ceo-surface-receipt-store-adapter" ||
    input.contractVersion !== 1 ||
    input.durability !== "postgres" ||
    input.atomicReservations !== true
  ) {
    throw new TypeError("receiptStoreAdapter does not satisfy the durable contract");
  }
  const expectedBinding = hash(deploymentBindingSha256, "deploymentBindingSha256");
  const adapterBinding = hash(input.deploymentBindingSha256, "receiptStoreAdapter.deploymentBindingSha256");
  if (adapterBinding !== expectedBinding) throw new TypeError("receiptStoreAdapter deployment binding does not match");
  return Object.freeze({
    contractType: "ceo-surface-receipt-store-adapter",
    contractVersion: 1,
    durability: "postgres",
    atomicReservations: true,
    deploymentBindingSha256: adapterBinding,
    ...capturedMethods(input, durableReceiptMethods, "receiptStoreAdapter"),
  });
}

export function validateDeliveryReceipt() {
  throw new TypeError("live receipt authority is unavailable in the inert shadow compiler");
}
