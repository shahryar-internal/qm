import { createHash } from "node:crypto";
import { types } from "node:util";

const forbiddenKeys = new Set(["__proto__", "constructor", "prototype"]);
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const digestPattern = /^[a-f0-9]{64}$/u;
const emailPattern =
  /^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/u;
const unsafeText = /[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}\ud800-\udfff]/u;

function clonePlain(value, label, stack) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${label} must contain finite JSON values`);
    return value;
  }
  if (!value || typeof value !== "object" || types.isProxy(value)) throw new TypeError(`${label} must be plain data`);
  if (stack.has(value)) throw new TypeError(`${label} must not contain cycles`);
  const array = Array.isArray(value);
  if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype)) {
    throw new TypeError(`${label} must be plain data`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new TypeError(`${label} must not contain symbols`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.getOwnPropertyNames(value);
  if (names.some((name) => forbiddenKeys.has(name))) throw new TypeError(`${label} contains a forbidden key`);
  if (array) {
    if (
      names.some((name) => name !== "length" && !/^(?:0|[1-9]\d*)$/u.test(name)) ||
      !Object.hasOwn(descriptors, "length") ||
      descriptors.length.enumerable ||
      !Object.hasOwn(descriptors.length, "value") ||
      names.length !== value.length + 1
    ) {
      throw new TypeError(`${label} must be a dense plain list`);
    }
  } else if (names.some((name) => !descriptors[name].enumerable)) {
    throw new TypeError(`${label} must not contain hidden fields`);
  }
  for (const name of names) {
    if (name === "length") continue;
    const descriptor = descriptors[name];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new TypeError(`${label}.${name} must be a plain data field`);
    }
  }
  stack.add(value);
  try {
    if (array) return names.slice(0, -1).map((name) => clonePlain(descriptors[name].value, `${label}.${name}`, stack));
    return Object.fromEntries(
      names.map((name) => [name, clonePlain(descriptors[name].value, `${label}.${name}`, stack)]),
    );
  } finally {
    stack.delete(value);
  }
}

export function snapshotPlainData(value, label = "value") {
  return clonePlain(value, label, new Set());
}

function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

export function canonicalJson(value) {
  return canonical(snapshotPlainData(value));
}

export function sha256Canonical(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const entry of Object.values(value)) deepFreeze(entry);
  return Object.freeze(value);
}

export function exactRecord(value, allowed, required, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} must be a plain record`);
  }
  for (const key of Object.keys(value))
    if (!allowed.includes(key)) throw new TypeError(`${label}.${key} is not supported`);
  for (const key of required) if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
  return value;
}

export function identifier(value, label) {
  if (typeof value !== "string" || !identifierPattern.test(value))
    throw new TypeError(`${label} must be an identifier`);
  return value;
}

export function digest(value, label) {
  if (typeof value !== "string" || !digestPattern.test(value)) throw new TypeError(`${label} must be a SHA-256 digest`);
  return value;
}

export function email(value, label) {
  if (typeof value !== "string" || value !== value.toLowerCase() || !emailPattern.test(value)) {
    throw new TypeError(`${label} must be a lowercase email address`);
  }
  return value;
}

export function instant(value, label) {
  if (typeof value !== "string") throw new TypeError(`${label} must be a canonical instant`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value)
    throw new TypeError(`${label} must be a canonical instant`);
  return value;
}

export function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum)
    throw new TypeError(`${label} must be an integer of at least ${minimum}`);
  return value;
}

export function plainText(value, label, maximum) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > maximum ||
    value !== value.normalize("NFKC") ||
    unsafeText.test(value)
  ) {
    throw new TypeError(`${label} must be normalized plain text`);
  }
  return value;
}

export function sortedUnique(values, label, normalize, minimum = 0, maximum = 256) {
  if (!Array.isArray(values) || values.length < minimum || values.length > maximum) {
    throw new TypeError(`${label} must contain between ${minimum} and ${maximum} items`);
  }
  const result = values.map((entry, index) => normalize(entry, `${label}[${index}]`)).sort();
  if (new Set(result).size !== result.length) throw new TypeError(`${label} must not contain duplicates`);
  return Object.freeze(result);
}
