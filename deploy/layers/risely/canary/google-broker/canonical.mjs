import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

export class GoogleBrokerContractError extends Error {
  constructor(code) {
    super(code);
    this.name = "GoogleBrokerContractError";
    this.code = code;
  }
}

const dataDescriptor = (descriptor) =>
  descriptor &&
  Object.hasOwn(descriptor, "value") &&
  !Object.hasOwn(descriptor, "get") &&
  !Object.hasOwn(descriptor, "set");

export const isProxyValue = (value) => {
  try {
    return utilTypes.isProxy(value);
  } catch {
    return true;
  }
};

const copy = (value, state, depth) => {
  if (depth > state.maxDepth) throw new GoogleBrokerContractError("json_depth_exceeded");
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    state.nodes += 1;
    if (state.nodes > state.maxNodes) throw new GoogleBrokerContractError("json_nodes_exceeded");
    if (typeof value === "string" && new TextEncoder().encode(value).byteLength > state.maxStringBytes) {
      throw new GoogleBrokerContractError("json_string_too_large");
    }
    return value;
  }
  if (typeof value === "number") {
    state.nodes += 1;
    if (state.nodes > state.maxNodes) throw new GoogleBrokerContractError("json_nodes_exceeded");
    if (!Number.isFinite(value)) throw new GoogleBrokerContractError("json_number_invalid");
    return value;
  }
  if (typeof value !== "object" || isProxyValue(value)) throw new GoogleBrokerContractError("json_shape_invalid");
  state.nodes += 1;
  if (state.nodes > state.maxNodes) throw new GoogleBrokerContractError("json_nodes_exceeded");
  let prototype;
  let descriptors;
  let symbols;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
    symbols = Object.getOwnPropertySymbols(value);
  } catch {
    throw new GoogleBrokerContractError("json_shape_invalid");
  }
  if (symbols.length !== 0) throw new GoogleBrokerContractError("json_shape_invalid");
  if (Array.isArray(value)) {
    if (prototype !== Array.prototype) throw new GoogleBrokerContractError("json_shape_invalid");
    const length = descriptors.length;
    if (
      !dataDescriptor(length) ||
      !Number.isSafeInteger(length.value) ||
      length.value < 0 ||
      length.value > state.maxArrayItems
    ) {
      throw new GoogleBrokerContractError("json_array_invalid");
    }
    const entries = Object.entries(descriptors).filter(([key]) => key !== "length");
    if (
      entries.length !== length.value ||
      entries.some(
        ([key, descriptor], index) => key !== String(index) || !dataDescriptor(descriptor) || !descriptor.enumerable,
      )
    ) {
      throw new GoogleBrokerContractError("json_array_invalid");
    }
    return Object.freeze(entries.map(([, descriptor]) => copy(descriptor.value, state, depth + 1)));
  }
  if (prototype !== Object.prototype && prototype !== null) throw new GoogleBrokerContractError("json_shape_invalid");
  const entries = Object.entries(descriptors);
  if (
    entries.length > state.maxObjectKeys ||
    entries.some(
      ([key, descriptor]) =>
        new TextEncoder().encode(key).byteLength > 256 || !dataDescriptor(descriptor) || !descriptor.enumerable,
    )
  ) {
    throw new GoogleBrokerContractError("json_object_invalid");
  }
  const result = Object.create(null);
  for (const [key, descriptor] of entries) result[key] = copy(descriptor.value, state, depth + 1);
  return Object.freeze(result);
};

const stringifyCanonical = (value) => {
  const stringify = (entry) => {
    if (entry === null || typeof entry === "string" || typeof entry === "boolean" || typeof entry === "number") {
      return JSON.stringify(entry);
    }
    if (Array.isArray(entry)) return `[${entry.map(stringify).join(",")}]`;
    return `{${Object.keys(entry)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stringify(entry[key])}`)
      .join(",")}}`;
  };
  return stringify(value);
};

export const snapshotJson = (
  value,
  limits = {
    maxDepth: 16,
    maxNodes: 4_000,
    maxStringBytes: 32_768,
    maxArrayItems: 1_000,
    maxObjectKeys: 1_000,
    maxBytes: 262_144,
  },
) => {
  const normalized = Object.freeze({
    maxDepth: limits.maxDepth,
    maxNodes: limits.maxNodes,
    maxStringBytes: limits.maxStringBytes,
    maxArrayItems: limits.maxArrayItems,
    maxObjectKeys: limits.maxObjectKeys,
    maxBytes: limits.maxBytes,
  });
  for (const value of Object.values(normalized)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new GoogleBrokerContractError("json_limits_invalid");
  }
  const state = { ...normalized, nodes: 0 };
  const result = copy(value, state, 0);
  if (new TextEncoder().encode(stringifyCanonical(result)).byteLength > normalized.maxBytes) {
    throw new GoogleBrokerContractError("json_bytes_exceeded");
  }
  return result;
};

export const canonicalJson = (value) => stringifyCanonical(snapshotJson(value));

export const canonicalBytes = (value) => new TextEncoder().encode(stringifyCanonical(snapshotJson(value)));

export const sha256 = (value) => createHash("sha256").update(canonicalBytes(value)).digest("hex");

export const exactRecord = (value, keys, code = "record_shape_invalid") => {
  const snapshot = snapshotJson(value);
  if (!snapshot || Array.isArray(snapshot) || typeof snapshot !== "object") throw new GoogleBrokerContractError(code);
  const actual = Object.keys(snapshot).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new GoogleBrokerContractError(code);
  }
  return snapshot;
};

export const boundedText = (value, label, maximumBytes, pattern) => {
  if (
    typeof value !== "string" ||
    !value ||
    new TextEncoder().encode(value).byteLength > maximumBytes ||
    /[\u0000-\u001f\u007f]/.test(value) ||
    (pattern && !pattern.test(value))
  ) {
    throw new GoogleBrokerContractError(`${label}_invalid`);
  }
  return value;
};

export const integer = (value, label, minimum, maximum) => {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new GoogleBrokerContractError(`${label}_invalid`);
  }
  return value;
};

export const timestamp = (value, label) => {
  boundedText(value, label, 24, /^(?:20|21)\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$/.exec(value);
  if (!match) throw new GoogleBrokerContractError(`${label}_invalid`);
  const [, year, month, day, hour, minute, second, fraction] = match;
  const epoch = Date.parse(value);
  const parsed = new Date(epoch);
  if (
    !Number.isFinite(epoch) ||
    parsed.getUTCFullYear() !== Number(year) ||
    parsed.getUTCMonth() + 1 !== Number(month) ||
    parsed.getUTCDate() !== Number(day) ||
    parsed.getUTCHours() !== Number(hour) ||
    parsed.getUTCMinutes() !== Number(minute) ||
    parsed.getUTCSeconds() !== Number(second) ||
    parsed.getUTCMilliseconds() !== Number(fraction)
  ) {
    throw new GoogleBrokerContractError(`${label}_invalid`);
  }
  return Object.freeze({ text: value, epoch });
};

export const nonce32 = (value, label) => {
  boundedText(value, label, 43, /^[A-Za-z0-9_-]{43}$/);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== 32 || decoded.toString("base64url") !== value) {
    throw new GoogleBrokerContractError(`${label}_invalid`);
  }
  return value;
};

export const sha256Text = (value, label) => boundedText(value, label, 64, /^[a-f0-9]{64}$/);
