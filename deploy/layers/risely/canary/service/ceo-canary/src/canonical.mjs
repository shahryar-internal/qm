import { createHash } from "node:crypto";
import { types } from "node:util";

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const MAX_DEPTH = 64;
const MAX_NODES = 100000;
const MAX_STRING_BYTES = 8 * 1024 * 1024;

function canonicalString(value, budget) {
  if (LONE_SURROGATE.test(value)) throw new TypeError("Canonical JSON does not support lone Unicode surrogates");
  budget.stringBytes += Buffer.byteLength(value, "utf8");
  if (budget.stringBytes > MAX_STRING_BYTES)
    throw new TypeError("Canonical JSON string content exceeds its size limit");
  return JSON.stringify(value);
}

function canonical(value, stack, depth, budget) {
  if (depth > MAX_DEPTH) throw new TypeError("Canonical JSON exceeds its depth limit");
  budget.nodes += 1;
  if (budget.nodes > MAX_NODES) throw new TypeError("Canonical JSON exceeds its node limit");
  if (value === null) return "null";
  if (typeof value === "string") return canonicalString(value, budget);
  if (typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON does not support non-finite numbers");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw new TypeError(`Canonical JSON does not support ${typeof value}`);
  if (types.isProxy(value)) throw new TypeError("Canonical JSON does not support proxies");
  if (stack.has(value)) throw new TypeError("Canonical JSON does not support cyclic values");
  stack.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype)
        throw new TypeError("Canonical JSON supports only plain arrays");
      if (Object.getOwnPropertySymbols(value).length) throw new TypeError("Canonical JSON does not support symbols");
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const length = descriptors.length?.value;
      if (!Number.isSafeInteger(length) || length < 0) throw new TypeError("Canonical JSON array length is invalid");
      const entries = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor) throw new TypeError("Canonical JSON does not support sparse arrays");
        if (descriptor.get || descriptor.set) throw new TypeError("Canonical JSON does not support accessors");
        if (!descriptor.enumerable) {
          throw new TypeError("Canonical JSON arrays support only enumerable data properties");
        }
        entries.push(canonical(descriptor.value, stack, depth + 1, budget));
      }
      const keys = Object.keys(descriptors).filter((key) => key !== "length");
      if (keys.length !== length || keys.some((key, index) => key !== String(index))) {
        throw new TypeError("Canonical JSON arrays cannot have named properties");
      }
      if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set)) {
        throw new TypeError("Canonical JSON does not support accessors");
      }
      return `[${entries.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Canonical JSON supports only plain objects");
    }
    if (Object.getOwnPropertySymbols(value).length) throw new TypeError("Canonical JSON does not support symbols");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.values(descriptors).some((descriptor) => !descriptor.enumerable || descriptor.get || descriptor.set)) {
      throw new TypeError("Canonical JSON supports only enumerable data properties");
    }
    return `{${Object.keys(descriptors)
      .sort()
      .map((key) => `${canonicalString(key, budget)}:${canonical(descriptors[key].value, stack, depth + 1, budget)}`)
      .join(",")}}`;
  } finally {
    stack.delete(value);
  }
}

export function canonicalJson(value) {
  return canonical(value, new Set(), 0, { nodes: 0, stringBytes: 0 });
}

export function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function sha256Canonical(value) {
  return sha256(canonicalJson(value));
}

export function canonicalSnapshot(value) {
  return JSON.parse(canonicalJson(value));
}
