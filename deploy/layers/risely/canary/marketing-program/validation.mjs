import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

const unsafe =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060\u2064-\u206F\uFE00-\uFE0F\uFEFF\uFFF0-\uFFF8]/;
const surrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const reference = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const hash = /^[0-9a-f]{64}$/;
const date = /^\d{4}-\d{2}-\d{2}$/;

export class MarketingProgramError extends Error {
  constructor(code) {
    super(`marketing_program_${code}`);
    this.name = "MarketingProgramError";
    this.code = code;
  }
}

export const fail = (code) => {
  throw new MarketingProgramError(code);
};

const data = (descriptor) =>
  descriptor &&
  Object.hasOwn(descriptor, "value") &&
  !Object.hasOwn(descriptor, "get") &&
  !Object.hasOwn(descriptor, "set");
const proxy = (value) => {
  try {
    return utilTypes.isProxy(value);
  } catch {
    return true;
  }
};
const copy = (value, state, depth) => {
  if (depth > 32 || state.nodes++ > 20_000) fail("invalid_plain_json");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("invalid_plain_json");
    return value;
  }
  if (typeof value === "string") {
    if (unsafe.test(value) || surrogate.test(value)) fail("invalid_plain_json");
    state.bytes += Buffer.byteLength(value);
    if (state.bytes > 1_000_000) fail("invalid_plain_json");
    return value;
  }
  if (!value || typeof value !== "object" || proxy(value)) fail("invalid_plain_json");
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.getOwnPropertySymbols(value).length) fail("invalid_plain_json");
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || !data(descriptors.length)) fail("invalid_plain_json");
      const entries = Object.entries(descriptors).filter(([key]) => key !== "length");
      if (
        entries.length !== descriptors.length.value ||
        entries.some(([key, item], index) => key !== String(index) || !data(item) || !item.enumerable)
      )
        fail("invalid_plain_json");
      return Object.freeze(entries.map(([, item]) => copy(item.value, state, depth + 1)));
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail("invalid_plain_json");
    const entries = Object.entries(descriptors);
    if (
      entries.length > 5_000 ||
      entries.some(
        ([key, item]) =>
          !key || key.length > 256 || unsafe.test(key) || surrogate.test(key) || !data(item) || !item.enumerable,
      )
    )
      fail("invalid_plain_json");
    const output = Object.create(null);
    for (const [key, item] of entries) output[key] = copy(item.value, state, depth + 1);
    return Object.freeze(output);
  } catch (error) {
    if (error instanceof MarketingProgramError) throw error;
    fail("invalid_plain_json");
  }
};

export const snapshotPlainJson = (value) => copy(value, { bytes: 0, nodes: 0 }, 0);
export const compareCodepoints = (left, right) => {
  const a = Array.from(left);
  const b = Array.from(right);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const difference = a[index].codePointAt(0) - b[index].codePointAt(0);
    if (difference) return difference;
  }
  return a.length - b.length;
};
export const canonicalJson = (value) => {
  const current = snapshotPlainJson(value);
  if (current === null || typeof current !== "object") return JSON.stringify(current);
  if (Array.isArray(current)) return `[${current.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(current)
    .sort(compareCodepoints)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(current[key])}`)
    .join(",")}}`;
};
export const sha256Canonical = (value) => createHash("sha256").update(canonicalJson(value)).digest("hex");
export const assertKeys = (value, expected, code = "invalid_object") => {
  if (!value || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
  const actual = Object.keys(value).sort(compareCodepoints);
  const keys = [...expected].sort(compareCodepoints);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) fail(code);
};
export const text = (value, maximum = 4_096, code = "invalid_text") => {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    unsafe.test(value) ||
    surrogate.test(value)
  )
    fail(code);
  return value;
};
export const singleLine = (value, maximum, code) => {
  const result = text(value, maximum, code);
  if (/[\r\n]/.test(result)) fail(code);
  return result;
};
export const ref = (value, code = "invalid_reference") => {
  const result = text(value, 256, code);
  if (!reference.test(result)) fail(code);
  return result;
};
export const digest = (value, code = "invalid_hash") => {
  if (typeof value !== "string" || !hash.test(value)) fail(code);
  return value;
};
export const instant = (value, code = "invalid_instant") => {
  const parsed = new Date(text(value, 64, code));
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value) fail(code);
  return parsed;
};
export const localDate = (value, code = "invalid_date") => {
  if (
    typeof value !== "string" ||
    !date.test(value) ||
    new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) !== value
  )
    fail(code);
  return value;
};
export const zoneDate = (value, zone) => {
  const values = new Intl.DateTimeFormat("en-CA", {
    timeZone: zone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(value);
  const get = (kind) => values.find((part) => part.type === kind)?.value;
  return `${get("year")}-${get("month")}-${get("day")}`;
};
export const addDays = (value, days) =>
  new Date(Date.parse(`${localDate(value)}T00:00:00.000Z`) + days * 86_400_000).toISOString().slice(0, 10);
