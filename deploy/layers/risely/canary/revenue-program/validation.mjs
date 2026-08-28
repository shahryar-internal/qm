import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

const unsafeText = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/;
const loneSurrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const referencePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const hashPattern = /^[0-9a-f]{64}$/;
const datePattern = /^\d{4}-\d{2}-\d{2}$/;
const timeZonePattern = /^(?:UTC|[A-Za-z]+(?:_[A-Za-z]+)*(?:\/[A-Za-z]+(?:_[A-Za-z]+)*)+)$/;
const emailPattern =
  /^(?=.{1,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

export class RevenueProgramError extends Error {
  constructor(code) {
    super(code);
    this.name = "RevenueProgramError";
    this.code = code;
  }
}

export const fail = (code) => {
  throw new RevenueProgramError(`revenue_program_${code}`);
};

const dataDescriptor = (descriptor) =>
  descriptor &&
  Object.hasOwn(descriptor, "value") &&
  !Object.hasOwn(descriptor, "get") &&
  !Object.hasOwn(descriptor, "set");

const proxyValue = (value) => {
  try {
    return utilTypes.isProxy(value);
  } catch {
    return true;
  }
};

const snapshotValue = (value, state, depth) => {
  if (depth > 32 || state.nodes >= 30_000) fail("invalid_plain_json");
  state.nodes += 1;
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("invalid_plain_json");
    return value;
  }
  if (typeof value === "string") {
    if (loneSurrogate.test(value) || unsafeText.test(value)) fail("invalid_plain_json");
    state.bytes += Buffer.byteLength(value, "utf8");
    if (state.bytes > 2_097_152) fail("invalid_plain_json");
    return value;
  }
  if (typeof value !== "object" || proxyValue(value)) fail("invalid_plain_json");
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0)
        fail("invalid_plain_json");
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const length = descriptors.length;
      if (!dataDescriptor(length) || !Number.isSafeInteger(length.value) || length.value < 0 || length.value > 10_000)
        fail("invalid_plain_json");
      const entries = Object.entries(descriptors).filter(([key]) => key !== "length");
      if (
        entries.length !== length.value ||
        entries.some(
          ([key, descriptor], index) => key !== String(index) || !dataDescriptor(descriptor) || !descriptor.enumerable,
        )
      )
        fail("invalid_plain_json");
      return Object.freeze(entries.map(([, descriptor]) => snapshotValue(descriptor.value, state, depth + 1)));
    }
    if (
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.getOwnPropertySymbols(value).length !== 0
    )
      fail("invalid_plain_json");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const entries = Object.entries(descriptors);
    if (
      entries.length > 10_000 ||
      entries.some(([, descriptor]) => !dataDescriptor(descriptor) || !descriptor.enumerable)
    )
      fail("invalid_plain_json");
    const output = Object.create(null);
    for (const [key, descriptor] of entries) {
      if (!key || key.length > 256 || loneSurrogate.test(key) || unsafeText.test(key)) fail("invalid_plain_json");
      state.bytes += Buffer.byteLength(key, "utf8");
      if (state.bytes > 2_097_152) fail("invalid_plain_json");
      output[key] = snapshotValue(descriptor.value, state, depth + 1);
    }
    return Object.freeze(output);
  } catch (error) {
    if (error instanceof RevenueProgramError) throw error;
    fail("invalid_plain_json");
  }
};

export const snapshotPlainJson = (value) => snapshotValue(value, { nodes: 0, bytes: 0 }, 0);

const canonical = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string")
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value)
    .sort(compareCodepoints)
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
};

export const canonicalJson = (value) => canonical(snapshotPlainJson(value));

export const sha256Canonical = (value) => createHash("sha256").update(canonicalJson(value)).digest("hex");

export const compareCodepoints = (left, right) => {
  const leftPoints = Array.from(left);
  const rightPoints = Array.from(right);
  const limit = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < limit; index += 1) {
    const difference = leftPoints[index].codePointAt(0) - rightPoints[index].codePointAt(0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
};

export const assertExactKeys = (value, keys, code = "invalid_object") => {
  if (!value || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
  const actual = Object.keys(value).sort(compareCodepoints);
  const expected = [...keys].sort(compareCodepoints);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(code);
};

export const assertText = (value, maximum = 256, code = "invalid_text") => {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    loneSurrogate.test(value) ||
    unsafeText.test(value)
  )
    fail(code);
  return value;
};

export const assertSingleLineText = (value, maximum = 256, code = "invalid_text") => {
  const text = assertText(value, maximum, code);
  if (/[\r\n]/.test(text)) fail(code);
  return text;
};

export const assertReference = (value, code = "invalid_reference") => {
  const text = assertText(value, 256, code);
  if (!referencePattern.test(text)) fail(code);
  return text;
};

export const assertHash = (value, code = "invalid_hash") => {
  if (typeof value !== "string" || !hashPattern.test(value)) fail(code);
  return value;
};

export const assertEmail = (value, code = "invalid_email") => {
  if (typeof value !== "string") fail(code);
  const email = value.trim().toLowerCase();
  if (email !== value.toLowerCase() || !emailPattern.test(email)) fail(code);
  return email;
};

export const assertInteger = (value, minimum, maximum, code = "invalid_integer") => {
  if (!Number.isInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
};

export const assertInstant = (value, code = "invalid_timestamp") => {
  const text = assertText(value, 64, code);
  const instant = new Date(text);
  if (Number.isNaN(instant.valueOf()) || instant.toISOString() !== text) fail(code);
  return instant;
};

export const assertDate = (value, code = "invalid_date") => {
  const text = assertText(value, 10, code);
  if (!datePattern.test(text) || new Date(`${text}T00:00:00.000Z`).toISOString().slice(0, 10) !== text) fail(code);
  return text;
};

export const assertTimeZone = (value, code = "invalid_time_zone") => {
  const text = assertText(value, 128, code);
  if (!timeZonePattern.test(text)) fail(code);
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: text }).format(new Date(0));
  } catch {
    fail(code);
  }
  return text;
};

export const dateInTimeZone = (instant, timeZone) => {
  const values = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(instant);
  const part = (type) => values.find((value) => value.type === type)?.value;
  return `${part("year")}-${part("month")}-${part("day")}`;
};
