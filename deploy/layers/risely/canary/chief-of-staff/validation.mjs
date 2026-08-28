import { types as utilTypes } from "node:util";

const hashPattern = /^[0-9a-f]{64}$/;
const refPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const emailPattern =
  /^(?=.{1,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const unsafeControlText = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
const defaultIgnorableText = /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Bidi_Control}]/u;
const unsafeText = Object.freeze({
  test(value) {
    return unsafeControlText.test(value) || defaultIgnorableText.test(value);
  },
});
const unsafeMailText = /[\r\n\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/;

export class ChiefOfStaffContractError extends TypeError {
  constructor(code) {
    super(`chief_of_staff_${code}`);
    this.name = "ChiefOfStaffContractError";
    this.code = code;
  }
}

export const fail = (code) => {
  throw new ChiefOfStaffContractError(code);
};

const isDataDescriptor = (descriptor) =>
  descriptor !== undefined &&
  Object.hasOwn(descriptor, "value") &&
  !Object.hasOwn(descriptor, "get") &&
  !Object.hasOwn(descriptor, "set") &&
  descriptor.enumerable === true;

const clonePlain = (value, state, depth) => {
  if (depth > 32 || state.nodes >= 20_000) fail("invalid_plain_json");
  state.nodes += 1;
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (
      unsafeText.test(value) ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)
    ) {
      fail("invalid_plain_json");
    }
    state.bytes += Buffer.byteLength(value, "utf8");
    if (state.bytes > 1_048_576) fail("invalid_plain_json");
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("invalid_plain_json");
    return value;
  }
  if (typeof value !== "object" || utilTypes.isProxy(value)) fail("invalid_plain_json");
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0) {
      fail("invalid_plain_json");
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const length = descriptors.length;
    if (!length || !Object.hasOwn(length, "value") || !Number.isSafeInteger(length.value) || length.value > 2_000) {
      fail("invalid_plain_json");
    }
    const entries = Object.entries(descriptors).filter(([key]) => key !== "length");
    if (
      entries.length !== length.value ||
      entries.some(([key, descriptor], index) => key !== String(index) || !isDataDescriptor(descriptor))
    ) {
      fail("invalid_plain_json");
    }
    return Object.freeze(entries.map(([, descriptor]) => clonePlain(descriptor.value, state, depth + 1)));
  }
  if (
    ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    fail("invalid_plain_json");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).length > 2_000) fail("invalid_plain_json");
  const result = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!isDataDescriptor(descriptor) || key.length > 256) fail("invalid_plain_json");
    result[key] = clonePlain(descriptor.value, state, depth + 1);
  }
  return Object.freeze(result);
};

export const snapshotPlainJson = (value) => clonePlain(value, { nodes: 0, bytes: 0 }, 0);

export const assertRecord = (value, keys, code = "invalid_object") => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(code);
  return value;
};

export const assertOptionalRecord = (value, required, optional, code = "invalid_object") => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code);
  const actual = Object.keys(value);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    actual.some((key) => !required.includes(key) && !optional.includes(key))
  ) {
    fail(code);
  }
  return value;
};

export const assertText = (value, maximum = 512, minimum = 1) => {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || unsafeText.test(value)) {
    fail("invalid_text");
  }
  return value;
};

export const assertMailHeader = (value, maximum = 998) => {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || unsafeMailText.test(value)) {
    fail("invalid_mail_header");
  }
  return value;
};

export const assertHash = (value) => {
  if (typeof value !== "string" || !hashPattern.test(value)) fail("invalid_hash");
  return value;
};

export const assertRef = (value) => {
  if (typeof value !== "string" || !refPattern.test(value)) fail("invalid_reference");
  return value;
};

export const assertEmail = (value) => {
  if (typeof value !== "string" || !emailPattern.test(value)) fail("invalid_email");
  return value.toLowerCase();
};

export const parseInstant = (value) => {
  if (typeof value !== "string" || value.length > 64) fail("invalid_timestamp");
  const date = new Date(value);
  if (Number.isNaN(date.valueOf()) || date.toISOString() !== value) fail("invalid_timestamp");
  return date;
};

export const assertInteger = (value, minimum, maximum) => {
  if (!Number.isInteger(value) || value < minimum || value > maximum) fail("invalid_integer");
  return value;
};

export const compareCodepoints = (left, right) => {
  const leftPoints = Array.from(left);
  const rightPoints = Array.from(right);
  const limit = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < limit; index += 1) {
    const difference = leftPoints[index].codePointAt(0) - rightPoints[index].codePointAt(0);
    if (difference !== 0) return difference < 0 ? -1 : 1;
  }
  return leftPoints.length - rightPoints.length;
};

export const assertUnique = (values, key, code = "duplicate_record") => {
  const seen = new Set();
  for (const value of values) {
    const identity = key(value);
    if (seen.has(identity)) fail(code);
    seen.add(identity);
  }
  return values;
};
