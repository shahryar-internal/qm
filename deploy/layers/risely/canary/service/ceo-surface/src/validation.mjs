import { canonicalJson, deepFreeze, sha256Canonical } from "../../../contracts/index.mjs";

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const hashPattern = /^[0-9a-f]{64}$/;
const emailPattern =
  /^(?=.{1,254}$)[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const slackTeamPattern = /^T[A-Z0-9]{8,31}$/;
const slackUserPattern = /^U[A-Z0-9]{8,31}$/;
const slackDirectMessagePattern = /^D[A-Z0-9]{8,31}$/;

export function snapshot(value, label) {
  try {
    return deepFreeze(JSON.parse(canonicalJson(value)));
  } catch (error) {
    throw new TypeError(
      `${label} must be canonical plain JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export function record(value, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return value;
}

export function exactKeys(value, allowed, required, label) {
  const input = record(value, label);
  if (Object.getOwnPropertySymbols(input).length) throw new TypeError(`${label} must not contain symbol properties`);
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Object.values(descriptors).some((descriptor) => !descriptor.enumerable || descriptor.get || descriptor.set))
    throw new TypeError(`${label} must contain only enumerable data properties`);
  for (const key of Object.keys(input))
    if (!allowed.includes(key)) throw new TypeError(`${label}.${key} is not supported`);
  for (const key of required) if (!Object.hasOwn(input, key)) throw new TypeError(`${label}.${key} is required`);
  return input;
}

export function text(value, label, maximum = 256) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || value !== value.trim()) {
    throw new TypeError(`${label} must be bounded canonical text`);
  }
  if (/[^\P{C}\t\n]/u.test(value) || /[\u202A-\u202E\u2066-\u2069]/u.test(value)) {
    throw new TypeError(`${label} contains unsafe control text`);
  }
  return value;
}

export function identifier(value, label) {
  const result = text(value, label);
  if (!identifierPattern.test(result)) throw new TypeError(`${label} must be an identifier`);
  return result;
}

export function hash(value, label) {
  if (typeof value !== "string" || !hashPattern.test(value))
    throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  return value;
}

export function email(value, label) {
  const result = text(value, label, 254);
  if (result !== result.toLowerCase() || !emailPattern.test(result))
    throw new TypeError(`${label} must be a canonical lowercase email address`);
  return result;
}

export function timestamp(value, label) {
  const result = text(value, label, 32);
  const parsed = Date.parse(result);
  if (!timestampPattern.test(result) || !Number.isFinite(parsed) || new Date(parsed).toISOString() !== result)
    throw new TypeError(`${label} must be a canonical UTC timestamp`);
  return result;
}

export function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new TypeError(`${label} must be a bounded integer`);
  return value;
}

export function boolean(value, label) {
  if (typeof value !== "boolean") throw new TypeError(`${label} must be boolean`);
  return value;
}

export function uniqueIdentifiers(value, label, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum)
    throw new TypeError(`${label} must be a bounded list`);
  const result = value.map((item, index) => identifier(item, `${label}[${index}]`));
  if (new Set(result).size !== result.length) throw new TypeError(`${label} must contain unique identifiers`);
  return Object.freeze(result);
}

function slackIdentifier(value, pattern, label) {
  const result = text(value, label, 32);
  if (!pattern.test(result)) throw new TypeError(`${label} must be a canonical Slack identifier`);
  return result;
}

export const slackTeamId = (value, label) => slackIdentifier(value, slackTeamPattern, label);
export const slackUserId = (value, label) => slackIdentifier(value, slackUserPattern, label);
export const slackDirectMessageId = (value, label) => slackIdentifier(value, slackDirectMessagePattern, label);
export { deepFreeze, sha256Canonical };
