import { isProxy } from "node:util/types";

const dangerousKey = "__proto__";

export class MercuryInvoicingError extends Error {
  constructor(code) {
    super(code);
    this.name = "MercuryInvoicingError";
    this.code = code;
  }
}

export const fail = (code) => {
  throw new MercuryInvoicingError(code);
};

export const snapshotPlainJson = (value) => {
  const seen = new Set();
  const visit = (current) => {
    if (current === null || typeof current === "string" || typeof current === "boolean") return current;
    if (typeof current === "number") {
      if (!Number.isFinite(current)) fail("invalid_number");
      return current;
    }
    if (typeof current !== "object") fail("invalid_json_value");
    if (seen.has(current)) fail("cyclic_input");
    if (isProxy(current)) fail("proxy_input");
    const prototype = Object.getPrototypeOf(current);
    if (prototype !== Object.prototype && prototype !== Array.prototype) fail("invalid_prototype");
    seen.add(current);
    if (Array.isArray(current)) {
      const descriptors = Object.getOwnPropertyDescriptors(current);
      const keys = Reflect.ownKeys(descriptors);
      if (
        keys.some((key) => typeof key !== "string") ||
        keys.some((key) => key !== "length" && !/^(0|[1-9][0-9]*)$/u.test(key)) ||
        descriptors.length.value !== current.length
      ) {
        fail("invalid_array");
      }
      const result = [];
      for (let index = 0; index < current.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) fail("invalid_array");
        result.push(visit(descriptor.value));
      }
      seen.delete(current);
      return result;
    }
    const result = {};
    for (const key of Reflect.ownKeys(current)) {
      if (typeof key !== "string" || key === dangerousKey) fail("invalid_object_key");
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) fail("invalid_object_descriptor");
      Object.defineProperty(result, key, {
        value: visit(descriptor.value),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    seen.delete(current);
    return result;
  };
  return visit(value);
};

export const exact = (value, fields, code) => {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  ) {
    fail(code);
  }
  return value;
};

export const identifier = (value, code, maximum = 255) => {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.test(value)
  ) {
    fail(code);
  }
  return value;
};

export const text = (value, code, maximum) => {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    fail(code);
  }
  return value;
};

export const date = (value, code) => {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) fail(code);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) fail(code);
  return value;
};

export const instant = (value, code) => {
  if (typeof value !== "string") fail(code);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value) fail(code);
  return value;
};

export const email = (value, code) => {
  if (
    typeof value !== "string" ||
    value !== value.toLowerCase() ||
    value.length > 254 ||
    !/^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/u.test(
      value,
    )
  ) {
    fail(code);
  }
  return value;
};
