import { CanaryServiceError } from "./service.mjs";

const MAX_DEPTH = 48;
const MAX_NODES = 20000;

export function parseStrictJson(body) {
  let index = 0;
  let nodes = 0;

  function fail(code = "invalid_json", message = "Request body must contain valid JSON") {
    throw new CanaryServiceError(code, message);
  }

  function whitespace() {
    while (index < body.length && /[\t\n\r ]/.test(body[index])) index += 1;
  }

  function string() {
    const start = index;
    index += 1;
    let escaped = false;
    while (index < body.length) {
      const character = body[index];
      if (!escaped && character === '"') {
        index += 1;
        try {
          return JSON.parse(body.slice(start, index));
        } catch {
          fail();
        }
      }
      if (!escaped && character.charCodeAt(0) < 0x20) fail();
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      index += 1;
    }
    fail();
  }

  function value(depth) {
    if (depth > MAX_DEPTH) fail("json_complexity_exceeded", "Request JSON exceeds its complexity limit");
    nodes += 1;
    if (nodes > MAX_NODES) fail("json_complexity_exceeded", "Request JSON exceeds its complexity limit");
    whitespace();
    const character = body[index];
    if (character === '"') {
      string();
      return;
    }
    if (character === "{") {
      object(depth + 1);
      return;
    }
    if (character === "[") {
      array(depth + 1);
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (body.startsWith(literal, index)) {
        index += literal.length;
        return;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(body.slice(index));
    if (!number) fail();
    index += number[0].length;
  }

  function object(depth) {
    index += 1;
    whitespace();
    const keys = new Set();
    if (body[index] === "}") {
      index += 1;
      return;
    }
    while (index < body.length) {
      if (body[index] !== '"') fail();
      const key = string();
      if (keys.has(key)) fail("duplicate_json_key", "Request JSON contains a duplicate object key");
      keys.add(key);
      whitespace();
      if (body[index] !== ":") fail();
      index += 1;
      value(depth);
      whitespace();
      if (body[index] === "}") {
        index += 1;
        return;
      }
      if (body[index] !== ",") fail();
      index += 1;
      whitespace();
    }
    fail();
  }

  function array(depth) {
    index += 1;
    whitespace();
    if (body[index] === "]") {
      index += 1;
      return;
    }
    while (index < body.length) {
      value(depth);
      whitespace();
      if (body[index] === "]") {
        index += 1;
        return;
      }
      if (body[index] !== ",") fail();
      index += 1;
      whitespace();
    }
    fail();
  }

  whitespace();
  value(0);
  whitespace();
  if (index !== body.length) fail();
  try {
    return JSON.parse(body);
  } catch {
    fail();
  }
}
