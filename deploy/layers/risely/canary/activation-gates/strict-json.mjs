export class StrictJsonError extends Error {
  constructor(code) {
    super(code);
    this.name = "StrictJsonError";
    this.code = code;
  }
}

const whitespace = new Set([" ", "\t", "\n", "\r"]);

export function parseStrictJson(text, maximumBytes = 131_072) {
  if (typeof text !== "string") throw new StrictJsonError("manifest_json_not_text");
  if (new TextEncoder().encode(text).byteLength > maximumBytes) {
    throw new StrictJsonError("manifest_json_too_large");
  }
  let offset = 0;

  const fail = (code = "manifest_json_invalid") => {
    throw new StrictJsonError(code);
  };

  const skipWhitespace = () => {
    while (whitespace.has(text[offset])) offset += 1;
  };

  const parseString = () => {
    if (text[offset] !== '"') fail();
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch {
          fail();
        }
      }
      if (character === "\\") {
        offset += 1;
        const escape = text[offset];
        if (!['"', "\\", "/", "b", "f", "n", "r", "t", "u"].includes(escape)) fail();
        if (escape === "u") {
          const sequence = text.slice(offset + 1, offset + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(sequence)) fail();
          offset += 4;
        }
      } else if (character.charCodeAt(0) < 0x20) {
        fail();
      }
      offset += 1;
    }
    fail();
  };

  const parseNumber = () => {
    const match = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) fail();
    offset += match[0].length;
  };

  const parseLiteral = (literal) => {
    if (text.slice(offset, offset + literal.length) !== literal) fail();
    offset += literal.length;
  };

  const parseValue = () => {
    skipWhitespace();
    const character = text[offset];
    if (character === '"') {
      parseString();
      return;
    }
    if (character === "{") {
      parseObject();
      return;
    }
    if (character === "[") {
      parseArray();
      return;
    }
    if (character === "t") {
      parseLiteral("true");
      return;
    }
    if (character === "f") {
      parseLiteral("false");
      return;
    }
    if (character === "n") {
      parseLiteral("null");
      return;
    }
    parseNumber();
  };

  const parseObject = () => {
    const keys = new Set();
    offset += 1;
    skipWhitespace();
    if (text[offset] === "}") {
      offset += 1;
      return;
    }
    while (offset < text.length) {
      skipWhitespace();
      const key = parseString();
      if (keys.has(key)) fail("manifest_json_duplicate_key");
      keys.add(key);
      skipWhitespace();
      if (text[offset] !== ":") fail();
      offset += 1;
      parseValue();
      skipWhitespace();
      if (text[offset] === "}") {
        offset += 1;
        return;
      }
      if (text[offset] !== ",") fail();
      offset += 1;
    }
    fail();
  };

  const parseArray = () => {
    offset += 1;
    skipWhitespace();
    if (text[offset] === "]") {
      offset += 1;
      return;
    }
    while (offset < text.length) {
      parseValue();
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return;
      }
      if (text[offset] !== ",") fail();
      offset += 1;
    }
    fail();
  };

  parseValue();
  skipWhitespace();
  if (offset !== text.length) fail();
  try {
    return JSON.parse(text);
  } catch {
    fail();
  }
}
