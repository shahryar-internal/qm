const maxSeedCharacters = 1000000;

const clone = (value) => structuredClone(value);

const boundedSeed = (seed) => {
  if (seed === null || typeof seed !== "object") return false;
  try {
    return JSON.stringify(seed).length <= maxSeedCharacters;
  } catch {
    return false;
  }
};

export const createReadOnlyReplay = (seed = {}) => {
  if (!boundedSeed(seed)) throw new TypeError("replay seed is invalid or too large");
  const reads = [];
  const deniedWrites = [];
  const data = clone(seed);
  const read = (name, value) => {
    reads.push(name);
    return clone(value);
  };
  const deny = (name) => {
    deniedWrites.push(name);
    throw new Error(`write denied in replay: ${name}`);
  };
  return Object.freeze({
    calendar: Object.freeze({ list: () => read("calendar.list", data.calendar ?? []) }),
    gmail: Object.freeze({ search: () => read("gmail.search", data.gmail ?? []), send: () => deny("gmail.send") }),
    notion: Object.freeze({
      get: () => read("notion.get", data.notion ?? {}),
      create: () => deny("notion.create"),
      update: () => deny("notion.update"),
      delete: () => deny("notion.delete"),
    }),
    slack: Object.freeze({
      history: () => read("slack.history", data.slack ?? []),
      post: () => deny("slack.post"),
      update: () => deny("slack.update"),
    }),
    commandCenter: Object.freeze({
      get: () => read("command-center.get", data.commandCenter ?? {}),
      mutate: () => deny("command-center.mutate"),
    }),
    get reads() {
      return Object.freeze([...reads]);
    },
    get deniedWrites() {
      return Object.freeze([...deniedWrites]);
    },
  });
};

export const replayFixture = async (fixture, executor) => {
  if (!fixture || typeof executor !== "function") throw new TypeError("fixture and executor are required");
  const adapters = createReadOnlyReplay(fixture.input);
  let output;
  let error;
  try {
    output = await executor(fixture, adapters);
  } catch (caught) {
    error = caught instanceof Error ? caught.message : String(caught);
  }
  return Object.freeze({
    fixtureId: fixture.id,
    output,
    error,
    reads: [...adapters.reads],
    deniedWrites: [...adapters.deniedWrites],
  });
};

export const replaySuite = async (fixtures, executor) => {
  if (!Array.isArray(fixtures)) throw new TypeError("fixtures must be an array");
  if (new Set(fixtures.map((fixture) => fixture?.id)).size !== fixtures.length)
    throw new TypeError("fixture ids must be unique");
  const results = [];
  for (const fixture of fixtures) results.push(await replayFixture(fixture, executor));
  return results;
};
