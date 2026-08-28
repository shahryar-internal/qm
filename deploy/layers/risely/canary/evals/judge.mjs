export const judgeRubricVersion = "2026-08-26.v1";

const categories = Object.freeze(["accuracy", "grounding", "safety", "voice", "usefulness"]);
const fields = Object.freeze([
  "runId",
  "caseId",
  "judgeId",
  "rubricVersion",
  "scores",
  "pass",
  "rationale",
  "failures",
  "evidence",
  "generatedAt",
]);
const maxIdLength = 160;
const maxRationaleLength = 4000;
const maxArrayItems = 100;
const unsafeControls = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/u;

const isRecord = (value) =>
  Boolean(value) &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const isBoundedString = (value, maximum) =>
  typeof value === "string" && value.length > 0 && value.length <= maximum && !unsafeControls.test(value);

const parseTimestamp = (value) => {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return NaN;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : NaN;
};

export const validateJudgeResult = (value, options = {}) => {
  const errors = [];
  if (!isRecord(value)) return { valid: false, errors: ["result must be a plain object"] };
  if (Object.keys(value).some((field) => !fields.includes(field))) errors.push("unknown result field");
  for (const field of ["runId", "caseId", "judgeId", "rubricVersion"])
    if (!isBoundedString(value[field], maxIdLength)) errors.push(`invalid ${field}`);
  if (!isBoundedString(value.rationale, maxRationaleLength)) errors.push("invalid rationale");
  const generatedAt = parseTimestamp(value.generatedAt);
  if (!Number.isFinite(generatedAt)) errors.push("invalid generatedAt");
  if (options.runId !== undefined && value.runId !== options.runId) errors.push("runId mismatch");
  if (options.caseId !== undefined && value.caseId !== options.caseId) errors.push("caseId mismatch");
  if (options.rubricVersion !== undefined && value.rubricVersion !== options.rubricVersion)
    errors.push("rubricVersion mismatch");
  if (Number.isFinite(generatedAt) && Number.isFinite(options.now)) {
    if (generatedAt > options.now + (options.maxFutureMs ?? 300000)) errors.push("generatedAt is in the future");
    if (options.maxAgeMs !== undefined && generatedAt < options.now - options.maxAgeMs)
      errors.push("generatedAt is too old");
  }
  if (!isRecord(value.scores)) errors.push("missing scores");
  else {
    for (const category of categories)
      if (!Number.isInteger(value.scores[category]) || value.scores[category] < 1 || value.scores[category] > 5)
        errors.push(`invalid score ${category}`);
    if (Object.keys(value.scores).some((key) => !categories.includes(key))) errors.push("unknown score category");
  }
  if (typeof value.pass !== "boolean") errors.push("missing pass");
  if (
    !Array.isArray(value.failures) ||
    value.failures.length > maxArrayItems ||
    value.failures.some((item) => !isBoundedString(item, maxRationaleLength))
  )
    errors.push("failures must be bounded strings");
  if (
    !Array.isArray(value.evidence) ||
    value.evidence.length > maxArrayItems ||
    value.evidence.some((item) => !isBoundedString(item, maxIdLength))
  )
    errors.push("evidence must be bounded strings");
  if (Array.isArray(value.failures) && value.pass && value.failures.length > 0)
    errors.push("passing result has failures");
  if (Array.isArray(value.evidence) && value.pass && value.evidence.length === 0)
    errors.push("passing result has no evidence");
  return { valid: errors.length === 0, errors };
};

export const createJudgeResult = ({
  runId,
  caseId,
  judgeId,
  scores,
  pass,
  rationale,
  failures = [],
  evidence = [],
  generatedAt = new Date().toISOString(),
  rubricVersion = judgeRubricVersion,
}) => {
  const result = Object.freeze({
    runId,
    caseId,
    judgeId,
    rubricVersion,
    scores: Object.freeze({ ...scores }),
    pass: Boolean(pass),
    rationale,
    failures: Object.freeze([...failures]),
    evidence: Object.freeze([...evidence]),
    generatedAt,
  });
  const validation = validateJudgeResult(result);
  if (!validation.valid) throw new TypeError(validation.errors.join(", "));
  return result;
};

export const judgeAgreement = (results, minimumJudgesOrOptions = 2) => {
  const options =
    typeof minimumJudgesOrOptions === "number"
      ? { minimumJudges: minimumJudgesOrOptions }
      : (minimumJudgesOrOptions ?? {});
  const minimumJudges = options.minimumJudges ?? 2;
  if (
    !Number.isInteger(minimumJudges) ||
    minimumJudges < 2 ||
    !Array.isArray(results) ||
    results.length < minimumJudges ||
    results.length > 10
  )
    return { pass: false, reason: "insufficient independent judges", spread: Infinity };
  const first = results[0];
  const context = {
    runId: options.runId ?? first?.runId,
    caseId: options.caseId ?? first?.caseId,
    rubricVersion: options.rubricVersion ?? first?.rubricVersion,
    now: options.now,
    maxAgeMs: options.maxAgeMs,
    maxFutureMs: options.maxFutureMs,
  };
  const invalid = results.find((item) => !validateJudgeResult(item, context).valid);
  if (invalid) return { pass: false, reason: "invalid judge result", spread: Infinity };
  const judgeIds = results.map((item) => item.judgeId);
  if (new Set(judgeIds).size !== judgeIds.length)
    return { pass: false, reason: "duplicate judge identity", spread: Infinity };
  if (
    options.allowedJudgeIds &&
    (new Set(options.allowedJudgeIds).size !== options.allowedJudgeIds.length ||
      judgeIds.some((id) => !options.allowedJudgeIds.includes(id)))
  )
    return { pass: false, reason: "judge identity is not allowlisted", spread: Infinity };
  if (options.independenceKeys) {
    const keys = results.map((item) => options.independenceKeys[item.judgeId]);
    if (keys.some((key) => !isBoundedString(key, maxIdLength)) || new Set(keys).size !== keys.length)
      return { pass: false, reason: "judges do not have independent origins", spread: Infinity };
  }
  const averages = categories.map(
    (category) => results.reduce((sum, item) => sum + item.scores[category], 0) / results.length,
  );
  const spread = Math.max(
    ...categories.map(
      (category) =>
        Math.max(...results.map((item) => item.scores[category])) -
        Math.min(...results.map((item) => item.scores[category])),
    ),
  );
  const pass = spread <= 1 && averages.every((score) => score >= 4) && results.every((item) => item.pass);
  return { pass, reason: pass ? "judges agree" : "judge disagreement or score below threshold", spread, averages };
};
