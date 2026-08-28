import {
  addDays,
  assertKeys,
  compareCodepoints,
  digest,
  fail,
  instant,
  localDate,
  ref,
  sha256Canonical,
  singleLine,
  snapshotPlainJson,
  text,
  zoneDate,
} from "./validation.mjs";
import { ceoDeploymentProfile } from "../deployment-profiles/index.mjs";
import { assertProfileAuthority } from "../deployment-profiles/profile-contract/index.mjs";

const marketingPolicyTemplate = Object.freeze({
  version: "marketing-program.v4",
  timeZone: "America/Los_Angeles",
  planWeekday: "Friday",
  cooldownDays: 28,
  noveltyDays: 90,
  maximumResearch: 32,
  maximumDraftCharacters: 5_000,
  researchFreshnessMilliseconds: 7 * 86_400_000,
  maximumCitationCharacters: 2_048,
  evaluationOriginsPerGate: 2,
  maximumRevision: 1_000_000,
  maximumMoveDelayDays: 2,
});
const voiceRubricTemplate = Object.freeze({
  version: "marketing-voice.v4",
  rules: Object.freeze([
    "lexical_prefilter_only",
    "short_direct_sentences",
    "one_or_two_sentence_paragraphs",
    "curious_not_condescending",
    "no_known_ai_slop",
    "safe_cta",
    "no_known_customer_claim",
    "no_known_anecdote",
  ]),
  bannedPhrases: Object.freeze([
    "game changer",
    "leverage synergies",
    "thought leadership",
    "unlock value",
    "in today s fast paced world",
    "as an ai",
    "delve into",
    "revolutionize",
    "seamlessly",
    "cutting edge",
    "best in class",
    "world class",
    "obviously",
    "everyone knows",
    "you should",
    "hurry",
    "last chance",
    "act today",
    "click here",
    "reply today",
    "reply now",
    "share with your team",
    "colleague said",
    "founder said",
    "story",
    "in my experience",
  ]),
  safeCta: "Lexical prefilter only; independent trusted evaluation remains required.",
});
export const requiredEvaluationGates = Object.freeze([
  "voice",
  "citation_integrity",
  "claim_safety",
  "presentation_safety",
]);
const marketingContractSuites = new WeakSet();
const marketingAuthority = (value) => {
  const profile = assertProfileAuthority(value);
  const requiredCapabilities = ["marketing.content_propose", "notion.artifact_propose", "slack.surface_compile"];
  const requiredProviders = ["notion", "slack"];
  if (
    requiredCapabilities.some((capability) => !profile.allowedCapabilities.includes(capability)) ||
    requiredProviders.some((provider) => !profile.providerOwners.some((entry) => entry.provider === provider)) ||
    profile.providerExecutionAllowed !== false
  )
    fail("unsupported_marketing_profile");
  const policyProjection = {
    ...marketingPolicyTemplate,
    policyRef: `marketing-policy:${profile.profileRef}`,
    profileRef: profile.profileRef,
    profileSha256: profile.profileSha256,
    roleRef: `role:${profile.identity.externalOrganizationRole}`,
    approvalLifetimeMilliseconds: profile.grantPolicy.maximumApprovalLifetimeMs,
    requiredEvaluationGates,
  };
  const voiceProjection = {
    ...voiceRubricTemplate,
    voiceProfileRef: `marketing-voice:${profile.profileRef}`,
    profileRef: profile.profileRef,
    profileSha256: profile.profileSha256,
    principalRef: profile.identity.humanPrincipalRef,
    roleRef: `role:${profile.identity.externalOrganizationRole}`,
  };
  return Object.freeze({
    profile,
    policy: Object.freeze({ ...policyProjection, policySha256: sha256Canonical(policyProjection) }),
    voice: Object.freeze({ ...voiceProjection, voiceSha256: sha256Canonical(voiceProjection) }),
    bindingAnchor: Object.freeze({
      deploymentRef: profile.anchors.deploymentRef,
      anchorRef: profile.anchors.principalBindingRef,
      tenantRef: profile.anchors.tenantRef,
      workspaceRef: profile.anchors.workspaceRef,
      principalRef: profile.identity.humanPrincipalRef,
      credentialOwnerRef: profile.identity.credentialOwnerRef,
      notionRootRef: profile.audiences.notion.parentRef,
      slackTeamRef: profile.anchors.slackTeamRef,
      slackUserRef: profile.audiences.slack.principalRef,
    }),
  });
};
const ceoMarketingAuthority = marketingAuthority(ceoDeploymentProfile);
export const marketingPolicy = ceoMarketingAuthority.policy;
export const shahryarVoiceRubric = ceoMarketingAuthority.voice;
export const marketingBindingAnchor = ceoMarketingAuthority.bindingAnchor;
export const researchProviderRegistry = Object.freeze({
  "research-provider:ipeds": Object.freeze({ host: "nces.ed.gov" }),
  "research-provider:education-department": Object.freeze({ host: "www.ed.gov" }),
});
export const lanes = Object.freeze(["admissions", "advancement"]);

const researchKeys = new Set([
  "citationRef",
  "providerRef",
  "sourceRef",
  "sourceUrl",
  "sourceReceiptProposalRef",
  "sourceReceiptHash",
  "receiptDisposition",
  "exactCitation",
  "citationStart",
  "citationEnd",
  "trust",
  "availability",
  "observedAt",
  "fetchedAt",
  "researchHash",
]);
const entryKeys = new Set([
  "date",
  "lane",
  "topicRef",
  "noveltyKey",
  "outline",
  "citationRefs",
  "occurrenceRef",
  "occurrenceVersion",
]);
const planKeys = new Set(["planRef", "weekStartDate", "revision", "entries"]);
const historyKeys = new Set(["date", "lane", "topicRef", "noveltyKey"]);
const baseKeys = new Set([
  "version",
  "programRef",
  "programRevision",
  "now",
  "goalDate",
  "timeZone",
  "binding",
  "weeklyPlan",
  "research",
  "history",
]);
const draftKeys = new Set([
  "date",
  "draftRevision",
  "planRef",
  "planHash",
  "approvalRequestRef",
  "text",
  "citationRefs",
  "claimCitations",
  "notionParentRef",
  "schedule",
]);
const claimCitationKeys = new Set(["sentence", "citationRefs"]);
const scheduleKeys = new Set([
  "status",
  "plannedDate",
  "effectiveDate",
  "movedFromDate",
  "missedReason",
  "localTime",
  "scheduledAt",
  "occurrenceRef",
  "occurrenceVersion",
  "serverTimeRequestRef",
  "serverTimeDisposition",
]);
const dayName = (value) =>
  new Intl.DateTimeFormat("en-US", { timeZone: "UTC", weekday: "long" }).format(new Date(`${value}T00:00:00.000Z`));
export const uncitedCopyTemplates = Object.freeze([
  "I am curious what you think.",
  "Reply if a question comes to mind.",
  "What question would you ask?",
]);
const forbiddenCopy = /(?:<|>|\[|\]|\(|\)|`|\*|_|~|@)/;
const forbiddenTokenPhrases = Object.freeze([
  "click here",
  "reply today",
  "reply now",
  "you need",
  "you must",
  "must",
  "customer",
  "customers",
  "client",
  "clients",
  "student told me",
  "a student told me",
  "i worked with",
  "we worked with",
  "i remember",
  "we saw",
  "case study",
  "our partner",
  "always",
  "never",
  "proven",
  "guarantee",
  "act now",
  "limited time",
  "urgent",
  "immediately",
]);
const normalizedMarketingTextForAuthority = (value, authority) => {
  if (
    typeof value !== "string" ||
    value.length > authority.policy.maximumDraftCharacters ||
    value.startsWith("\n") ||
    value.endsWith("\n") ||
    !/^[\x20-\x7E\n]*$/.test(value)
  )
    fail("invalid_marketing_text");
  const normalized = value
    .split("\n")
    .map((line) => line.trim().replace(/ {2,}/g, " "))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n");
  if (normalized !== value) fail("invalid_marketing_text");
  return value;
};
const wordTokens = (value, authority) =>
  normalizedMarketingTextForAuthority(value, authority)
    .toLowerCase()
    .match(/[a-z0-9]+/g) ?? [];
const hasTokenPhrase = (tokens, phrase) => {
  const phraseTokens = phrase.split(" ");
  return tokens.some((token, start) => phraseTokens.every((part, index) => tokens[start + index] === part));
};
const lexicalCopyChecksForAuthority = (value, authority) => {
  const original = normalizedMarketingTextForAuthority(
    text(value, authority.policy.maximumDraftCharacters, "invalid_marketing_text"),
    authority,
  );
  const tokens = wordTokens(original, authority);
  const forbidden = [...forbiddenTokenPhrases, ...authority.voice.bannedPhrases];
  return Object.freeze({
    printableAsciiLfOnly: true,
    normalizedWhitespace: true,
    noMarkupOrMention: !forbiddenCopy.test(original),
    noKnownForbiddenPhrase: !forbidden.some((phrase) => hasTokenPhrase(tokens, phrase)),
  });
};
const copySentencesForAuthority = (value, authority) =>
  normalizedMarketingTextForAuthority(value, authority)
    .split(/[.!?]+/)
    .map((sentence) => sentence.trim())
    .filter(Boolean)
    .map(
      (sentence) => `${sentence}${value.slice(value.indexOf(sentence) + sentence.length).match(/^[.!?]/)?.[0] ?? "."}`,
    );
export const isUncitedCopyTemplate = (value) => uncitedCopyTemplates.includes(value);
const assertLexicallyAdmissibleCopyForAuthority = (value, authority, code = "invalid_marketing_text") => {
  const original = normalizedMarketingTextForAuthority(
    text(value, authority.policy.maximumDraftCharacters, code),
    authority,
  );
  const checks = lexicalCopyChecksForAuthority(original, authority);
  if (!original || !Object.values(checks).every(Boolean)) fail(code);
  return original;
};
const localParts = (value, policy) => {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: policy.timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(value);
  const get = (kind) => parts.find((part) => part.type === kind)?.value;
  return `${get("year")}-${get("month")}-${get("day")}T${get("hour")}:${get("minute")}`;
};
const canonicalLocalInstant = (dateValue, localTime, policy) => {
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(localTime)) fail("invalid_schedule");
  const target = `${dateValue}T${localTime}`;
  let candidate = new Date(`${target}:00.000Z`);
  for (let index = 0; index < 4; index += 1)
    candidate = new Date(
      candidate.valueOf() + Date.parse(`${target}:00.000Z`) - Date.parse(`${localParts(candidate, policy)}:00.000Z`),
    );
  if (
    localParts(candidate, policy) !== target ||
    localParts(new Date(candidate.valueOf() + 3_600_000), policy) === target ||
    localParts(new Date(candidate.valueOf() - 3_600_000), policy) === target
  )
    fail("ambiguous_or_missing_dst_schedule");
  return candidate.toISOString();
};
const normalizeBinding = (value, authority) => {
  const marketingBindingAnchor = authority.bindingAnchor;
  assertKeys(value, new Set(Object.keys(marketingBindingAnchor)), "invalid_binding");
  const normalized = Object.freeze(
    Object.fromEntries(Object.keys(marketingBindingAnchor).map((key) => [key, ref(value[key], "invalid_binding")])),
  );
  if (Object.keys(marketingBindingAnchor).some((key) => normalized[key] !== marketingBindingAnchor[key]))
    fail("binding_mismatch");
  return normalized;
};
const normalizeResearch = (values, now, authority) => {
  if (!Array.isArray(values) || values.length < 1 || values.length > authority.policy.maximumResearch)
    fail("invalid_research");
  const normalized = values
    .map((value) => {
      assertKeys(value, researchKeys, "invalid_research");
      const provider = researchProviderRegistry[value.providerRef];
      const observedAt = instant(value.observedAt, "invalid_research");
      const fetchedAt = instant(value.fetchedAt, "invalid_research");
      const exactCitation = text(value.exactCitation, authority.policy.maximumCitationCharacters, "invalid_research");
      const citationStart = value.citationStart;
      const citationEnd = value.citationEnd;
      if (
        !provider ||
        observedAt > fetchedAt ||
        fetchedAt > now ||
        now - fetchedAt > authority.policy.researchFreshnessMilliseconds ||
        value.availability !== "unresolved" ||
        value.trust !== "unresolved" ||
        value.receiptDisposition !== "unresolved" ||
        !Number.isSafeInteger(citationStart) ||
        !Number.isSafeInteger(citationEnd) ||
        citationStart < 0 ||
        citationEnd <= citationStart ||
        citationEnd > exactCitation.length
      )
        fail("invalid_research");
      const entry = {
        citationRef: ref(value.citationRef, "invalid_research"),
        providerRef: ref(value.providerRef, "invalid_research"),
        sourceRef: ref(value.sourceRef, "invalid_research"),
        sourceUrl: singleLine(value.sourceUrl, 2_048, "invalid_research"),
        sourceReceiptProposalRef: ref(value.sourceReceiptProposalRef, "invalid_research"),
        sourceReceiptHash: digest(value.sourceReceiptHash, "invalid_research"),
        receiptDisposition: "unresolved",
        exactCitation,
        citationStart,
        citationEnd,
        trust: "unresolved",
        availability: "unresolved",
        observedAt: observedAt.toISOString(),
        fetchedAt: fetchedAt.toISOString(),
      };
      const url = new URL(entry.sourceUrl);
      if (
        url.protocol !== "https:" ||
        url.hostname !== provider.host ||
        url.username ||
        url.password ||
        url.port ||
        digest(value.researchHash, "invalid_research") !== sha256Canonical(entry)
      )
        fail("invalid_research");
      return Object.freeze({ ...entry, researchHash: value.researchHash });
    })
    .sort((left, right) => compareCodepoints(left.citationRef, right.citationRef));
  if (
    new Set(normalized.map((item) => item.citationRef)).size !== normalized.length ||
    new Set(normalized.map((item) => item.sourceReceiptProposalRef)).size !== normalized.length
  )
    fail("duplicate_citation");
  return Object.freeze(normalized);
};
const normalizeEntry = (value, citations, authority) => {
  assertKeys(value, entryKeys, "invalid_plan_entry");
  if (
    !lanes.includes(value.lane) ||
    !Array.isArray(value.citationRefs) ||
    value.citationRefs.length < 1 ||
    value.citationRefs.length > 8 ||
    !Number.isSafeInteger(value.occurrenceVersion) ||
    value.occurrenceVersion < 1 ||
    value.occurrenceVersion > authority.policy.maximumRevision
  )
    fail("invalid_plan_entry");
  const citationRefs = value.citationRefs.map((item) => ref(item, "invalid_plan_entry")).sort(compareCodepoints);
  if (new Set(citationRefs).size !== citationRefs.length || citationRefs.some((item) => !citations.has(item)))
    fail("invalid_plan_entry");
  const outline = assertLexicallyAdmissibleCopyForAuthority(value.outline, authority, "invalid_plan_entry");
  if (copySentencesForAuthority(outline, authority).length !== 1 || isUncitedCopyTemplate(outline))
    fail("invalid_plan_entry");
  return Object.freeze({
    date: localDate(value.date, "invalid_plan_entry"),
    lane: value.lane,
    topicRef: ref(value.topicRef, "invalid_plan_entry"),
    noveltyKey: ref(value.noveltyKey, "invalid_plan_entry"),
    outline,
    citationRefs: Object.freeze(citationRefs),
    occurrenceRef: ref(value.occurrenceRef, "invalid_plan_entry"),
    occurrenceVersion: value.occurrenceVersion,
  });
};
const normalizePlan = (value, research, authority) => {
  assertKeys(value, planKeys, "invalid_weekly_plan");
  const weekStartDate = localDate(value.weekStartDate, "invalid_weekly_plan");
  if (
    dayName(weekStartDate) !== authority.policy.planWeekday ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0 ||
    value.revision > authority.policy.maximumRevision ||
    !Array.isArray(value.entries) ||
    value.entries.length !== 5
  )
    fail("invalid_weekly_plan");
  const entries = value.entries
    .map((item) => normalizeEntry(item, new Set(research.map((entry) => entry.citationRef)), authority))
    .sort((left, right) => compareCodepoints(left.date, right.date));
  if (
    entries.some((entry, index) => entry.date !== addDays(weekStartDate, index + 3)) ||
    new Set(entries.map((entry) => entry.topicRef)).size !== entries.length ||
    new Set(entries.map((entry) => entry.noveltyKey)).size !== entries.length ||
    new Set(entries.map((entry) => entry.occurrenceRef)).size !== entries.length
  )
    fail("invalid_plan_schedule");
  return Object.freeze({
    planRef: ref(value.planRef, "invalid_weekly_plan"),
    weekStartDate,
    revision: value.revision,
    entries: Object.freeze(entries),
  });
};
const normalizeHistory = (values) => {
  if (!Array.isArray(values) || values.length > 200) fail("invalid_history");
  const normalized = values
    .map((value) => {
      assertKeys(value, historyKeys, "invalid_history");
      if (!lanes.includes(value.lane)) fail("invalid_history");
      return Object.freeze({
        date: localDate(value.date, "invalid_history"),
        lane: value.lane,
        topicRef: ref(value.topicRef, "invalid_history"),
        noveltyKey: ref(value.noveltyKey, "invalid_history"),
      });
    })
    .sort(
      (left, right) =>
        compareCodepoints(left.date, right.date) ||
        compareCodepoints(left.topicRef, right.topicRef) ||
        compareCodepoints(left.noveltyKey, right.noveltyKey),
    );
  if (
    new Set(normalized.map((item) => `${item.date}\u0000${item.topicRef}\u0000${item.noveltyKey}`)).size !==
    normalized.length
  )
    fail("duplicate_history");
  return Object.freeze(normalized);
};
const enforceRotation = (plan, history, authority) => {
  let prior = history.filter((item) => item.date < plan.entries[0].date).at(-1)?.lane ?? "advancement";
  for (const entry of plan.entries) {
    if (entry.lane === prior) fail("rotation_violation");
    if (
      history.some(
        (item) => item.topicRef === entry.topicRef && item.date >= addDays(entry.date, -authority.policy.cooldownDays),
      )
    )
      fail("topic_cooldown_violation");
    if (
      history.some(
        (item) =>
          item.noveltyKey === entry.noveltyKey && item.date >= addDays(entry.date, -authority.policy.noveltyDays),
      )
    )
      fail("novelty_violation");
    prior = entry.lane;
  }
};
const normalizeDraft = (value, plan, goalDate, research, authority) => {
  const marketingBindingAnchor = authority.bindingAnchor;
  assertKeys(value, draftKeys, "invalid_draft");
  assertKeys(value.schedule, scheduleKeys, "invalid_schedule");
  const entry = plan.entries.find((item) => item.date === goalDate);
  const schedule = value.schedule;
  const effectiveDate = localDate(schedule.effectiveDate, "invalid_schedule");
  const scheduledAt = canonicalLocalInstant(effectiveDate, schedule.localTime, authority.policy);
  if (
    !entry ||
    !["scheduled", "moved"].includes(schedule.status) ||
    localDate(schedule.plannedDate, "invalid_schedule") !== goalDate ||
    effectiveDate !== goalDate ||
    instant(schedule.scheduledAt, "invalid_schedule").toISOString() !== scheduledAt ||
    ref(schedule.occurrenceRef, "invalid_schedule") !== entry.occurrenceRef ||
    schedule.occurrenceVersion !== entry.occurrenceVersion ||
    !Number.isSafeInteger(schedule.occurrenceVersion) ||
    schedule.serverTimeDisposition !== "unresolved" ||
    ref(schedule.serverTimeRequestRef, "invalid_schedule").length < 1 ||
    (schedule.status === "moved"
      ? (() => {
          const movedFromDate = localDate(schedule.movedFromDate, "invalid_schedule");
          return (
            movedFromDate >= effectiveDate ||
            movedFromDate < addDays(effectiveDate, -authority.policy.maximumMoveDelayDays)
          );
        })()
      : schedule.movedFromDate !== null) ||
    schedule.missedReason !== null
  )
    fail("invalid_schedule");
  const planHash = sha256Canonical(plan);
  if (
    ref(value.planRef, "invalid_draft") !== plan.planRef ||
    digest(value.planHash, "invalid_draft") !== planHash ||
    !Number.isSafeInteger(value.draftRevision) ||
    value.draftRevision < 0 ||
    value.draftRevision > authority.policy.maximumRevision ||
    ref(value.approvalRequestRef, "invalid_draft").length < 1 ||
    ref(value.notionParentRef, "invalid_draft") !== marketingBindingAnchor.notionRootRef ||
    localDate(value.date, "invalid_draft") !== goalDate
  )
    fail("invalid_draft");
  const citations = value.citationRefs;
  if (!Array.isArray(citations) || citations.length < 1) fail("invalid_draft");
  const citationRefs = citations.map((item) => ref(item, "invalid_draft")).sort(compareCodepoints);
  if (
    new Set(citationRefs).size !== citationRefs.length ||
    citationRefs.some(
      (item) => !entry.citationRefs.includes(item) || !research.some((source) => source.citationRef === item),
    ) ||
    !Array.isArray(value.claimCitations) ||
    value.claimCitations.length > 8
  )
    fail("invalid_draft");
  const draftText = assertLexicallyAdmissibleCopyForAuthority(value.text, authority, "invalid_draft");
  const claims = value.claimCitations.map((claim) => {
    assertKeys(claim, claimCitationKeys, "invalid_draft");
    if (!Array.isArray(claim.citationRefs)) fail("invalid_draft");
    const claimRefs = claim.citationRefs.map((item) => ref(item, "invalid_draft")).sort(compareCodepoints);
    const sentence = assertLexicallyAdmissibleCopyForAuthority(claim.sentence, authority, "invalid_draft");
    if (
      copySentencesForAuthority(sentence, authority).length !== 1 ||
      claimRefs.length < 1 ||
      claimRefs.some((item) => !citationRefs.includes(item))
    )
      fail("invalid_draft");
    return Object.freeze({ sentence, citationRefs: Object.freeze(claimRefs) });
  });
  const substantive = copySentencesForAuthority(draftText, authority).filter(
    (sentence) => !isUncitedCopyTemplate(sentence),
  );
  if (
    new Set(claims.map((claim) => claim.sentence)).size !== claims.length ||
    substantive.length !== claims.length ||
    substantive.some((sentence) => !claims.some((claim) => claim.sentence === sentence))
  )
    fail("missing_claim_citation");
  return Object.freeze({
    date: goalDate,
    draftRevision: value.draftRevision,
    planRef: plan.planRef,
    planHash,
    approvalRequestRef: value.approvalRequestRef,
    text: draftText,
    citationRefs: Object.freeze(citationRefs),
    claimCitations: Object.freeze(claims),
    notionParentRef: marketingBindingAnchor.notionRootRef,
    schedule: Object.freeze({ ...schedule, scheduledAt }),
  });
};

const normalizeMarketingInputForAuthority = (raw, mode, authority) => {
  const policy = authority.policy;
  if (!["weekly", "daily"].includes(mode)) fail("invalid_mode");
  const value = snapshotPlainJson(raw);
  assertKeys(value, mode === "daily" ? new Set([...baseKeys, "draft"]) : baseKeys, "invalid_input");
  if (
    value.version !== policy.version ||
    value.timeZone !== policy.timeZone ||
    !Number.isSafeInteger(value.programRevision) ||
    value.programRevision < 0 ||
    value.programRevision > policy.maximumRevision
  )
    fail("invalid_input");
  const now = instant(value.now, "invalid_input");
  const goalDate = localDate(value.goalDate, "invalid_input");
  if (mode === "weekly" && dayName(goalDate) !== policy.planWeekday) fail("friday_plan_required");
  if (zoneDate(now, policy.timeZone) !== goalDate) fail("goal_date_mismatch");
  const research = normalizeResearch(value.research, now, authority);
  const weeklyPlan = normalizePlan(value.weeklyPlan, research, authority);
  const history = normalizeHistory(value.history);
  enforceRotation(weeklyPlan, history, authority);
  if (mode === "weekly" && goalDate !== weeklyPlan.weekStartDate) fail("friday_plan_required");
  const base = {
    version: policy.version,
    programRef: ref(value.programRef, "invalid_input"),
    programRevision: value.programRevision,
    now: now.toISOString(),
    goalDate,
    timeZone: policy.timeZone,
    binding: normalizeBinding(value.binding, authority),
    weeklyPlan,
    research,
    history,
  };
  return Object.freeze(
    mode === "daily"
      ? { ...base, draft: normalizeDraft(value.draft, weeklyPlan, goalDate, research, authority) }
      : base,
  );
};

export function createMarketingProgramContractSuite(profile) {
  const authority = marketingAuthority(profile);
  const suite = Object.freeze({
    profile: authority.profile,
    policy: authority.policy,
    voice: authority.voice,
    marketingBindingAnchor: authority.bindingAnchor,
    normalizeMarketingInput: (raw, mode) => normalizeMarketingInputForAuthority(raw, mode, authority),
    normalizedMarketingText: (value) => normalizedMarketingTextForAuthority(value, authority),
    lexicalCopyChecks: (value) => lexicalCopyChecksForAuthority(value, authority),
    copySentences: (value) => copySentencesForAuthority(value, authority),
    assertLexicallyAdmissibleCopy: (value, code) => assertLexicallyAdmissibleCopyForAuthority(value, authority, code),
    isUncitedCopyTemplate,
    providerExecutionAllowed: false,
  });
  marketingContractSuites.add(suite);
  return suite;
}

export function assertMarketingProgramContractSuite(value) {
  if (!marketingContractSuites.has(value)) fail("invalid_marketing_contract_suite");
  return value;
}

export const ceoMarketingProgramContractSuite = createMarketingProgramContractSuite(ceoDeploymentProfile);
export const normalizeMarketingInput = ceoMarketingProgramContractSuite.normalizeMarketingInput;
export const normalizedMarketingText = ceoMarketingProgramContractSuite.normalizedMarketingText;
export const lexicalCopyChecks = ceoMarketingProgramContractSuite.lexicalCopyChecks;
export const copySentences = ceoMarketingProgramContractSuite.copySentences;
export const assertLexicallyAdmissibleCopy = ceoMarketingProgramContractSuite.assertLexicallyAdmissibleCopy;
