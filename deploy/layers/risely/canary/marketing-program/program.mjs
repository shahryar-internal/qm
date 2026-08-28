import { assertMarketingProgramContractSuite, ceoMarketingProgramContractSuite } from "./contracts.mjs";
import { compareCodepoints, fail, sha256Canonical, snapshotPlainJson } from "./validation.mjs";

const builtMarketingPrograms = new WeakSet();
const marketingProgramContracts = new WeakMap();
const lexicalPrefilters = (contracts, draft) => {
  const sentences = contracts.copySentences(draft.text);
  return Object.freeze({
    ...contracts.lexicalCopyChecks(draft.text),
    oneOrTwoSentenceParagraphs: draft.text.split("\n\n").every((paragraph) => {
      const count = contracts.copySentences(paragraph).length;
      return count >= 1 && count <= 2;
    }),
    shortDirectSentences: sentences.every((sentence) => sentence.split(/\s+/).length <= 24),
    exactCitationForEverySubstantiveSentence: sentences
      .filter((sentence) => !contracts.isUncitedCopyTemplate(sentence))
      .every((sentence) =>
        draft.claimCitations.some((claim) => claim.sentence === sentence && claim.citationRefs.length > 0),
      ),
    paragraphSentenceCounts: Object.freeze(
      draft.text.split("\n\n").map((paragraph) => contracts.copySentences(paragraph).length),
    ),
  });
};
const researchEvidence = (research) =>
  Object.freeze(
    research.map((entry) =>
      Object.freeze({
        citationRef: entry.citationRef,
        providerRef: entry.providerRef,
        sourceRef: entry.sourceRef,
        sourceUrl: entry.sourceUrl,
        sourceReceiptProposalRef: entry.sourceReceiptProposalRef,
        sourceReceiptHash: entry.sourceReceiptHash,
        receiptDisposition: "unresolved",
        citationSpan: Object.freeze({ start: entry.citationStart, end: entry.citationEnd }),
        trust: "unresolved",
        availability: "unresolved",
        observedAt: entry.observedAt,
        fetchedAt: entry.fetchedAt,
        researchHash: entry.researchHash,
        exactCitationHash: sha256Canonical(entry.exactCitation),
      }),
    ),
  );
const sourceRefsFor = (research, citationRefs) =>
  Object.freeze(
    research
      .filter((entry) => citationRefs.includes(entry.citationRef))
      .map((entry) =>
        Object.freeze({
          citationRef: entry.citationRef,
          sourceRef: entry.sourceRef,
          sourceReceiptProposalRef: entry.sourceReceiptProposalRef,
          sourceReceiptHash: entry.sourceReceiptHash,
          researchHash: entry.researchHash,
        }),
      )
      .sort((left, right) => compareCodepoints(left.citationRef, right.citationRef)),
  );
export const marketingProgramHash = (program) => {
  const value = snapshotPlainJson(program);
  const { programHash, artifact, ...rest } = value;
  const {
    programHash: artifactProgramHash,
    idempotencyKey,
    programRevision,
    rubricHash,
    researchHash,
    ...artifactRest
  } = artifact;
  return sha256Canonical({ ...rest, artifact: artifactRest });
};
const base = (contracts, input, kind, artifactBase) => {
  const research = researchEvidence(input.research);
  const skeleton = {
    version: contracts.policy.version,
    kind,
    programRef: input.programRef,
    programRevision: input.programRevision,
    goalDate: input.goalDate,
    timeZone: input.timeZone,
    principalBinding: input.binding,
    rolePolicy: contracts.policy,
    weeklyPlan: input.weeklyPlan,
    planHash: sha256Canonical(input.weeklyPlan),
    rubric: contracts.voice,
    rubricHash: sha256Canonical(contracts.voice),
    research,
    researchHash: sha256Canonical(research),
    artifact: artifactBase,
    safety: Object.freeze({
      disposition: "unresolved_proposals",
      executionDisposition: "hard_disabled",
      providerAccess: "none",
      socialExecution: "not_available",
      trustedReceiptRequired: true,
    }),
    requiredEvaluationGates: contracts.policy.requiredEvaluationGates,
  };
  const programHash = marketingProgramHash(skeleton);
  const artifact = Object.freeze({
    ...artifactBase,
    programHash,
    programRevision: input.programRevision,
    rubricHash: skeleton.rubricHash,
    researchHash: skeleton.researchHash,
  });
  const output = Object.freeze({ ...skeleton, artifact, programHash });
  builtMarketingPrograms.add(output);
  marketingProgramContracts.set(output, contracts);
  return output;
};
export const buildWeeklyMarketingPlanForContractSuite = (contractSuite, raw) => {
  const contracts = assertMarketingProgramContractSuite(contractSuite);
  const input = contracts.normalizeMarketingInput(raw, "weekly");
  const citationRefs = Object.freeze(
    [...new Set(input.weeklyPlan.entries.flatMap((entry) => entry.citationRefs))].sort(compareCodepoints),
  );
  const outlineMappings = Object.freeze(
    input.weeklyPlan.entries.map((entry) =>
      Object.freeze({ occurrenceRef: entry.occurrenceRef, outline: entry.outline, citationRefs: entry.citationRefs }),
    ),
  );
  return base(
    contracts,
    input,
    "weekly_plan",
    Object.freeze({
      artifactRef: `marketing-plan:${sha256Canonical({ planRef: input.weeklyPlan.planRef, revision: input.weeklyPlan.revision, outlineMappings, citationRefs })}`,
      type: "slack.plan_approval_proposal",
      disposition: "unresolved",
      copyDisposition: "untrusted_candidate",
      releaseDisposition: "impossible_without_independent_trusted_eval_receipts",
      entries: input.weeklyPlan.entries,
      outlineMappings,
      citationRefs,
      sourceRefs: sourceRefsFor(input.research, citationRefs),
      mappingHash: sha256Canonical(outlineMappings),
      slackArtifact: Object.freeze({ type: "qm.marketing_plan", actionless: true }),
    }),
  );
};
export const inspectDailyMarketingDraftForContractSuite = (contractSuite, raw) => {
  const contracts = assertMarketingProgramContractSuite(contractSuite);
  const input = contracts.normalizeMarketingInput(raw, "daily");
  const checks = lexicalPrefilters(contracts, input.draft);
  if (
    !Object.values(checks)
      .filter((value) => typeof value === "boolean")
      .every(Boolean)
  )
    fail("lexical_prefilter_failed");
  return Object.freeze({
    draftRevision: input.draft.draftRevision,
    contentHash: sha256Canonical(input.draft.text),
    mappingHash: sha256Canonical(input.draft.claimCitations),
    sourceRefs: sourceRefsFor(input.research, input.draft.citationRefs),
    planHash: input.draft.planHash,
    approvalRequestRef: input.draft.approvalRequestRef,
    copyDisposition: "untrusted_candidate",
    releaseDisposition: "impossible_without_independent_trusted_eval_receipts",
    lexicalPrefilters: checks,
  });
};
export const buildWeeklyMarketingPlan = (raw) =>
  buildWeeklyMarketingPlanForContractSuite(ceoMarketingProgramContractSuite, raw);
export const inspectDailyMarketingDraft = (raw) =>
  inspectDailyMarketingDraftForContractSuite(ceoMarketingProgramContractSuite, raw);
export const buildDailyMarketingDraftForContractSuite = (contractSuite, raw, callerApprovalContext) => {
  const contracts = assertMarketingProgramContractSuite(contractSuite);
  if (callerApprovalContext !== undefined) fail("caller_approval_context_unsupported");
  const input = contracts.normalizeMarketingInput(raw, "daily");
  const deterministic = inspectDailyMarketingDraftForContractSuite(contracts, input);
  const artifactBase = Object.freeze({
    artifactRef: `marketing-draft:${sha256Canonical({ planRef: input.draft.planRef, date: input.goalDate, draftRevision: input.draft.draftRevision, contentHash: deterministic.contentHash, mappingHash: deterministic.mappingHash, sourceRefs: deterministic.sourceRefs })}`,
    type: "notion.private_ceo_draft_proposal",
    notionParentRef: input.binding.notionRootRef,
    audience: "private_ceo",
    text: input.draft.text,
    draftRevision: input.draft.draftRevision,
    citationRefs: input.draft.citationRefs,
    claimCitations: input.draft.claimCitations,
    sourceRefs: deterministic.sourceRefs,
    mappingHash: deterministic.mappingHash,
    approvalRequestRef: input.draft.approvalRequestRef,
    schedule: input.draft.schedule,
    lexicalPrefilters: deterministic.lexicalPrefilters,
    copyDisposition: "untrusted_candidate",
    releaseDisposition: "impossible_without_independent_trusted_eval_receipts",
    contentHash: deterministic.contentHash,
    slackArtifact: Object.freeze({ type: "qm.marketing_draft", actionless: true, socialExecution: "not_available" }),
    publication: Object.freeze({
      state: "impossible_without_independent_trusted_eval_receipts",
      trustedReceiptRequired: true,
    }),
  });
  const preliminary = base(contracts, input, "daily_draft", artifactBase);
  const idempotencyKey = sha256Canonical({
    version: contracts.policy.version,
    programHash: preliminary.programHash,
    artifactRef: preliminary.artifact.artifactRef,
    programRevision: preliminary.programRevision,
    goalDate: preliminary.goalDate,
    planHash: preliminary.planHash,
    draftRevision: input.draft.draftRevision,
    contentHash: deterministic.contentHash,
    mappingHash: deterministic.mappingHash,
    sourceRefs: deterministic.sourceRefs,
    notionParentRef: input.binding.notionRootRef,
  });
  const output = Object.freeze({
    ...preliminary,
    artifact: Object.freeze({ ...preliminary.artifact, idempotencyKey }),
  });
  builtMarketingPrograms.add(output);
  marketingProgramContracts.set(output, contracts);
  return output;
};
export const buildDailyMarketingDraft = (raw, callerApprovalContext) =>
  buildDailyMarketingDraftForContractSuite(ceoMarketingProgramContractSuite, raw, callerApprovalContext);
export const assertBuiltMarketingProgram = (value) => {
  if (!value || typeof value !== "object" || !builtMarketingPrograms.has(value)) fail("untrusted_program");
  return value;
};
export const assertBuiltMarketingProgramForContractSuite = (contractSuite, value) => {
  const contracts = assertMarketingProgramContractSuite(contractSuite);
  assertBuiltMarketingProgram(value);
  if (marketingProgramContracts.get(value) !== contracts) fail("untrusted_program");
  return value;
};
