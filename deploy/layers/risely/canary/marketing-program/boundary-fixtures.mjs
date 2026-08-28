import { assertMarketingProgramContractSuite, ceoMarketingProgramContractSuite } from "./contracts.mjs";
import { sha256Canonical } from "./validation.mjs";

const research = (citationRef, exactCitation) => {
  const entry = {
    citationRef,
    providerRef: "research-provider:ipeds",
    sourceRef: `research-source:${citationRef}`,
    sourceUrl: `https://nces.ed.gov/${citationRef}`,
    sourceReceiptProposalRef: `research-receipt:${citationRef}`,
    sourceReceiptHash: sha256Canonical(`source-receipt:${citationRef}`),
    receiptDisposition: "unresolved",
    exactCitation,
    citationStart: 0,
    citationEnd: exactCitation.length,
    trust: "unresolved",
    availability: "unresolved",
    observedAt: "2026-08-28T15:00:00.000Z",
    fetchedAt: "2026-08-28T16:00:00.000Z",
  };
  return { ...entry, researchHash: sha256Canonical(entry) };
};
const plan = () => ({
  planRef: "marketing-plan:2026-08-28",
  weekStartDate: "2026-08-28",
  revision: 0,
  entries: [
    {
      date: "2026-08-31",
      lane: "admissions",
      topicRef: "topic:admissions-listening",
      noveltyKey: "novelty:admissions-listening",
      outline: "A practical question about listening before changing a student journey.",
      citationRefs: ["citation:one"],
      occurrenceRef: "occurrence:2026-08-31",
      occurrenceVersion: 1,
    },
    {
      date: "2026-09-01",
      lane: "advancement",
      topicRef: "topic:advancement-clarity",
      noveltyKey: "novelty:advancement-clarity",
      outline: "A practical question about clear next steps for alumni support.",
      citationRefs: ["citation:two"],
      occurrenceRef: "occurrence:2026-09-01",
      occurrenceVersion: 1,
    },
    {
      date: "2026-09-02",
      lane: "admissions",
      topicRef: "topic:admissions-handoff",
      noveltyKey: "novelty:admissions-handoff",
      outline: "A practical question about reducing handoff friction.",
      citationRefs: ["citation:three"],
      occurrenceRef: "occurrence:2026-09-02",
      occurrenceVersion: 1,
    },
    {
      date: "2026-09-03",
      lane: "advancement",
      topicRef: "topic:advancement-followthrough",
      noveltyKey: "novelty:advancement-followthrough",
      outline: "A practical question about consistent followthrough.",
      citationRefs: ["citation:four"],
      occurrenceRef: "occurrence:2026-09-03",
      occurrenceVersion: 1,
    },
    {
      date: "2026-09-04",
      lane: "admissions",
      topicRef: "topic:admissions-questions",
      noveltyKey: "novelty:admissions-questions",
      outline: "A practical question about making room for better questions.",
      citationRefs: ["citation:five"],
      occurrenceRef: "occurrence:2026-09-04",
      occurrenceVersion: 1,
    },
  ],
});

export const createMarketingBoundaryFixtureForContractSuite = (contractSuite, { daily = false } = {}) => {
  const contracts = assertMarketingProgramContractSuite(contractSuite);
  const marketingBindingAnchor = contracts.marketingBindingAnchor;
  const input = {
    version: contracts.policy.version,
    programRef: daily ? "marketing-program:daily:2026-08-31" : "marketing-program:weekly:2026-08-28",
    programRevision: 0,
    now: daily ? "2026-08-31T16:00:00.000Z" : "2026-08-28T16:00:00.000Z",
    goalDate: daily ? "2026-08-31" : "2026-08-28",
    timeZone: contracts.policy.timeZone,
    binding: { ...marketingBindingAnchor },
    weeklyPlan: plan(),
    research: [
      research("citation:one", "A source-backed observation about listening."),
      research("citation:two", "A source-backed observation about clarity."),
      research("citation:three", "A source-backed observation about handoffs."),
      research("citation:four", "A source-backed observation about followthrough."),
      research("citation:five", "A source-backed observation about questions."),
    ],
    history: [{ date: "2026-08-27", lane: "advancement", topicRef: "topic:previous", noveltyKey: "novelty:previous" }],
  };
  if (!daily) return input;
  const planHash = sha256Canonical(input.weeklyPlan);
  return {
    ...input,
    draft: {
      date: input.goalDate,
      draftRevision: 0,
      planRef: input.weeklyPlan.planRef,
      planHash,
      approvalRequestRef: "approval-request:weekly:2026-08-28",
      text: "A cited point is included for review.\n\nI am curious what you think.",
      citationRefs: ["citation:one"],
      claimCitations: [{ sentence: "A cited point is included for review.", citationRefs: ["citation:one"] }],
      notionParentRef: marketingBindingAnchor.notionRootRef,
      schedule: {
        status: "scheduled",
        plannedDate: input.goalDate,
        effectiveDate: input.goalDate,
        movedFromDate: null,
        missedReason: null,
        localTime: "09:00",
        scheduledAt: "2026-08-31T16:00:00.000Z",
        occurrenceRef: "occurrence:2026-08-31",
        occurrenceVersion: 1,
        serverTimeRequestRef: "server-time-request:2026-08-31",
        serverTimeDisposition: "unresolved",
      },
    },
  };
};

export const createMarketingBoundaryFixture = (options) =>
  createMarketingBoundaryFixtureForContractSuite(ceoMarketingProgramContractSuite, options);
