import { proposalPresentationLabels, proposedEffectTypes } from "./contracts.mjs";
import { initializeRevenueProgramState } from "./state-machine.mjs";
import { fail, snapshotPlainJson } from "./validation.mjs";

export const presentRevenueProgram = (rawProgram) => {
  const state = initializeRevenueProgramState(rawProgram);
  const program = snapshotPlainJson(rawProgram);
  if (Object.keys(proposalPresentationLabels).length !== proposedEffectTypes.length)
    fail("incomplete_presentation_mapping");
  const proposals = program.proposals.map((proposal) => {
    const label = proposalPresentationLabels[proposal.type];
    if (!label) fail("incomplete_presentation_mapping");
    return Object.freeze({
      proposalRef: proposal.proposalRef,
      label,
      subjectRef: proposal.subjectRef,
      providerAccountRef: proposal.providerAccountRef,
      disposition: "Awaiting evaluation and CEO review",
      evidenceCount: proposal.evidenceHashes.length,
      correlationCount: proposal.correlationRefs.length,
    });
  });
  return Object.freeze({
    title: `CEO revenue program · ${program.goalDate}`,
    safetyLabel: "Prospective only · no external action can run",
    safetyDisposition: state.safetyDisposition,
    emailGoal: Object.freeze({
      minimum: program.accounting.email.minimum,
      maximum: program.accounting.email.maximum,
      totalAfterProposal: program.accounting.email.totalAfterProposal,
      shortfall: program.accounting.email.minimumShortfall,
    }),
    sourceStatus: Object.freeze(
      program.sourceHealth.sources.map((source) =>
        Object.freeze({
          source: source.source,
          status: source.status,
          unavailableCode: source.unavailableCode ?? null,
        }),
      ),
    ),
    proposals: Object.freeze(proposals),
  });
};
