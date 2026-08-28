import { initializeMarketingState } from "./state-machine.mjs";
import { snapshotPlainJson } from "./validation.mjs";

const labels = Object.freeze({ weekly_plan: "Friday weekly marketing plan", daily_draft: "Private CEO daily draft" });
export const presentMarketingProgram = (program) => {
  const state = initializeMarketingState(program);
  const value = snapshotPlainJson(program);
  if (!labels[value.kind]) throw new Error("marketing_program_incomplete_presentation_mapping");
  return Object.freeze({
    title: `${labels[value.kind]} · ${value.goalDate}`,
    safetyLabel: "Prospective only · no Slack, Notion, or social action can run",
    executionDisposition: state.executionDisposition,
    artifact: Object.freeze({
      label: labels[value.kind],
      artifactRef: value.artifact.artifactRef,
      disposition: "Awaiting independent evaluation and CEO review",
      citationCount: value.artifact.citationRefs?.length ?? value.research.length,
      actionlessSlackArtifact: true,
    }),
    schedule: value.artifact.schedule ?? Object.freeze({ status: "planned", plannedDate: value.goalDate }),
    research: Object.freeze(
      value.research.map((item) =>
        Object.freeze({ citationRef: item.citationRef, trust: item.trust, availability: item.availability }),
      ),
    ),
  });
};
