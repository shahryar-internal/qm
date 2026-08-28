import { assertPrivateCeoSurface, buildPrivateCeoSurface } from "../presentation/index.mjs";

export const privateCeoNotionBinding = Object.freeze({
  parentRef: "notion:ceo-private-root-v1",
  audienceRef: "audience:ceo-private",
  scope: "private_ceo",
  providerInvocationAllowed: false,
});

const fixedSections = Object.freeze([
  Object.freeze({ key: "executive_brief", label: "Executive brief" }),
  Object.freeze({ key: "status_and_trust", label: "Status and trust" }),
  Object.freeze({ key: "review_details", label: "Review details" }),
  Object.freeze({ key: "evidence", label: "Evidence" }),
  Object.freeze({ key: "cross_surface_record", label: "Cross-surface record" }),
]);

export function buildNotionPageTemplateFromSurface(snapshot) {
  const surface = assertPrivateCeoSurface(snapshot);
  return Object.freeze({
    version: 1,
    type: "private_ceo_notion_page_proposal",
    templateRef: "risely.private-ceo.work-item.v1",
    binding: privateCeoNotionBinding,
    audience: surface.audience,
    page: Object.freeze({
      title: surface.artifact.title,
      artifactRef: surface.artifact.artifactRef,
      revision: surface.artifact.revision,
      kind: surface.artifact.kind,
      state: surface.status.state,
      presentationCode: surface.artifact.presentationCode,
    }),
    sections: Object.freeze([
      Object.freeze({
        ...fixedSections[0],
        items: Object.freeze([
          Object.freeze({
            label: "Summary",
            value: surface.artifact.summary,
            trust: "generated_evidence_cited_update",
          }),
        ]),
      }),
      Object.freeze({
        ...fixedSections[1],
        items: Object.freeze([
          Object.freeze({ label: "Status", value: surface.status.label, trust: "verified_source" }),
          Object.freeze({
            label: "Trust boundary",
            value: "Private CEO review only. No external action can run.",
            trust: "verified_source",
          }),
          Object.freeze({ label: "Detail", value: surface.status.detail, trust: "generated_evidence_cited_update" }),
        ]),
      }),
      Object.freeze({
        ...fixedSections[2],
        items: Object.freeze([
          Object.freeze({ label: "Evidence count", value: String(surface.evidence.length), trust: "verified_source" }),
          Object.freeze({
            label: "Detail view",
            value: "Future authenticated artifact view.",
            trust: "verified_source",
          }),
        ]),
      }),
      Object.freeze({ ...fixedSections[3], items: surface.evidence }),
      Object.freeze({
        ...fixedSections[4],
        items: Object.freeze([
          Object.freeze({ label: "Artifact", value: surface.artifact.artifactRef, trust: "verified_source" }),
          Object.freeze({ label: "Revision", value: surface.artifact.revision, trust: "verified_source" }),
          Object.freeze({ label: "Stable links", value: String(surface.links.length), trust: "verified_source" }),
        ]),
      }),
    ]),
    actionless: true,
  });
}

export function buildNotionPageTemplate(input) {
  return buildNotionPageTemplateFromSurface(buildPrivateCeoSurface(input));
}

export const notionTemplateKinds = Object.freeze(["private_ceo_work_item"]);
