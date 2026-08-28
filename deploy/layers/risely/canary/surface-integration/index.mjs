import { buildPrivateCeoSurface, buildQmRendererFromSurface } from "../presentation/index.mjs";
import { buildNotionPageTemplateFromSurface } from "../notion-templates/index.mjs";
import { renderPrivateCeoSlackBlockKitFromSurface } from "../slack/index.mjs";

export function composePrivateCeoSurfaces(input) {
  const snapshot = buildPrivateCeoSurface(input);
  return Object.freeze({
    version: 1,
    audience: snapshot.audience,
    artifact: snapshot.artifact,
    status: snapshot.status,
    evidence: snapshot.evidence,
    slack: renderPrivateCeoSlackBlockKitFromSurface(snapshot),
    qm: buildQmRendererFromSurface(snapshot),
    notion: buildNotionPageTemplateFromSurface(snapshot),
    actionless: true,
  });
}
