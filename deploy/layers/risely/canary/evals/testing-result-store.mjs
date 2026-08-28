import { types } from "node:util";
import { assertRuntimeScope } from "../runtime-scope/index.mjs";

const syntheticStores = new WeakMap();

export function createInertEvaluationResultStoreForTesting(runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  const records = {
    candidates: [],
    judgeResults: [],
    releases: [],
    replayTombstones: [],
  };
  const port = Object.freeze({
    durability: "synthetic_inert_memory",
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    persistAuthorityEvaluation(value) {
      if (!value || typeof value !== "object" || types.isProxy(value)) {
        throw new TypeError("Synthetic evaluation result set is invalid");
      }
      records.candidates.push(value.candidate);
      records.judgeResults.push(
        ...value.judgeResults.map((result) => ({ candidateId: value.candidate.runRef, result })),
      );
      records.releases.push({ candidateId: value.candidate.runRef, release: value.release });
      return Object.freeze({
        candidateId: value.candidate.runRef,
        releaseId: `evaluation-release:${value.release.releaseSha256}`,
      });
    },
    appendReplayTombstone(value) {
      records.replayTombstones.push(value);
      return value;
    },
    readRelease(releaseId) {
      return (
        records.releases.find((entry) => `evaluation-release:${entry.release.releaseSha256}` === releaseId)?.release ??
        null
      );
    },
  });
  syntheticStores.set(port, Object.freeze({ scope, records }));
  return Object.freeze({ port, records });
}

export function assertInertEvaluationResultStoreForTesting(value, runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  const state = syntheticStores.get(value);
  if (
    state?.scope !== scope ||
    value.profileRef !== scope.profileRef ||
    value.profileSha256 !== scope.profileSha256 ||
    !Object.isFrozen(value)
  ) {
    throw new TypeError("An inert synthetic evaluation result store is required");
  }
  return value;
}
