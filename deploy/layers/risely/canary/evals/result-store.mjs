import { assertRuntimeScope } from "../runtime-scope/index.mjs";

const postgresResultStores = new WeakMap();

export function bindPostgresEvaluationResultStore(value, runtimeScope, isActive) {
  const scope = assertRuntimeScope(runtimeScope);
  if (
    !value ||
    typeof value !== "object" ||
    !Object.isFrozen(value) ||
    typeof value.persistAuthorityEvaluation !== "function" ||
    typeof value.appendReplayTombstone !== "function" ||
    typeof value.readRelease !== "function" ||
    typeof isActive !== "function"
  ) {
    throw new TypeError("A frozen PostgreSQL evaluation result store is required");
  }
  postgresResultStores.set(value, Object.freeze({ scope, isActive }));
  return value;
}

export function assertEvaluationResultStore(value, runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  const state = postgresResultStores.get(value);
  if (
    !state ||
    state.scope !== scope ||
    state.isActive() !== true ||
    value.profileRef !== scope.profileRef ||
    value.profileSha256 !== scope.profileSha256 ||
    !Object.isFrozen(value)
  ) {
    throw new TypeError("An initialized PostgreSQL evaluation result store is required");
  }
  return value;
}
