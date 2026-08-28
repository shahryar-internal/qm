import { createInertEvaluationAuthorityForTesting } from "./release-authority.mjs";
import { assertInertEvaluationResultStoreForTesting } from "./testing-result-store.mjs";

export {
  assertInertEvaluationResultStoreForTesting,
  createInertEvaluationResultStoreForTesting,
} from "./testing-result-store.mjs";

export function createInertProviderFreeEvaluationAuthorityForTesting(value) {
  return createInertEvaluationAuthorityForTesting(value, assertInertEvaluationResultStoreForTesting);
}
