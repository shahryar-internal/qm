import { isStrongSigningSecret } from "../auth/source-auth.ts";
import { signedRequestHeaders } from "../auth/source-auth-sign.ts";
import {
  snapshotPrivateTurnObservation,
  type PrivateTurnObservation,
  type PrivateTurnObservationSink,
} from "./private-turn-observer.ts";

interface SignedPrivateTurnObserverOptions {
  endpoint: string;
  signingSecret: string;
  fetch?: typeof fetch;
  now?: () => number;
}

export function createSignedPrivateTurnObserver(options: SignedPrivateTurnObserverOptions): PrivateTurnObservationSink {
  let endpoint: URL;
  try {
    endpoint = new URL(options.endpoint);
  } catch {
    throw new TypeError("private turn observer endpoint must be an HTTPS URL");
  }
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.hash ||
    endpoint.hostname.endsWith(".")
  ) {
    throw new TypeError("private turn observer endpoint must be an HTTPS URL without credentials or a fragment");
  }
  if (!isStrongSigningSecret(options.signingSecret)) {
    throw new TypeError("private turn observer signing secret must contain at least 32 characters");
  }
  const request = options.fetch ?? fetch;
  const now = options.now ?? Date.now;
  const pathWithQuery = `${endpoint.pathname}${endpoint.search}`;
  return Object.freeze({
    async observe(input: PrivateTurnObservation) {
      const observation = snapshotPrivateTurnObservation(input);
      const body = JSON.stringify(observation);
      const headers = signedRequestHeaders(
        options.signingSecret,
        "POST",
        pathWithQuery,
        body,
        { "content-type": "application/json", "x-idempotency-key": observation.eventRef },
        Math.floor(now() / 1_000),
      );
      const response = await request(endpoint, { method: "POST", headers, body, redirect: "error" });
      await response.body?.cancel().catch(() => undefined);
      if (response.status === 208 || response.status === 409) return "duplicate";
      if (response.status === 200 || response.status === 201 || response.status === 202 || response.status === 204) {
        return "accepted";
      }
      return "unconfirmed";
    },
  });
}
