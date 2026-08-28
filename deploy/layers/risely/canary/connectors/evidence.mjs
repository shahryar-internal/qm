import { createHash } from "node:crypto";
import { assertResolvedConnection, canonicalJson, ConnectorError, snapshotJson } from "./types.mjs";

const validOperation = (operation) => typeof operation === "string" && /^[a-z][a-z0-9_.]{1,127}$/.test(operation);

export const normalizeEvidence = (provider, connection, operation, request, content, observedAt = new Date()) => {
  const resolved = assertResolvedConnection(connection, provider);
  if (!validOperation(operation) || !(observedAt instanceof Date) || Number.isNaN(observedAt.valueOf())) {
    throw new ConnectorError("invalid_response");
  }
  let requestSnapshot;
  let contentSnapshot;
  try {
    requestSnapshot = snapshotJson(request);
    contentSnapshot = snapshotJson(content);
  } catch {
    throw new ConnectorError("invalid_response");
  }
  const provenance = {
    provider,
    connectionRef: resolved.connectionRef,
    serverAccountRef: resolved.serverAccountRef,
    principalRef: resolved.principalRef,
    rootResourceRef: resolved.rootResourceRef,
    credentialLeaseRef: resolved.credentialLeaseRef,
    bindingNonce: resolved.bindingNonce,
    operation,
    request: requestSnapshot,
  };
  return Object.freeze({
    ...provenance,
    contentTrust: "external_untrusted",
    observedAt: observedAt.toISOString(),
    content: contentSnapshot,
    evidenceHash: createHash("sha256")
      .update(canonicalJson({ ...provenance, content: contentSnapshot }))
      .digest("hex"),
  });
};
