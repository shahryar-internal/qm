import { canonicalJson, deepFreeze, sha256Canonical } from "./canonicalize.mjs";
import { validateContract } from "./validation.mjs";

const DERIVED_FIELDS = ["semanticFingerprint", "effectKey", "proposalHash"];

function effectProjection(proposal) {
  return {
    contractType: "action-effect",
    contractVersion: 1,
    principalRef: proposal.actor.principalRef,
    credentialOwnerRef: proposal.actor.credentialOwnerRef,
    capability: proposal.capability,
    capabilityVersion: proposal.capabilityVersion,
    provider: proposal.provider,
    credentialRef: proposal.credentialRef,
    target: proposal.target,
    payload: proposal.payload,
    artifactRefs: proposal.artifactRefs,
  };
}

function semanticProjection(proposal) {
  return {
    contractType: "action-semantic-fingerprint",
    contractVersion: 1,
    principalRef: proposal.actor.principalRef,
    capability: proposal.capability,
    capabilityVersion: proposal.capabilityVersion,
    subjectRef: proposal.subjectRef,
    target: proposal.target,
  };
}

function proposalProjection(proposal) {
  const { proposalHash: _proposalHash, ...projection } = proposal;
  return projection;
}

export function deriveProposalHashes(proposal) {
  const semanticFingerprint = sha256Canonical(semanticProjection(proposal));
  const effectKey = sha256Canonical(effectProjection(proposal));
  const withDerived = { ...proposal, semanticFingerprint, effectKey };
  const proposalHash = sha256Canonical(proposalProjection(withDerived));
  return { semanticFingerprint, effectKey, proposalHash };
}

export function buildActionProposal(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Action proposal input must be an object");
  }
  for (const field of DERIVED_FIELDS) {
    if (Object.hasOwn(input, field)) throw new TypeError(`${field} is derived and must not be supplied`);
  }
  const proposal = JSON.parse(canonicalJson(input));
  const hashes = deriveProposalHashes(proposal);
  const built = { ...proposal, ...hashes };
  validateContract("actionProposal", built);
  return deepFreeze(built);
}

export function verifyActionProposalHashes(proposal) {
  try {
    const snapshot = JSON.parse(canonicalJson(proposal));
    validateContract("actionProposal", snapshot);
    const expected = deriveProposalHashes(snapshot);
    return DERIVED_FIELDS.every((field) => snapshot[field] === expected[field]);
  } catch {
    return false;
  }
}

export function assertActionProposalHashes(proposal) {
  const snapshot = JSON.parse(canonicalJson(proposal));
  validateContract("actionProposal", snapshot);
  const expected = deriveProposalHashes(snapshot);
  if (!DERIVED_FIELDS.every((field) => snapshot[field] === expected[field])) {
    throw new TypeError("Action proposal hashes do not match its content");
  }
  return deepFreeze(snapshot);
}

export function proposalCanonicalJson(proposal) {
  return canonicalJson(assertActionProposalHashes(proposal));
}
