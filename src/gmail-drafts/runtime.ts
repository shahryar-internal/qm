import type { GmailDraftPrivateOwnerDmPublisherPort, GmailDraftPrivateReviewRoutePort } from "./card.ts";
import type { GmailDraftExecutionStore } from "./contracts.ts";
import type {
  GmailDraftPrivateApprovalAdmissionStore,
  GmailDraftPrivateIntentCipherPort,
  GmailDraftPostgresStartupDoctorResult,
  GmailDraftSealedApprovedIntent,
  GmailDraftVerifiedOwnerSlackBinding,
  GmailDraftVerifiedThreadSource,
} from "./postgres-store.ts";
import { gmailDraftPrivateCredentialReadiness, type GmailDraftPrivateCredentialPort } from "./provider-client.ts";

export interface GmailDraftPrivateApprovalSignerPort {
  boundary: "private_gmail_draft_owner_dm_approval_signer";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  verifyCurrentClickAndSeal(input: unknown): Promise<Readonly<{
    sealedIntent: GmailDraftSealedApprovedIntent;
    ownerSlackBinding: GmailDraftVerifiedOwnerSlackBinding;
  }> | null>;
}

export interface GmailDraftPrivateThreadSourceVerifierPort {
  boundary: "private_gmail_draft_thread_source_verifier";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  verifyAndNormalize(input: unknown): Promise<GmailDraftVerifiedThreadSource | null>;
}

export interface GmailDraftPrivateRuntimeDependencies {
  approvalSigner: GmailDraftPrivateApprovalSignerPort;
  threadSourceVerifier: GmailDraftPrivateThreadSourceVerifierPort;
  approvalAdmission: GmailDraftPrivateApprovalAdmissionStore;
  credentials: GmailDraftPrivateCredentialPort;
  intentCipher: GmailDraftPrivateIntentCipherPort;
  ownerDmPublisher: GmailDraftPrivateOwnerDmPublisherPort;
  reviewRoute: GmailDraftPrivateReviewRoutePort;
  executionStore: GmailDraftExecutionStore & {
    startupDoctor(): Promise<GmailDraftPostgresStartupDoctorResult>;
  };
}

type GmailDraftRuntimeReadiness = Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function runtimeReadiness(value: unknown): GmailDraftRuntimeReadiness {
  if (exactObject(value, ["ready"]) && value.ready === true) return { ready: true };
  if (
    exactObject(value, ["ready", "reason"]) &&
    value.ready === false &&
    typeof value.reason === "string" &&
    value.reason.length > 0 &&
    value.reason.length <= 512
  ) {
    return { ready: false, reason: value.reason };
  }
  return { ready: false, reason: "invalid readiness result" };
}

function postgresDoctorAttestation(
  value: unknown,
  runtimeRole: "qm_gmail_draft_admission" | "qm_gmail_draft_broker",
): GmailDraftPostgresStartupDoctorResult {
  if (
    exactObject(value, ["provider", "providerMajorVersion", "ready", "runtimeRole", "schema"]) &&
    value.ready === true &&
    value.provider === "postgresql" &&
    value.providerMajorVersion === 16 &&
    value.schema === "gmail_draft_broker" &&
    value.runtimeRole === runtimeRole
  ) {
    return Object.freeze({
      ready: true,
      provider: "postgresql",
      providerMajorVersion: 16,
      schema: "gmail_draft_broker",
      runtimeRole,
    });
  }
  if (
    exactObject(value, ["ready", "reason"]) &&
    value.ready === false &&
    typeof value.reason === "string" &&
    value.reason.length > 0 &&
    value.reason.length <= 512
  ) {
    return { ready: false, reason: value.reason };
  }
  return { ready: false, reason: "invalid database startup doctor attestation" };
}

export const GMAIL_DRAFT_BROKER_MISSING_PRIVATE_PORTS = Object.freeze([
  "private_gmail_draft_owner_dm_approval_signer",
  "private_gmail_draft_thread_source_verifier",
  "private_verified_slack_owner_dm_approval_store",
  "private_gmail_oauth_connection_credential_adapter",
  "private_gmail_draft_intent_cipher",
  "private_gmail_draft_owner_dm_publisher",
  "private_gmail_draft_review_route",
] as const);

export function gmailDraftBrokerProductionReadiness(
  dependencies?: Partial<GmailDraftPrivateRuntimeDependencies>,
):
  | Readonly<{ ready: true; dependencies: GmailDraftPrivateRuntimeDependencies }>
  | Readonly<{ ready: false; reason: string }> {
  if (!dependencies) return { ready: false, reason: GMAIL_DRAFT_BROKER_MISSING_PRIVATE_PORTS.join(",") };
  let entries;
  try {
    entries = [
      ["approvalSigner", dependencies.approvalSigner, "private_gmail_draft_owner_dm_approval_signer"],
      ["threadSourceVerifier", dependencies.threadSourceVerifier, "private_gmail_draft_thread_source_verifier"],
      ["approvalAdmission", dependencies.approvalAdmission, "private_verified_slack_owner_dm_approval_store"],
      ["credentials", dependencies.credentials, "private_gmail_draft_broker_only"],
      ["intentCipher", dependencies.intentCipher, "private_gmail_draft_intent_cipher"],
      ["ownerDmPublisher", dependencies.ownerDmPublisher, "private_gmail_draft_owner_dm_publisher"],
      ["reviewRoute", dependencies.reviewRoute, "private_gmail_draft_review_route"],
    ] as const;
  } catch {
    return { ready: false, reason: "runtime dependencies are invalid" };
  }
  for (const [name, dependency, boundary] of entries) {
    try {
      if (!dependency || dependency.boundary !== boundary) return { ready: false, reason: `missing:${name}` };
      const ready = runtimeReadiness(
        name === "credentials"
          ? gmailDraftPrivateCredentialReadiness(dependency as GmailDraftPrivateCredentialPort)
          : dependency.readiness(),
      );
      if (!ready.ready) return { ready: false, reason: `${name}:${ready.reason}` };
    } catch {
      return { ready: false, reason: `${name}:readiness failed` };
    }
  }
  try {
    if (!dependencies.executionStore || typeof dependencies.executionStore.startupDoctor !== "function") {
      return { ready: false, reason: "missing:executionStore" };
    }
    const executionStore = runtimeReadiness(dependencies.executionStore.readiness());
    if (!executionStore.ready) return { ready: false, reason: `executionStore:${executionStore.reason}` };
  } catch {
    return { ready: false, reason: "executionStore:readiness failed" };
  }
  return { ready: true, dependencies: dependencies as GmailDraftPrivateRuntimeDependencies };
}

export async function gmailDraftBrokerStartupDoctor(
  dependencies?: Partial<GmailDraftPrivateRuntimeDependencies>,
): Promise<
  | Readonly<{ ready: true; dependencies: GmailDraftPrivateRuntimeDependencies }>
  | Readonly<{ ready: false; reason: string }>
> {
  let approvalAdmission: GmailDraftPrivateApprovalAdmissionStore | undefined;
  let executionStore: GmailDraftPrivateRuntimeDependencies["executionStore"] | undefined;
  let admissionDoctor: GmailDraftPrivateApprovalAdmissionStore["startupDoctor"] | undefined;
  let executionDoctor: GmailDraftPrivateRuntimeDependencies["executionStore"]["startupDoctor"] | undefined;
  try {
    approvalAdmission = dependencies?.approvalAdmission;
    executionStore = dependencies?.executionStore;
    admissionDoctor = approvalAdmission?.startupDoctor;
    executionDoctor = executionStore?.startupDoctor;
  } catch {
    return { ready: false, reason: "database startup doctor dependencies are invalid" };
  }
  if (!approvalAdmission || typeof admissionDoctor !== "function") {
    return { ready: false, reason: "missing:approvalAdmission.startupDoctor" };
  }
  if (!executionStore || typeof executionDoctor !== "function") {
    return { ready: false, reason: "missing:executionStore.startupDoctor" };
  }
  let admission: GmailDraftPostgresStartupDoctorResult;
  try {
    admission = postgresDoctorAttestation(await admissionDoctor.call(approvalAdmission), "qm_gmail_draft_admission");
  } catch {
    admission = { ready: false, reason: "startup doctor failed" };
  }
  let execution: GmailDraftPostgresStartupDoctorResult;
  try {
    execution = postgresDoctorAttestation(await executionDoctor.call(executionStore), "qm_gmail_draft_broker");
  } catch {
    execution = { ready: false, reason: "startup doctor failed" };
  }
  if (!admission.ready) return { ready: false, reason: `approvalAdmission:${admission.reason}` };
  if (!execution.ready) return { ready: false, reason: `executionStore:${execution.reason}` };
  return gmailDraftBrokerProductionReadiness(dependencies);
}

export function assertGmailDraftBrokerProductionReady(
  dependencies?: Partial<GmailDraftPrivateRuntimeDependencies>,
): GmailDraftPrivateRuntimeDependencies {
  const ready = gmailDraftBrokerProductionReadiness(dependencies);
  if (!ready.ready) throw new Error(`gmail draft broker is disabled: ${ready.reason}`);
  return ready.dependencies;
}
