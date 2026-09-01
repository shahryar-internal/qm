import type {
  BackgroundJobKmsGeneration,
  BackgroundJobNativeDependency,
  BackgroundJobNativeDependencyRegistry,
} from "./runtime.ts";
import type { BackgroundJobDeploymentProfile, BackgroundJobRenderOnlySender } from "./types.ts";

export interface BackgroundJobProductionComposition {
  registry: BackgroundJobNativeDependencyRegistry;
  sender: BackgroundJobRenderOnlySender;
  receiptStoreName: string;
  approvalStoreName: string;
  profiles: () => readonly Readonly<BackgroundJobDeploymentProfile>[];
}

interface BackgroundJobAuthorityDependency {
  active: Readonly<BackgroundJobKmsGeneration>;
  next?: Readonly<BackgroundJobKmsGeneration>;
  kms?: import("./kms-signer.ts").BackgroundJobKmsSignerDependencies;
}

export interface BackgroundJobProductionDependencies {
  adapters?: Readonly<Record<string, Readonly<BackgroundJobNativeDependency>>>;
  resolveAuthority?: (
    profile: Readonly<BackgroundJobDeploymentProfile>,
  ) => Readonly<BackgroundJobAuthorityDependency> | undefined;
  sender?: BackgroundJobRenderOnlySender;
  receiptStoreName?: string;
  approvalStoreName?: string;
  profiles?: () => readonly Readonly<BackgroundJobDeploymentProfile>[];
}

const unavailableSender: BackgroundJobRenderOnlySender = Object.freeze({
  transport: "slack_first_party_render_only",
  rawFallback: "forbidden",
  idempotency: "durable_delivery_key",
  readiness: () => Object.freeze({ ready: false as const }),
  send: async () => {
    throw new Error("background job render-only sender is unavailable");
  },
});

export function createBackgroundJobProductionComposition(
  dependencies: Readonly<BackgroundJobProductionDependencies> = {},
): Readonly<BackgroundJobProductionComposition> {
  const adapters = Object.freeze({ ...dependencies.adapters });
  const registry: BackgroundJobNativeDependencyRegistry = Object.freeze({
    readiness: () => Object.freeze({ ready: true as const }),
    resolveAdapter: (name: string) => adapters[name],
    resolveAuthority: (profile: Readonly<BackgroundJobDeploymentProfile>) => dependencies.resolveAuthority?.(profile),
  });
  return Object.freeze({
    registry,
    sender: dependencies.sender ?? unavailableSender,
    receiptStoreName: dependencies.receiptStoreName ?? "background_job_records",
    approvalStoreName: dependencies.approvalStoreName ?? "background_job_approval_ledger",
    profiles: dependencies.profiles ?? (() => Object.freeze([])),
  });
}
