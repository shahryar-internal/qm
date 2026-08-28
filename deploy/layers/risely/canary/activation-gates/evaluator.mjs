import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrictJson, StrictJsonError } from "./strict-json.mjs";

export const bundledManifestSha256 = "5a9416a7cbab991ad639ef37db58bfec6e8973fa5d8bfb432747f7cebbbf6310";

const layerRoot = fileURLToPath(new URL("../../", import.meta.url));
const bundledManifestSegments = Object.freeze(["canary", "activation-gates", "manifest.json"]);
const sha256Pattern = /^[0-9a-f]{64}$/;
const identifierPattern = /^[a-z][a-z0-9_]{2,63}$/;
const maximumEvidenceBytes = 262_144;
const maximumManifestBytes = 131_072;
const exactManifestKeys = Object.freeze([
  "schemaVersion",
  "manifestId",
  "assessmentMode",
  "semanticContracts",
  "externalRequirements",
  "evidence",
  "gates",
]);
const exactEvidenceKeys = Object.freeze(["id", "path", "kind", "sha256", "maxBytes"]);
const exactGateKeys = Object.freeze(["id", "dependsOn", "evidence", "blockers"]);
const exactNotionContractKeys = Object.freeze(["parentRef", "audienceRef", "scope", "providerInvocationAllowed"]);
const exactExternalRequirementKeys = Object.freeze([
  "id",
  "gateId",
  "state",
  "evidenceClass",
  "offlineEvidenceCanSatisfy",
  "blocker",
]);

const closedEvidence = Object.freeze([
  Object.freeze({
    id: "shadow_v6_source",
    path: "canary/acceptance-shadow/provider-free-v6.mjs",
    kind: "source",
    sha256: "f0339a808d0b24830292a441212b27cc4abaf20a1f6db787d3946e8d893c67d4",
  }),
  Object.freeze({
    id: "shadow_v6_test",
    path: "test/shared-contracts/shared-contracts.test.mjs",
    kind: "test",
    sha256: "51c324a568f5327a495a926dd839539dc1aa3dd3b39ecf5552b8e1a39dc0ca4a",
  }),
  Object.freeze({
    id: "qm_shadow_ingress_source",
    path: "canary/qm-shadow-ingress/index.mjs",
    kind: "source",
    sha256: "5763ef739beb7f6164e6258001456ef0f671e2d94a7a82f06f9b8f2385eefd3a",
  }),
  Object.freeze({
    id: "qm_shadow_ingress_test",
    path: "test/qm-shadow-ingress/qm-shadow-ingress.test.mjs",
    kind: "test",
    sha256: "35605f1144162b8293456e6c0696d047e6939747bd379246c56064a9ec3b9457",
  }),
  Object.freeze({
    id: "qm_shadow_ingress_readme",
    path: "canary/qm-shadow-ingress/README.md",
    kind: "source",
    sha256: "211c8bfc58048cd4ea568d458b393bcc0651849a33fd3668eb95931a0e46cbbb",
  }),
  Object.freeze({
    id: "mercury_invoicing_source",
    path: "canary/mercury-invoicing/index.mjs",
    kind: "source",
    sha256: "687be4d84fe265c5322174ec662c2dc28fe1ef8752368dd70987e414481d4123",
  }),
  Object.freeze({
    id: "mercury_invoicing_validation_source",
    path: "canary/mercury-invoicing/validation.mjs",
    kind: "source",
    sha256: "2d543969e3865c061d4154ef261bed9f5b5f895ade147d913d3aa3e2f3efafa2",
  }),
  Object.freeze({
    id: "mercury_invoicing_test",
    path: "test/mercury-invoicing/mercury-invoicing.test.mjs",
    kind: "test",
    sha256: "9cd550943244fb5be622a0ceb6859fe584d013606fc080c70435b55921015d66",
  }),
  Object.freeze({
    id: "mercury_invoicing_cli_integration_test",
    path: "test/mercury-invoicing/cli.integration.test.mjs",
    kind: "test",
    sha256: "213ae058a5f7f94e498e6d7816c47498676716504b2f7090a7449a226d993b2f",
  }),
  Object.freeze({
    id: "mercury_invoicing_readme",
    path: "canary/mercury-invoicing/README.md",
    kind: "source",
    sha256: "45e77bbf948a1b1b0e3742071455952ed69cdd1a251d70504d152df358454982",
  }),
  Object.freeze({
    id: "postgres_store_source",
    path: "canary/service/ceo-canary/src/postgres-store.mjs",
    kind: "source",
    sha256: "d5caa6a991ef8f48251cb66c1206f8fb8146fe2946667fd3d3697c07463f653b",
  }),
  Object.freeze({
    id: "postgres_evaluation_writer_source",
    path: "canary/service/ceo-canary/src/evaluation-writer.mjs",
    kind: "source",
    sha256: "7e3e1fb6cb4cc58f15c283ee61764e04f71b749930235f63fda14e732f47d351",
  }),
  Object.freeze({
    id: "postgres_database_security_source",
    path: "canary/service/ceo-canary/src/database-security.mjs",
    kind: "source",
    sha256: "5505cf452f69ed09073b064a22a3ec32f046bba2e46391923ca75ae4e6de253f",
  }),
  Object.freeze({
    id: "postgres_database_boundary_source",
    path: "canary/service/ceo-canary/src/index.mjs",
    kind: "source",
    sha256: "8478f4c17b36f388d007422e75464b416ccf93c0d30d4266a2ab172a48f6c4e1",
  }),
  Object.freeze({
    id: "postgres_schema_source",
    path: "canary/service/ceo-canary/src/schema.mjs",
    kind: "source",
    sha256: "9e8278f1967f743e8cd3ffdf4dc724e905cc4dc9515fa7e89d69648287bec710",
  }),
  Object.freeze({
    id: "postgres_catalog_authority_source",
    path: "canary/service/ceo-canary/src/catalog-authority-v8.mjs",
    kind: "source",
    sha256: "a0b1d9259d6f72146aaf5bce5d30bc45762f9cb8bdc48bfa45afd980b2d92459",
  }),
  Object.freeze({
    id: "postgres_bootstrap_source",
    path: "canary/service/ceo-canary/migrations/bootstrap.sql",
    kind: "source",
    sha256: "4d84811bca745f4a5e8c43caeb23a513432ae7514e481838e9354ee7eb7ce71a",
  }),
  Object.freeze({
    id: "postgres_bootstrap_test",
    path: "test/ceo-canary/bootstrap.pg16.integration.test.mjs",
    kind: "test",
    sha256: "4c1e5c018168644c611ba2649ba979e6b8f07b956bfcd77c62c4a05676937b8d",
  }),
  Object.freeze({
    id: "postgres_db_operator_source",
    path: "canary/service/ceo-canary/src/db-operator.mjs",
    kind: "source",
    sha256: "9ca869be46a8a6b3b01b0ba80e5e5067a1c43666e28ddf2ca68f64ea432e775e",
  }),
  Object.freeze({
    id: "postgres_db_operator_bootstrap_source",
    path: "canary/service/ceo-canary/src/db-operator-bootstrap-sql.mjs",
    kind: "source",
    sha256: "5bd1059b1bbace699afd0b2ea69e3db288cc71208bb38c068ef5e5789000bcba",
  }),
  Object.freeze({
    id: "postgres_migrate_source",
    path: "canary/service/ceo-canary/src/migrate.mjs",
    kind: "source",
    sha256: "062fa7de10e8a7f341370e411b19be651f6344abc7e3bd800d7a10337af7f251",
  }),
  Object.freeze({
    id: "postgres_credential_provisioner_source",
    path: "canary/service/ceo-canary/src/provision-credentials.mjs",
    kind: "source",
    sha256: "bbef16478bd25ed0cb93c833b99cbe4b650cf730874ade0a2e4032baf3573180",
  }),
  Object.freeze({
    id: "postgres_credential_test",
    path: "test/ceo-canary/credential-provisioning.test.mjs",
    kind: "test",
    sha256: "2dfc150217099c5cea8f5a4a45b8cb66895cb503b0fc2d7198f2aecf3569ba18",
  }),
  Object.freeze({
    id: "postgres_lifecycle_test",
    path: "test/ceo-canary/lifecycle.pg16.integration.test.mjs",
    kind: "test",
    sha256: "9b17218cfaea4802c92501fa3beffc2f26d03719f3d808529e38f3d98de37b69",
  }),
  Object.freeze({
    id: "postgres_retention_source",
    path: "canary/service/ceo-canary/src/retention.mjs",
    kind: "source",
    sha256: "a5db608cfcef00b89d28b7f104e9b91ca8a503594c2e2317ebdf163dff19aad1",
  }),
  Object.freeze({
    id: "ceo_canary_security_doc",
    path: "canary/service/ceo-canary/SECURITY.md",
    kind: "source",
    sha256: "76184af37699923ec9790ac2eef3bf688b7f88b820ab9a89ef380dbf7f7f0306",
  }),
  Object.freeze({
    id: "ceo_canary_migration_runbook",
    path: "canary/service/ceo-canary/migrations/RUNBOOK.md",
    kind: "source",
    sha256: "517dc6fdfe39a217edcde9b7431769fb43a839238fba38d81d7d7c1b3f3c3a74",
  }),
  Object.freeze({
    id: "postgres_infra_host_source",
    path: "infra/outputs.tf",
    kind: "source",
    sha256: "9b612ea5bc5de3899ad278143ba10008759627ee7f2037e9b707a3e056bb2e24",
  }),
  Object.freeze({
    id: "ceo_canary_task_contract_data",
    path: "canary/deployment/ceo-canary-task-contract.json",
    kind: "source",
    sha256: "cb606898c89a02875f699671db6b492c766124a7bbd21246d332333161d03f3a",
  }),
  Object.freeze({
    id: "ceo_canary_task_renderer_source",
    path: "canary/deployment/task-definition.mjs",
    kind: "source",
    sha256: "99fcc85a7eb947b64ea12c107e49cd53270c63edfedc2d333bbd70b066189690",
  }),
  Object.freeze({
    id: "ceo_canary_task_sealed_provenance_source",
    path: "canary/deployment/sealed-provenance.mjs",
    kind: "source",
    sha256: "a6ee79a1a3eae4c09c5535d72876129c590f4d8cd8e54b3a5fdde94633375bc4",
  }),
  Object.freeze({
    id: "ceo_canary_task_infra_source",
    path: "infra/ceo-canary.tf",
    kind: "source",
    sha256: "77dbf53c26db46f2421fa89ebb665922917a7b16c360e41a6b6434e75a28e8c9",
  }),
  Object.freeze({
    id: "ceo_canary_infra_main_hash_only",
    path: "infra/main.tf",
    kind: "source",
    sha256: "de2f346d3f7b6c4b0e32edbd64d60d100c3201293051d4a10143b907a258aa11",
  }),
  Object.freeze({
    id: "ceo_canary_tfvars_hash_only",
    path: "infra/terraform.tfvars",
    kind: "source",
    sha256: "34ccef397970ee46fb95c30f3ada7873110a542978b9a6279309849f2e326507",
  }),
  Object.freeze({
    id: "ceo_canary_terraform_versions_hash_only",
    path: "infra/versions.tf",
    kind: "source",
    sha256: "08c70acd458a956374d2b79b0dcb9296ad33a36c5fd45399485376b5db9f1d70",
  }),
  Object.freeze({
    id: "ceo_canary_terraform_lock_hash_only",
    path: "infra/.terraform.lock.hcl",
    kind: "source",
    sha256: "e47df301e05bb8dd5ae1fb572f2090140891f49b1b2a642fb6f0adf886bac01e",
  }),
  Object.freeze({
    id: "ceo_canary_task_variables_source",
    path: "infra/variables.tf",
    kind: "source",
    sha256: "cc9c44eb7df6b13010b352abb323e4497311f073354b55b9fdf63b1755fab9e3",
  }),
  Object.freeze({
    id: "ceo_canary_task_test",
    path: "test/ceo-canary/task-definition.test.mjs",
    kind: "test",
    sha256: "0f36564e702d3b1c8d4b2b8a735112eba612f34050913ae2dedca0f74731c481",
  }),
  Object.freeze({
    id: "ceo_canary_task_runbook",
    path: "canary/deployment/RUNBOOK.md",
    kind: "source",
    sha256: "e8a6d818cd1c6360f161d28f56213a3f086747600365bb13100160e9409c073e",
  }),
  Object.freeze({
    id: "ceo_canary_db_operator_contract_data",
    path: "canary/deployment/ceo-canary-db-operator-contract.json",
    kind: "source",
    sha256: "e7798c2df0db35f39d59a1f27f0be5b26d1684cf1a54dff96c8a0492d34c1acd",
  }),
  Object.freeze({
    id: "ceo_canary_db_operator_infra_source",
    path: "infra/ceo-canary-db-operator.tf",
    kind: "source",
    sha256: "0f44adedf4a703531eb0c0808db25ca7336a19f3872f120a939b15f21f9ad76c",
  }),
  Object.freeze({
    id: "ceo_canary_db_operator_test",
    path: "test/ceo-canary/db-operator.test.mjs",
    kind: "test",
    sha256: "41bc75458ac8e766debdabde275faf5600659b917af14368f48b09b4d290a843",
  }),
  Object.freeze({
    id: "ceo_canary_db_operator_runbook",
    path: "canary/deployment/DB-OPERATOR-RUNBOOK.md",
    kind: "source",
    sha256: "255ece2f37f53ec8ae26298aaa8e6d3e2d5ce0ad953049bd9fe99c080c4a1a7f",
  }),
  Object.freeze({
    id: "postgres_sentinel_test",
    path: "test/ceo-canary/postgres.integration.test.mjs",
    kind: "test",
    sha256: "2101f0ea2c08b14f1b2642ae39a54fe483b79cda711fe3ec18b5073ae08c349c",
  }),
  Object.freeze({
    id: "postgres_dockerfile_source",
    path: "canary/service/ceo-canary/Dockerfile",
    kind: "source",
    sha256: "de03832b224c5f6c21d1e553de08cc18235892591cb0f1da3c738e25c0d6ae24",
  }),
  Object.freeze({
    id: "postgres_runtime_dockerfile_source",
    path: "canary/service/ceo-canary/Dockerfile.runtime",
    kind: "source",
    sha256: "bb7f273c7d6f6a529a4dcf99f76420cde877b921710b203a2d962f2d719eb173",
  }),
  Object.freeze({
    id: "postgres_container_test",
    path: "test/ceo-canary/container.integration.test.mjs",
    kind: "test",
    sha256: "49088b80c8b95e016d5a173572cd4e8670341b4f49473637bf4cd35ff6c16712",
  }),
  Object.freeze({
    id: "secret_boundary_source",
    path: "canary/service/ceo-canary/src/auth.mjs",
    kind: "source",
    sha256: "bfcf5814fcb27aa55a2c1c645d856e099337678b29479899d828a7a67b9fda7d",
  }),
  Object.freeze({
    id: "secret_boundary_test",
    path: "test/ceo-canary/security-contract.test.mjs",
    kind: "test",
    sha256: "5ae4831c862ef78ed44ad94d88f5d638a5f01008d6169cf7badc13f61bf6d6e9",
  }),
  Object.freeze({
    id: "deployment_profile_contract_source",
    path: "canary/deployment-profiles/contract.mjs",
    kind: "source",
    sha256: "b84b10d6cc7278bcd3bbeb392e036ccb2852871930bd00e4064c4f1490290332",
  }),
  Object.freeze({
    id: "deployment_profile_registry_source",
    path: "canary/deployment-profiles/index.mjs",
    kind: "source",
    sha256: "478e5b3ab9063f3f7a23d27867b9e7375ae9ec1d2c64e042eebe3092e2dbbd32",
  }),
  Object.freeze({
    id: "deployment_profile_synthetic_fixture",
    path: "canary/deployment-profiles/testing.mjs",
    kind: "test",
    sha256: "e2debd2bf6c5a491e6d4cf346be42f6806c289c48c368786cedf091588170171",
  }),
  Object.freeze({
    id: "runtime_scope_source",
    path: "canary/runtime-scope/index.mjs",
    kind: "source",
    sha256: "2d8ebdafdca4abe0fa22c9b6f0f6584ec7ca4f066646927940819a1f6aa0f957",
  }),
  Object.freeze({
    id: "deployment_profile_registry_test",
    path: "test/deployment-profiles/deployment-profiles.test.mjs",
    kind: "test",
    sha256: "9dfe973d489aeb9032c17689ada5382b261ddc93038e53f3404d6398015c9c14",
  }),
  Object.freeze({
    id: "google_broker_source",
    path: "canary/google-broker/contracts.mjs",
    kind: "source",
    sha256: "d2bfaa82566509be9a5d9067cca0e136ace5e6a03115e05b683a25f1a91aba47",
  }),
  Object.freeze({
    id: "google_broker_test",
    path: "test/google-broker/static-surface.test.mjs",
    kind: "test",
    sha256: "6923c0693084ef83e7fe0dbc387b3636f45d2e5f6a69456a93b296cc00b01051",
  }),
  Object.freeze({
    id: "provider_effect_policy_source",
    path: "canary/deployment-profiles/provider-effect-policy.mjs",
    kind: "source",
    sha256: "88fc7a2c21fa499b7805ce11e6d254a692dc5aa06a14da8a68d44af46a4d3128",
  }),
  Object.freeze({
    id: "provider_effect_contract_source",
    path: "canary/provider-effects/index.mjs",
    kind: "source",
    sha256: "c557751d468870d7408b8f5439873c0a557f072a17e9ef49fa1a4730a6c19a1b",
  }),
  Object.freeze({
    id: "provider_effect_shared_validation_source",
    path: "canary/contracts/validation.mjs",
    kind: "source",
    sha256: "b61dbb506a34134a0231ab855bf31aaba78bdc03632a907c8dfd78fe9e0d7e77",
  }),
  Object.freeze({
    id: "provider_effect_runtime_domain_source",
    path: "canary/service/ceo-canary/src/domain.mjs",
    kind: "source",
    sha256: "a7c73e70a2a811064e4e00a285e194bae182c4cf22c6f62652631e373f09e01c",
  }),
  Object.freeze({
    id: "provider_effect_contract_test",
    path: "test/provider-effects/provider-effects.test.mjs",
    kind: "test",
    sha256: "a28f872f582cf30aaf09ea8ba64a175080b9b4e27c41cb648b09f1016aef7b89",
  }),
  Object.freeze({
    id: "provider_effect_runtime_test",
    path: "test/ceo-canary/domain.test.mjs",
    kind: "test",
    sha256: "b1c1f68f3cc895516883d2f8a8ce6571173fb29c572a6222a8a28ad199c599a8",
  }),
  Object.freeze({
    id: "provider_effect_authority_source",
    path: "canary/provider-effects/authority.mjs",
    kind: "source",
    sha256: "65883ef8d136006c9661a07eecf5a7ac37eb14e04f73919782e3074754c2bcb4",
  }),
  Object.freeze({
    id: "provider_effect_authority_harness_test",
    path: "test/provider-effects/authority-harness.mjs",
    kind: "test",
    sha256: "566e4e9c33d882738d78c22be3e9851a8324d7e860ca7c7b91a4b55bc8930405",
  }),
  Object.freeze({
    id: "provider_effect_authority_testing_fixture",
    path: "test/provider-effects/testing.mjs",
    kind: "test",
    sha256: "3c777bd1b37357da105fa1f22e09c8e8bf87911d5e8dc092f08fa7bec20d01c2",
  }),
  Object.freeze({
    id: "provider_effect_authority_test",
    path: "test/provider-effects/authority.test.mjs",
    kind: "test",
    sha256: "a2d255f3ad930a833dfe2eaab7588fa60a2f25bb0f78154c2a1c06bb28a568b7",
  }),
  Object.freeze({
    id: "provider_effect_authority_readme",
    path: "canary/provider-effects/README.md",
    kind: "source",
    sha256: "3ef5795b0c9d1d9b50e6270f5f14326c2e3af40d08ee4a6cd0b0c59395c83aa4",
  }),
  Object.freeze({
    id: "slack_outbox_source",
    path: "canary/shared-contracts/index.mjs",
    kind: "source",
    sha256: "12d05d6f2ff6fc1f4c99e397b851d8de352d4a42789d046a166b33c895e1e58d",
  }),
  Object.freeze({
    id: "eval_result_store_source",
    path: "canary/evals/result-store.mjs",
    kind: "source",
    sha256: "1b6377d18827fe28cc9bcd20bf2a96bb36e021541be273c8ac616d07d56e0bf3",
  }),
  Object.freeze({
    id: "eval_release_authority_source",
    path: "canary/evals/release-authority.mjs",
    kind: "source",
    sha256: "37e6484abb116babf7f67f4068a99ce9cc00bf29b877a1b3bd418d724905428c",
  }),
  Object.freeze({
    id: "eval_testing_result_store_source",
    path: "canary/evals/testing-result-store.mjs",
    kind: "test",
    sha256: "324ce59870cd28e837bcd90ec0de0a6e246dae50115eb9ae401d0166f68d8bc4",
  }),
  Object.freeze({
    id: "ceo_surface_security_doc",
    path: "canary/service/ceo-surface/SECURITY.md",
    kind: "source",
    sha256: "6a754070caaa973e4652a744d85afd25746b3b4bfecd5bdce649bca6cc41fab6",
  }),
  Object.freeze({
    id: "ceo_surface_runbook",
    path: "canary/service/ceo-surface/RUNBOOK.md",
    kind: "source",
    sha256: "ee442d5439be10647799d8cbd9e46df287cd16eea54d921d4cc7696524d09c08",
  }),
  Object.freeze({
    id: "slack_outbox_test",
    path: "test/integration/canonical-integration.test.mjs",
    kind: "test",
    sha256: "7975ee6a2523efbfac82cf66e62a871048941f945eb997af1529b0c1a4c6c4fc",
  }),
  Object.freeze({
    id: "notion_private_root_source",
    path: "canary/notion-templates/templates.mjs",
    kind: "source",
    sha256: "07ad077fca6afb2ef70a4cbd90af582878605ed30fc249b38acf8b3f82d239d8",
  }),
  Object.freeze({
    id: "notion_private_root_test",
    path: "test/visuals/rendering.test.mjs",
    kind: "test",
    sha256: "036c2da324b79aa8d9eecd147dcfae11a64debf1ed1defe4049454890fa9bcb8",
  }),
  Object.freeze({
    id: "connector_read_source",
    path: "canary/connectors/providers.mjs",
    kind: "source",
    sha256: "5ccbc0df4d1d8c5bc36250e590e0c5c61fb7ef4c14fea3363426da62b0a0e750",
  }),
  Object.freeze({
    id: "connector_read_test",
    path: "test/connectors/contract.test.mjs",
    kind: "test",
    sha256: "ca32d3d52e0564a2e2dadd581ef21d3bcc97631d7761e4aa98eb2802e16c2cf7",
  }),
  Object.freeze({
    id: "hard_disable_source",
    path: "canary/service/ceo-surface/src/startup.mjs",
    kind: "source",
    sha256: "0144207c22d8a47e9af6adfe8df90926075492aaba43e7a01a18b934b61dfdee",
  }),
  Object.freeze({
    id: "hard_disable_test",
    path: "test/ceo-surface/security-contract.test.mjs",
    kind: "test",
    sha256: "fe3d9c4f27a32f2d5c6c9c8e154ba4c70a3ef42b0612dfb26d79f68c7c86a63d",
  }),
]);

const notionPrivateRootContract = Object.freeze({
  parentRef: "notion:ceo-private-root-v1",
  audienceRef: "audience:ceo-private",
  scope: "private_ceo",
  providerInvocationAllowed: false,
});

const productionPostgresRequirement = Object.freeze({
  id: "production_postgres_deployment_sentinel",
  gateId: "disposable_postgres_sentinel",
  state: "unmet",
  evidenceClass: "external_production_deployment_sentinel",
  offlineEvidenceCanSatisfy: false,
  blocker: "production_postgres_deployment_sentinel_contract_unmet",
});

const taskHostProvenanceRequirement = Object.freeze({
  id: "ceo_canary_task_host_provenance",
  gateId: "disposable_postgres_sentinel",
  state: "unmet",
  evidenceClass: "external_task_definition_host_provenance",
  offlineEvidenceCanSatisfy: false,
  blocker: "ceo_canary_task_host_provenance_unverified",
});

const taskRoleInventoryRequirement = Object.freeze({
  id: "ceo_canary_iam_role_inventory",
  gateId: "disposable_postgres_sentinel",
  state: "unmet",
  evidenceClass: "external_iam_role_inventory",
  offlineEvidenceCanSatisfy: false,
  blocker: "ceo_canary_iam_role_inventory_unverified",
});

const privateDnsCompatibilityRequirement = Object.freeze({
  id: "ceo_canary_private_dns_compatibility",
  gateId: "disposable_postgres_sentinel",
  state: "unmet",
  evidenceClass: "external_vpc_private_dns_resolution",
  offlineEvidenceCanSatisfy: false,
  blocker: "ceo_canary_private_dns_compatibility_unverified",
});

const statePlanLineageRequirement = Object.freeze({
  id: "ceo_canary_state_plan_lineage",
  gateId: "disposable_postgres_sentinel",
  state: "unmet",
  evidenceClass: "external_terraform_state_plan_backend_workspace_lineage",
  offlineEvidenceCanSatisfy: false,
  blocker: "ceo_canary_state_plan_lineage_unverified",
});

const runtimeImageSecurityRequirement = Object.freeze({
  id: "ceo_canary_runtime_image_security",
  gateId: "disposable_postgres_sentinel",
  state: "unmet",
  evidenceClass: "external_ecr_enhanced_image_scan",
  offlineEvidenceCanSatisfy: false,
  blocker: "ceo_canary_runtime_image_security_unverified",
});

const upstreamQmObserverMergeRequirement = Object.freeze({
  id: "upstream_qm_private_turn_observer_merge",
  gateId: "qm_shadow_ingress",
  state: "unmet",
  evidenceClass: "external_upstream_qm_merge",
  offlineEvidenceCanSatisfy: false,
  blocker: "upstream_qm_turn_observer_merge_unverified",
});

const upstreamQmObserverDeploymentRequirement = Object.freeze({
  id: "upstream_qm_private_turn_observer_deployment",
  gateId: "qm_shadow_ingress",
  state: "unmet",
  evidenceClass: "external_upstream_qm_deployment",
  offlineEvidenceCanSatisfy: false,
  blocker: "upstream_qm_turn_observer_deployment_binding_unavailable",
});

const qmObserverRouteKeyRequirement = Object.freeze({
  id: "qm_shadow_route_signing_key",
  gateId: "qm_shadow_ingress",
  state: "unmet",
  evidenceClass: "external_route_scoped_signing_key",
  offlineEvidenceCanSatisfy: false,
  blocker: "route_scoped_qm_observer_signing_key_unprovisioned",
});

const qmObserverPostgresOutboxRequirement = Object.freeze({
  id: "upstream_qm_observer_postgres_outbox",
  gateId: "qm_shadow_ingress",
  state: "unmet",
  evidenceClass: "external_postgres_outbox_live_acceptance",
  offlineEvidenceCanSatisfy: false,
  blocker: "upstream_qm_postgres_outbox_acceptance_unverified",
});

const qmWorkflowArtifactUiRequirement = Object.freeze({
  id: "qm_workflow_artifact_ui_live_acceptance",
  gateId: "mercury_invoicing",
  state: "unmet",
  evidenceClass: "external_authenticated_ui_live_acceptance",
  offlineEvidenceCanSatisfy: false,
  blocker: "qm_workflow_artifact_ui_live_acceptance_unverified",
});

const closedExternalRequirements = Object.freeze([
  productionPostgresRequirement,
  taskHostProvenanceRequirement,
  taskRoleInventoryRequirement,
  privateDnsCompatibilityRequirement,
  statePlanLineageRequirement,
  runtimeImageSecurityRequirement,
  upstreamQmObserverMergeRequirement,
  upstreamQmObserverDeploymentRequirement,
  qmObserverRouteKeyRequirement,
  qmObserverPostgresOutboxRequirement,
  qmWorkflowArtifactUiRequirement,
]);

const closedGates = Object.freeze([
  Object.freeze({
    id: "shadow_v6",
    dependsOn: Object.freeze([]),
    evidence: Object.freeze(["shadow_v6_source", "shadow_v6_test"]),
    blockers: Object.freeze(["live_shadow_execution_not_assessed"]),
  }),
  Object.freeze({
    id: "disposable_postgres_sentinel",
    dependsOn: Object.freeze(["shadow_v6"]),
    evidence: Object.freeze([
      "postgres_store_source",
      "postgres_evaluation_writer_source",
      "postgres_database_security_source",
      "postgres_database_boundary_source",
      "postgres_schema_source",
      "postgres_catalog_authority_source",
      "postgres_bootstrap_source",
      "postgres_bootstrap_test",
      "postgres_db_operator_source",
      "postgres_db_operator_bootstrap_source",
      "postgres_migrate_source",
      "postgres_credential_provisioner_source",
      "postgres_credential_test",
      "postgres_lifecycle_test",
      "postgres_retention_source",
      "ceo_canary_security_doc",
      "ceo_canary_migration_runbook",
      "postgres_infra_host_source",
      "ceo_canary_task_contract_data",
      "ceo_canary_task_renderer_source",
      "ceo_canary_task_sealed_provenance_source",
      "ceo_canary_task_infra_source",
      "ceo_canary_infra_main_hash_only",
      "ceo_canary_tfvars_hash_only",
      "ceo_canary_terraform_versions_hash_only",
      "ceo_canary_terraform_lock_hash_only",
      "ceo_canary_task_variables_source",
      "ceo_canary_task_test",
      "ceo_canary_task_runbook",
      "ceo_canary_db_operator_contract_data",
      "ceo_canary_db_operator_infra_source",
      "ceo_canary_db_operator_test",
      "ceo_canary_db_operator_runbook",
      "postgres_sentinel_test",
      "postgres_dockerfile_source",
      "postgres_runtime_dockerfile_source",
      "secret_boundary_test",
      "postgres_container_test",
    ]),
    blockers: Object.freeze([
      "disposable_postgres_sentinel_not_run",
      "production_postgres_deployment_sentinel_contract_unmet",
      "ceo_canary_task_host_provenance_unverified",
      "ceo_canary_iam_role_inventory_unverified",
      "ceo_canary_private_dns_compatibility_unverified",
      "ceo_canary_state_plan_lineage_unverified",
      "ceo_canary_runtime_image_security_unverified",
    ]),
  }),
  Object.freeze({
    id: "secret_routing",
    dependsOn: Object.freeze(["disposable_postgres_sentinel"]),
    evidence: Object.freeze([
      "secret_boundary_source",
      "secret_boundary_test",
      "deployment_profile_contract_source",
      "deployment_profile_registry_source",
      "deployment_profile_synthetic_fixture",
      "runtime_scope_source",
      "deployment_profile_registry_test",
    ]),
    blockers: Object.freeze(["live_secret_route_not_assessed"]),
  }),
  Object.freeze({
    id: "qm_shadow_ingress",
    dependsOn: Object.freeze(["shadow_v6", "disposable_postgres_sentinel", "secret_routing"]),
    evidence: Object.freeze(["qm_shadow_ingress_source", "qm_shadow_ingress_test", "qm_shadow_ingress_readme"]),
    blockers: Object.freeze([
      "upstream_qm_turn_observer_merge_unverified",
      "upstream_qm_turn_observer_deployment_binding_unavailable",
      "upstream_qm_postgres_outbox_acceptance_unverified",
      "qm_surface_identity_bridge_unverified",
      "route_scoped_qm_observer_signing_key_unprovisioned",
      "same_qm_runtime_schema_not_live_verified",
      "private_slack_and_web_acceptance_not_completed",
    ]),
  }),
  Object.freeze({
    id: "google_broker",
    dependsOn: Object.freeze(["secret_routing"]),
    evidence: Object.freeze([
      "google_broker_source",
      "google_broker_test",
      "provider_effect_policy_source",
      "provider_effect_contract_source",
      "provider_effect_shared_validation_source",
      "provider_effect_runtime_domain_source",
      "provider_effect_contract_test",
      "provider_effect_runtime_test",
    ]),
    blockers: Object.freeze(["trusted_google_broker_not_activated"]),
  }),
  Object.freeze({
    id: "provider_effect_authority",
    dependsOn: Object.freeze(["secret_routing", "google_broker"]),
    evidence: Object.freeze([
      "provider_effect_policy_source",
      "provider_effect_contract_source",
      "provider_effect_authority_source",
      "provider_effect_authority_harness_test",
      "provider_effect_authority_testing_fixture",
      "provider_effect_authority_test",
      "provider_effect_authority_readme",
    ]),
    blockers: Object.freeze([
      "provider_execution_not_activated",
      "provider_grant_not_activated",
      "immutable_provider_effect_proof_registry_unavailable",
      "production_provider_effect_durable_port_unavailable",
      "production_provider_effect_adapters_unavailable",
      "production_provider_effect_reconciliation_ports_unavailable",
    ]),
  }),
  Object.freeze({
    id: "mercury_invoicing",
    dependsOn: Object.freeze(["qm_shadow_ingress", "provider_effect_authority"]),
    evidence: Object.freeze([
      "mercury_invoicing_source",
      "mercury_invoicing_validation_source",
      "mercury_invoicing_test",
      "mercury_invoicing_cli_integration_test",
      "mercury_invoicing_readme",
    ]),
    blockers: Object.freeze([
      "mercury_provider_effect_catalog_and_adapter_not_approved",
      "mercury_trusted_schedule_lineage_not_live_assessed",
      "mercury_durable_approval_and_reservation_not_implemented",
      "mercury_signed_identity_and_billing_receipts_not_live_assessed",
      "mercury_cli_sandbox_acceptance_not_completed",
      "mercury_immutable_cli_packaging_provenance_unapproved",
      "mercury_authenticated_reconciliation_not_implemented",
      "qm_workflow_artifact_ui_live_acceptance_unverified",
    ]),
  }),
  Object.freeze({
    id: "slack_identity_eval_outbox",
    dependsOn: Object.freeze(["shadow_v6", "secret_routing"]),
    evidence: Object.freeze([
      "slack_outbox_source",
      "eval_result_store_source",
      "postgres_evaluation_writer_source",
      "eval_release_authority_source",
      "eval_testing_result_store_source",
      "ceo_surface_security_doc",
      "ceo_surface_runbook",
      "slack_outbox_test",
    ]),
    blockers: Object.freeze(["slack_identity_and_delivery_not_live_assessed"]),
  }),
  Object.freeze({
    id: "notion_private_root",
    dependsOn: Object.freeze(["slack_identity_eval_outbox"]),
    evidence: Object.freeze(["notion_private_root_source", "notion_private_root_test"]),
    blockers: Object.freeze(["notion_private_root_not_live_assessed"]),
  }),
  Object.freeze({
    id: "clarify_read",
    dependsOn: Object.freeze(["secret_routing"]),
    evidence: Object.freeze(["connector_read_source", "connector_read_test"]),
    blockers: Object.freeze(["clarify_read_binding_not_live_assessed"]),
  }),
  Object.freeze({
    id: "brain_read",
    dependsOn: Object.freeze(["secret_routing"]),
    evidence: Object.freeze(["connector_read_source", "connector_read_test"]),
    blockers: Object.freeze(["command_center_brain_read_binding_not_live_assessed"]),
  }),
  Object.freeze({
    id: "hard_disable_transition",
    dependsOn: Object.freeze([
      "qm_shadow_ingress",
      "provider_effect_authority",
      "mercury_invoicing",
      "notion_private_root",
      "clarify_read",
      "brain_read",
    ]),
    evidence: Object.freeze(["hard_disable_source", "hard_disable_test"]),
    blockers: Object.freeze(["activation_transition_review_not_performed"]),
  }),
]);

const secretPatterns = Object.freeze([
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  /\bAKIA[A-Z0-9]{16}\b/u,
  /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/u,
  /\bsk-(?:live|proj)-[A-Za-z0-9_-]{16,}\b/u,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
  /\bAIza[0-9A-Za-z_-]{30,}\b/u,
  /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^@\s/]+@/iu,
  /\b(?:client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*["'\x60][^"'\x60\r\n]{8,}["'\x60]/iu,
  /\bpassword\s*[:=]\s*(?:["'\x60][^"'\x60\r\n]{4,}["'\x60]|[^\s,;)}]{8,})/iu,
  /\bauthorization\s*[:=]\s*["'\x60]?\s*Bearer\s+[A-Za-z0-9._~+/=-]{8,}/iu,
]);
const hashOnlyEvidencePaths = Object.freeze([
  "infra/main.tf",
  "infra/terraform.tfvars",
  "infra/versions.tf",
  "infra/.terraform.lock.hcl",
]);
const hashOnlyEvidencePathSet = new Set(hashOnlyEvidencePaths);

export class ActivationGateError extends Error {
  constructor(code) {
    super(code);
    this.name = "ActivationGateError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ActivationGateError(code);
};

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

const canonicalJson = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((key) => JSON.stringify(key) + ":" + canonicalJson(value[key]))
      .join(",") +
    "}"
  );
};

const freeze = (value) => {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
};

const exactRecord = (value, keys, code) => {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  ) {
    fail(code);
  }
  return value;
};

const exactArray = (actual, expected, code) => {
  if (
    !Array.isArray(actual) ||
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    fail(code);
  }
};

const safeEvidencePath = (value) => {
  if (
    typeof value !== "string" ||
    value.length < 5 ||
    value.length > 240 ||
    isAbsolute(value) ||
    value.includes("\\") ||
    value.includes("\u0000") ||
    (!["canary/service/ceo-canary/Dockerfile", "canary/service/ceo-canary/Dockerfile.runtime"].includes(value) &&
      ![".mjs", ".sql", ".tf", ".tfvars", ".hcl", ".md", ".json"].some((extension) => value.endsWith(extension)))
  ) {
    fail("evidence_path_invalid");
  }
  const segments = value.split("/");
  if (
    !["canary", "infra", "test"].includes(segments[0]) ||
    segments.some((segment) => segment === "" || segment === "." || segment === ".." || segment === "node_modules")
  ) {
    fail("evidence_path_invalid");
  }
  return value;
};

const validateDag = (gates) => {
  const ids = gates.map((gate) => gate.id);
  if (new Set(ids).size !== ids.length) fail("gate_id_duplicate");
  const known = new Set(ids);
  for (const gate of gates) {
    if (!Array.isArray(gate.dependsOn) || new Set(gate.dependsOn).size !== gate.dependsOn.length) {
      fail("gate_dependency_invalid");
    }
    if (gate.dependsOn.some((dependency) => !known.has(dependency) || dependency === gate.id)) {
      fail("gate_dependency_invalid");
    }
  }
  const visiting = new Set();
  const visited = new Set();
  const byId = new Map(gates.map((gate) => [gate.id, gate]));
  const visit = (id) => {
    if (visiting.has(id)) fail("gate_dependency_cycle");
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of byId.get(id).dependsOn) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  };
  for (const id of ids) visit(id);
};

const validateManifest = (manifest) => {
  exactRecord(manifest, exactManifestKeys, "manifest_shape_invalid");
  if (
    manifest.schemaVersion !== 1 ||
    manifest.manifestId !== "risely.ceo.activation-gates.offline.v1" ||
    manifest.assessmentMode !== "offline_source_and_test_evidence"
  ) {
    fail("manifest_identity_invalid");
  }
  exactRecord(manifest.semanticContracts, ["notionPrivateRoot"], "semantic_contract_shape_invalid");
  const notionContract = exactRecord(
    manifest.semanticContracts.notionPrivateRoot,
    exactNotionContractKeys,
    "notion_semantic_contract_invalid",
  );
  if (exactNotionContractKeys.some((key) => notionContract[key] !== notionPrivateRootContract[key])) {
    fail("notion_semantic_contract_invalid");
  }
  if (
    !Array.isArray(manifest.externalRequirements) ||
    manifest.externalRequirements.length !== closedExternalRequirements.length
  ) {
    fail("external_requirement_set_not_closed");
  }
  manifest.externalRequirements.forEach((value, index) => {
    const externalRequirement = exactRecord(value, exactExternalRequirementKeys, "external_requirement_shape_invalid");
    const expected = closedExternalRequirements[index];
    if (exactExternalRequirementKeys.some((key) => externalRequirement[key] !== expected[key])) {
      fail("external_requirement_not_closed");
    }
  });
  if (!Array.isArray(manifest.evidence) || manifest.evidence.length !== closedEvidence.length) {
    fail("evidence_set_not_closed");
  }
  const evidenceIds = new Set();
  manifest.evidence.forEach((entry, index) => {
    exactRecord(entry, exactEvidenceKeys, "evidence_shape_invalid");
    safeEvidencePath(entry.path);
    if (!identifierPattern.test(entry.id) || evidenceIds.has(entry.id)) fail("evidence_id_invalid");
    evidenceIds.add(entry.id);
    if (!["source", "test"].includes(entry.kind)) fail("evidence_kind_invalid");
    if (!sha256Pattern.test(entry.sha256)) fail("evidence_hash_invalid");
    if (!Number.isSafeInteger(entry.maxBytes) || entry.maxBytes < 1 || entry.maxBytes > maximumEvidenceBytes) {
      fail("evidence_size_limit_invalid");
    }
    const expected = closedEvidence[index];
    if (entry.id !== expected.id || entry.path !== expected.path || entry.kind !== expected.kind) {
      fail("evidence_set_not_closed");
    }
  });
  if (!Array.isArray(manifest.gates) || manifest.gates.length !== closedGates.length) {
    fail("gate_set_not_closed");
  }
  manifest.gates.forEach((gate) => {
    exactRecord(gate, exactGateKeys, "gate_shape_invalid");
    if (!identifierPattern.test(gate.id)) fail("gate_id_invalid");
    if (
      !Array.isArray(gate.evidence) ||
      gate.evidence.length < 1 ||
      new Set(gate.evidence).size !== gate.evidence.length
    ) {
      fail("gate_evidence_invalid");
    }
    if (gate.evidence.some((id) => !evidenceIds.has(id))) fail("gate_evidence_invalid");
    if (
      !Array.isArray(gate.blockers) ||
      gate.blockers.length < 1 ||
      new Set(gate.blockers).size !== gate.blockers.length ||
      gate.blockers.some((blocker) => !identifierPattern.test(blocker))
    ) {
      fail("gate_blocker_invalid");
    }
  });
  validateDag(manifest.gates);
  manifest.gates.forEach((gate, index) => {
    const expected = closedGates[index];
    if (gate.id !== expected.id) fail("gate_set_not_closed");
    exactArray(gate.dependsOn, expected.dependsOn, "gate_dependencies_not_closed");
    exactArray(gate.evidence, expected.evidence, "gate_evidence_not_closed");
    exactArray(gate.blockers, expected.blockers, "gate_blockers_not_closed");
  });
  return manifest;
};

const inside = (target, root) => {
  const child = relative(root, target);
  return child !== ".." && !child.startsWith(".." + sep) && !isAbsolute(child);
};

const evidenceRootBoundary = async (root) => {
  if (typeof root !== "string" || root.length === 0) fail("evidence_root_invalid");
  let metadata;
  try {
    metadata = await lstat(root);
  } catch {
    fail("evidence_root_unavailable");
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) fail("evidence_root_invalid");
  return Object.freeze({ lexical: resolve(root), canonical: await realpath(root) });
};

const bundledManifestFile = async () => {
  let rootMetadata;
  try {
    rootMetadata = await lstat(layerRoot);
  } catch {
    fail("bundled_manifest_root_unavailable");
  }
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) fail("bundled_manifest_root_invalid");
  const canonicalRoot = await realpath(layerRoot);
  let lexical = layerRoot;
  let canonicalExpected = canonicalRoot;
  for (let index = 0; index < bundledManifestSegments.length; index += 1) {
    lexical = resolve(lexical, bundledManifestSegments[index]);
    canonicalExpected = resolve(canonicalExpected, bundledManifestSegments[index]);
    let metadata;
    try {
      metadata = await lstat(lexical);
    } catch {
      fail("bundled_manifest_unavailable");
    }
    if (metadata.isSymbolicLink()) fail("bundled_manifest_symlink_rejected");
    if (index < bundledManifestSegments.length - 1 && !metadata.isDirectory()) {
      fail("bundled_manifest_parent_nonregular");
    }
    if (index === bundledManifestSegments.length - 1 && !metadata.isFile()) {
      fail("bundled_manifest_nonregular");
    }
    if ((await realpath(lexical)) !== canonicalExpected) fail("bundled_manifest_path_escape");
  }
  return lexical;
};

const readBundledManifest = async () => {
  const path = await bundledManifestFile();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const openedMetadata = await handle.stat();
    if (!openedMetadata.isFile()) fail("bundled_manifest_nonregular");
    if (openedMetadata.size > maximumManifestBytes) fail("bundled_manifest_too_large");
    const bytes = await handle.readFile();
    if (bytes.byteLength > maximumManifestBytes) fail("bundled_manifest_too_large");
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      fail("bundled_manifest_text_invalid");
    }
  } catch (error) {
    if (error instanceof ActivationGateError) throw error;
    fail("bundled_manifest_read_failed");
  } finally {
    await handle?.close().catch(() => {});
  }
};

const readEvidence = async (root, entry, expected) => {
  const segments = entry.path.split("/");
  let target = root.lexical;
  for (let index = 0; index < segments.length; index += 1) {
    target = resolve(target, segments[index]);
    let metadata;
    try {
      metadata = await lstat(target);
    } catch {
      fail("evidence_file_unavailable");
    }
    if (metadata.isSymbolicLink()) fail("evidence_symlink_rejected");
    if (index < segments.length - 1 && !metadata.isDirectory()) fail("evidence_path_nonregular");
    if (index === segments.length - 1 && !metadata.isFile()) fail("evidence_path_nonregular");
  }
  const canonicalTarget = await realpath(target);
  if (!inside(canonicalTarget, root.canonical)) fail("evidence_path_escape");
  let handle;
  try {
    handle = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (!metadata.isFile()) fail("evidence_path_nonregular");
    if (metadata.size > entry.maxBytes) fail("evidence_file_too_large");
    const bytes = await handle.readFile();
    if (bytes.byteLength > entry.maxBytes) fail("evidence_file_too_large");
    let source;
    try {
      source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      fail("evidence_text_invalid");
    }
    if (source.length === 0 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(source)) {
      fail("evidence_text_invalid");
    }
    const hashOnly = hashOnlyEvidencePathSet.has(entry.path);
    if (!hashOnly && secretPatterns.some((pattern) => pattern.test(source))) fail("evidence_secret_like");
    const digest = sha256(bytes);
    if (digest !== entry.sha256) fail("evidence_hash_mismatch");
    if (digest !== expected.sha256) fail("evidence_digest_not_closed");
    return freeze({
      id: entry.id,
      path: entry.path,
      kind: entry.kind,
      sha256: digest,
      bytes: bytes.byteLength,
      verification: "offline_hash_verified",
      contentInspection: hashOnly ? "not_assessed_hash_only" : "secret_patterns_rejected",
    });
  } catch (error) {
    if (error instanceof ActivationGateError) throw error;
    fail("evidence_read_failed");
  } finally {
    await handle?.close().catch(() => {});
  }
};

export async function evaluateClosedManifest(manifestText, evidenceRoot = layerRoot) {
  let parsed;
  try {
    parsed = parseStrictJson(manifestText);
  } catch (error) {
    if (error instanceof StrictJsonError) throw new ActivationGateError(error.code);
    throw error;
  }
  const manifest = validateManifest(parsed);
  const root = await evidenceRootBoundary(evidenceRoot);
  const evidence = [];
  for (let index = 0; index < manifest.evidence.length; index += 1) {
    evidence.push(await readEvidence(root, manifest.evidence[index], closedEvidence[index]));
  }
  const evidenceById = new Map(evidence.map((entry) => [entry.id, entry]));
  const gates = manifest.gates.map((gate) =>
    freeze({
      id: gate.id,
      dependsOn: [...gate.dependsOn],
      evidence: gate.evidence.map((id) => evidenceById.get(id).sha256),
      dependencyGraphVerified: true,
      offlineEvidence: "source_and_test_hashes_verified",
      state: "blocked",
      blockers: [...gate.blockers],
      liveReadiness: "not_assessed",
      activationAuthorized: false,
      providerInvocationAllowed: false,
    }),
  );
  const blockers = gates.flatMap((gate) => gate.blockers);
  const manifestSha256 = sha256(manifestText);
  const evidenceSetSha256 = sha256(canonicalJson(evidence));
  const dependencyGraphSha256 = sha256(canonicalJson(gates.map(({ id, dependsOn }) => ({ id, dependsOn }))));
  const readBoundary = freeze({
    mode: "closed_regular_repo_source_and_test_digests_only",
    evidencePathSetSha256: sha256(canonicalJson(closedEvidence)),
    hashOnlyContentPaths: [...hashOnlyEvidencePaths],
    environmentFilesAllowed: false,
    secretStoresAllowed: false,
    importedProviderPackagesAllowed: false,
  });
  const unsignedReport = freeze({
    schemaVersion: 1,
    manifestId: manifest.manifestId,
    assessmentMode: manifest.assessmentMode,
    manifestSha256,
    evidenceSetSha256,
    dependencyGraphSha256,
    semanticContracts: {
      notionPrivateRoot: { ...notionPrivateRootContract },
    },
    externalRequirements: closedExternalRequirements.map((requirement) => ({ ...requirement })),
    readBoundary,
    evidence,
    gates,
    overallState: "blocked",
    blockers,
    liveReadiness: "not_assessed",
    activationAuthorized: false,
    providerInvocationAllowed: false,
    networkContacted: false,
    secretValuesRead: false,
    secretValuesReadBasis:
      "closed_regular_repo_digests_with_explicit_hash_only_deployment_configuration_and_no_environment_or_secret_store_access",
  });
  return freeze({ ...unsignedReport, reportSha256: sha256(canonicalJson(unsignedReport)) });
}

export async function evaluateActivationGates() {
  const manifestText = await readBundledManifest();
  if (sha256(manifestText) !== bundledManifestSha256) fail("bundled_manifest_hash_mismatch");
  return evaluateClosedManifest(manifestText, layerRoot);
}
