import assert from "node:assert/strict";
import { test } from "node:test";
import type { GmailDraftOwnerDmPublication } from "../src/gmail-drafts/card.ts";
import type {
  GmailDraftOperation,
  GmailDraftReplyAuthority,
  VerifiedGmailDraftApproval,
} from "../src/gmail-drafts/contracts.ts";
import type {
  GmailDraftAuthenticatedResponse,
  GmailDraftPrivateTransportAllowlist,
} from "../src/gmail-drafts/provider-client.ts";
import type {
  GmailDraftPrivateApprovalSignerPort,
  GmailDraftPrivateThreadSourceVerifierPort,
} from "../src/gmail-drafts/runtime.ts";

type GmailDraftPrivateLayerContract = {
  operation: GmailDraftOperation;
  approval: VerifiedGmailDraftApproval;
  replyAuthority: GmailDraftReplyAuthority;
  publication: GmailDraftOwnerDmPublication;
  transportAllowlist: GmailDraftPrivateTransportAllowlist;
  authenticatedResponse: GmailDraftAuthenticatedResponse;
  approvalSigner: GmailDraftPrivateApprovalSignerPort;
  threadSourceVerifier: GmailDraftPrivateThreadSourceVerifierPort;
};

const contractKeys: readonly (keyof GmailDraftPrivateLayerContract)[] = [
  "operation",
  "approval",
  "replyAuthority",
  "publication",
  "transportAllowlist",
  "authenticatedResponse",
  "approvalSigner",
  "threadSourceVerifier",
];

test("private Gmail layer retains its public TypeScript contract surface", () => {
  assert.deepEqual(contractKeys, [
    "operation",
    "approval",
    "replyAuthority",
    "publication",
    "transportAllowlist",
    "authenticatedResponse",
    "approvalSigner",
    "threadSourceVerifier",
  ]);
});
