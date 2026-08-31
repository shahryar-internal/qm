import {
  GMAIL_DRAFT_REQUEST_MAX_BYTES,
  assertProviderIdentifier,
  normalizedMailbox,
  sha256Bytes,
  validateEffectProposal,
  type GmailDraftEffectProposal,
} from "./contracts.ts";

export interface GmailDraftMime {
  mimeSource: string;
  raw: string;
  markerMessageId: string;
  mimeSha256: string;
  requestBody: string;
  requestSha256: string;
}

function subjectHeaderLines(subject: string): string[] {
  if (/^[\x20-\x7e]+$/u.test(subject) && !/=\?[^?\s]+\?[bqBQ]\?[^?\s]+\?=/u.test(subject)) {
    return [`Subject: ${subject}`];
  }
  const chunks: string[] = [];
  let chunk = "";
  let bytes = 0;
  for (const point of subject) {
    const pointBytes = Buffer.byteLength(point, "utf8");
    if (bytes + pointBytes > 39 && chunk) {
      chunks.push(chunk);
      chunk = "";
      bytes = 0;
    }
    chunk += point;
    bytes += pointBytes;
  }
  if (chunk) chunks.push(chunk);
  return chunks.map((value, index) => {
    const word = `=?UTF-8?B?${Buffer.from(value, "utf8").toString("base64")}?=`;
    return index === 0 ? `Subject: ${word}` : ` ${word}`;
  });
}

function crlfBody(body: string): string {
  return body.replace(/\r\n|\r|\n/gu, "\r\n");
}

function wrapBase64(value: string): string {
  return value.match(/.{1,76}/gu)?.join("\r\n") ?? "";
}

function markerMessageId(effectPayloadSha256: string): string {
  return `<qm.${effectPayloadSha256}@drafts.invalid>`;
}

export function buildPlainTextGmailDraftMime(proposal: GmailDraftEffectProposal): GmailDraftMime {
  const validated = validateEffectProposal(proposal, proposal.approval.issuedAt);
  const recipients = validated.to.map((entry) => normalizedMailbox(entry, "recipient"));
  if (recipients.length < 1 || recipients.length > 20) throw new TypeError("recipient count is invalid");
  if (/[\r\n]/u.test(validated.subject)) throw new TypeError("subject contains a header boundary");
  if (validated.gmailThreadId !== null) assertProviderIdentifier(validated.gmailThreadId, "gmailThreadId");
  const marker = markerMessageId(validated.effectPayloadSha256);
  const body = crlfBody(validated.bodyText);
  const encodedBody = wrapBase64(Buffer.from(body, "utf8").toString("base64"));
  const headers = [
    `From: ${normalizedMailbox(validated.mailbox, "mailbox")}`,
    `To: ${recipients.join(", ")}`,
    ...subjectHeaderLines(validated.subject),
    `Message-ID: ${marker}`,
    ...(validated.replyAuthority ? [`In-Reply-To: ${validated.replyAuthority.parentMessageId}`] : []),
    ...(validated.replyAuthority ? [`References: ${validated.replyAuthority.referenceMessageIds.join(" ")}`] : []),
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
  ];
  if (headers.some((header) => Buffer.byteLength(header, "utf8") > 998))
    throw new TypeError("MIME header is too large");
  const mimeSource = [...headers, "", encodedBody, ""].join("\r\n");
  const raw = Buffer.from(mimeSource, "utf8").toString("base64url");
  const message = { raw, ...(validated.gmailThreadId ? { threadId: validated.gmailThreadId } : {}) };
  const requestBody =
    validated.operation === "update" ? JSON.stringify({ id: validated.draftId, message }) : JSON.stringify({ message });
  if (Buffer.byteLength(requestBody, "utf8") > GMAIL_DRAFT_REQUEST_MAX_BYTES) {
    throw new TypeError("Gmail draft request is too large");
  }
  return Object.freeze({
    mimeSource,
    raw,
    markerMessageId: marker,
    mimeSha256: sha256Bytes(mimeSource),
    requestBody,
    requestSha256: sha256Bytes(requestBody),
  });
}
