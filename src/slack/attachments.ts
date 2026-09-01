import { sleep } from "./util.ts";
import { createHash } from "node:crypto";
import { messageWithForwardedContent, type SlackMessageAttachment } from "./forwards.ts";
import {
  WORKFLOW_ARTIFACT_MIME,
  decodeWorkflowArtifactCard,
  workflowArtifactSlackLinksText,
  workflowArtifactSlackMrkdwn,
  workflowArtifactSlackSectionText,
  type WorkflowArtifactCard,
} from "../../plugins/chassis/src/workflow-artifact-card.ts";
import { WORKFLOW_ARTIFACT_SUFFIX, workflowArtifactMime } from "../../plugins/chassis/src/workflow-artifact.ts";
import { botIdentityArgs } from "./delivery.ts";

export interface IncomingAttachment {
  name: string;
  mimetype: string;
  sizeBytes: number;
  blobId: string;
  sourceId?: string;
  author?: string;
}

export interface OutgoingAttachment {
  name: string;
  mimetype: string;
  sizeBytes: number;
  blobId: string;
  artifactId?: string;
  artifactViewerId?: string;
  renderOnly?: true;
}

export interface SlackFile {
  id?: string;
  name?: string;
  title?: string;
  mimetype?: string;
  filetype?: string;
  size?: number;
  url_private?: string;
  url_private_download?: string;
  mode?: string;
  user?: string;
  alt_txt?: string;
}

export async function hydrateSlackFiles(
  files: readonly SlackFile[],
  lookup: (fileId: string) => Promise<SlackFile | undefined>,
): Promise<SlackFile[]> {
  return Promise.all(
    files.map(async (file) => {
      if (!file.id || file.url_private || file.url_private_download) return file;
      try {
        const hydrated = await lookup(file.id);
        return hydrated ? { ...file, ...hydrated, ...(file.user ? { user: file.user } : {}) } : file;
      } catch {
        return file;
      }
    }),
  );
}

export const MAX_ATTACHMENT_BYTES = 1_000_000_000;

export function isOversize(file: Pick<SlackFile, "size">): boolean {
  return typeof file.size === "number" && file.size > MAX_ATTACHMENT_BYTES;
}

export interface ThreadMessage {
  user?: string;
  text?: string;
  ts?: string;
  bot_id?: string;
  subtype?: string;
  files?: SlackFile[];
  attachments?: SlackMessageAttachment[];
}

export function collectEarlierThreadFiles(
  messages: readonly ThreadMessage[],
  opts: { triggerTs: string; botUserId: string; ownBotId: string; have: readonly SlackFile[]; inThread: boolean },
): SlackFile[] {
  if (!opts.inThread) return [];
  const seen = new Set<string>();
  for (const f of opts.have) if (f.id) seen.add(f.id);
  const out: SlackFile[] = [];
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]!;
    if (m.ts === opts.triggerTs) continue;
    const isBot = (m.user && m.user === opts.botUserId) || (opts.ownBotId !== "" && m.bot_id === opts.ownBotId);
    if (isBot) continue;
    for (const f of messageWithForwardedContent(m).files) {
      if (f.id && seen.has(f.id)) continue;
      if (f.id) seen.add(f.id);
      out.push(f.user || !m.user ? f : { ...f, user: m.user });
    }
  }
  return out;
}

export function isTrustedSlackHost(url: string, extraHost?: string): boolean {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return h === "slack.com" || h.endsWith(".slack.com") || (!!extraHost && h === extraHost.toLowerCase());
  } catch {
    return false;
  }
}

export function attachmentFromBytes(
  file: SlackFile,
  bytes: Uint8Array,
  blobId: string,
  author?: string,
): IncomingAttachment {
  const name = file.name || file.title || file.id || "file";
  const mimetype = file.mimetype || "application/octet-stream";
  return {
    name,
    mimetype,
    sizeBytes: bytes.length,
    blobId,
    ...(file.id ? { sourceId: file.id } : {}),
    ...(author ? { author } : {}),
  };
}

export const MAX_ATTACHMENTS_PER_TURN = 10;

const CAP_MB = Math.floor(MAX_ATTACHMENT_BYTES / 1_000_000);
const capLabel = CAP_MB >= 1000 ? `${Math.round(CAP_MB / 1000)} GB` : `${CAP_MB} MB`;
export const oversizeMsg = (label: string): string => `"${label}" is too large — I can handle files up to ~${capLabel}`;

export interface DownloadOptions {
  token?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  trustedHost?: string;
}

export async function downloadSlackFile(file: SlackFile, opts: DownloadOptions = {}): Promise<Uint8Array> {
  const url = file.url_private_download || file.url_private;
  if (!url) throw new Error("no url_private");
  if (file.mode === "external" || file.mode === "remote") throw new Error("external/remote files aren't supported");
  if (!isTrustedSlackHost(url, opts.trustedHost)) throw new Error("file is not Slack-hosted; refusing to fetch");
  const doFetch = opts.fetchImpl ?? fetch;
  const res = await doFetch(url, {
    headers: opts.token ? { Authorization: `Bearer ${opts.token}` } : {},
    redirect: "manual",
    signal: AbortSignal.timeout(opts.timeoutMs ?? 300_000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("text/html")) throw new Error("got an HTML page (check files:read scope)");
  const len = Number(res.headers.get("content-length") ?? "0");
  if (len > MAX_ATTACHMENT_BYTES) throw new Error("file too large");
  return new Uint8Array(await res.arrayBuffer());
}

export interface ProcessedInbound {
  attachments: IncomingAttachment[];
  issues: string[];
}

export async function processInboundFiles(
  files: readonly SlackFile[],
  download: (file: SlackFile) => Promise<Uint8Array>,
  stage: (bytes: Uint8Array) => Promise<{ blobId: string }>,
  resolveAuthor?: (userId: string | undefined) => Promise<string | undefined> | string | undefined,
): Promise<ProcessedInbound> {
  const attachments: IncomingAttachment[] = [];
  const issues: string[] = [];
  for (const f of files) {
    const label = f.name || f.title || "that file";
    if (attachments.length >= MAX_ATTACHMENTS_PER_TURN) {
      issues.push(`skipped "${label}" — too many files in one message (max ${MAX_ATTACHMENTS_PER_TURN})`);
      continue;
    }
    if (isOversize(f)) {
      issues.push(oversizeMsg(label));
      continue;
    }
    try {
      const bytes = await download(f);
      if (bytes.length > MAX_ATTACHMENT_BYTES) {
        issues.push(oversizeMsg(label));
        continue;
      }
      const { blobId } = await stage(bytes);
      const author = resolveAuthor ? await resolveAuthor(f.user) : undefined;
      attachments.push(attachmentFromBytes(f, bytes, blobId, author));
    } catch (err) {
      issues.push(
        `I couldn't read "${label}" — check my file-access permission (files:read) (${(err as Error).message})`,
      );
    }
  }
  return { attachments, issues };
}

export interface UploadClient {
  files: {
    uploadV2(args: any): Promise<unknown>;
    info(args: { file: string }): Promise<unknown>;
    delete?(args: { file: string }): Promise<unknown>;
  };
  chat?: { postMessage(args: any): Promise<unknown>; delete?(args: { channel: string; ts: string }): Promise<unknown> };
  conversations?: {
    history(args: Record<string, unknown>): Promise<unknown>;
    replies(args: Record<string, unknown>): Promise<unknown>;
  };
}

const SLACK_WORKFLOW_BASE_URL = "https://workflow-artifact.invalid/";

function clipped(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function neutralizeSlackFallbackText(value: string): string {
  return value
    .replace(/&/g, "＆")
    .replace(/</g, "‹")
    .replace(/>/g, "›")
    .replace(/@/g, "@\u200b")
    .replace(/\b([a-z][a-z0-9+.-]{1,31}:)\/\//gi, "$1\u200b//")
    .replace(/\b((?:mailto|tel):)/gi, "$1\u200b")
    .replace(/\bwww\./gi, (value) => `${value.slice(0, -1)}.\u200b`)
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (value) => value.replace(".", ".\u200b"))
    .replace(/\b(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\b/gi, (value) =>
      value.replace(".", ".\u200b"),
    );
}

function workflowArtifactBlocks(card: WorkflowArtifactCard): Array<Record<string, unknown>> {
  const toneIcon = {
    neutral: ":white_circle:",
    info: ":large_blue_circle:",
    success: ":large_green_circle:",
    warning: ":large_yellow_circle:",
    danger: ":red_circle:",
  } as const;
  const blocks: Array<Record<string, unknown>> = [
    { type: "header", text: { type: "plain_text", text: card.heading, emoji: true } },
  ];
  if (card.status) {
    blocks.push({
      type: "context",
      elements: [
        { type: "mrkdwn", text: `${toneIcon[card.status.tone]} *${workflowArtifactSlackMrkdwn(card.status.label)}*` },
      ],
    });
  }
  if (card.summary) {
    blocks.push({ type: "section", text: { type: "mrkdwn", text: workflowArtifactSlackMrkdwn(card.summary) } });
  }
  for (const section of card.sections ?? []) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: workflowArtifactSlackSectionText(section, SLACK_WORKFLOW_BASE_URL) },
    });
  }
  if (card.links?.length) {
    blocks.push({
      type: "context",
      elements: [{ type: "mrkdwn", text: workflowArtifactSlackLinksText(card.links, SLACK_WORKFLOW_BASE_URL) }],
    });
  }
  return blocks;
}

function isWorkflowArtifact(attachment: Pick<OutgoingAttachment, "name" | "mimetype">): boolean {
  return (
    workflowArtifactMime(attachment.mimetype) === WORKFLOW_ARTIFACT_MIME ||
    attachment.name.toLowerCase().endsWith(WORKFLOW_ARTIFACT_SUFFIX)
  );
}

async function waitForShareCommit(client: UploadClient, channel: string, fileId: string): Promise<string | undefined> {
  for (let i = 0; i < 60; i++) {
    let shares: any;
    try {
      shares = ((await client.files.info({ file: fileId })) as any)?.file?.shares ?? {};
    } catch {
      return undefined;
    }
    const here = [...(shares.public?.[channel] ?? []), ...(shares.private?.[channel] ?? [])];
    const shared = here.find((share: any) => share?.ts);
    if (shared?.ts) return String(shared.ts);
    await sleep(250);
  }
  return undefined;
}

function uploadedFileIds(response: any): string[] {
  const files = response?.file ? [response.file] : (response?.files ?? []);
  return files.flatMap((entry: any) => {
    if (entry?.id) return [String(entry.id)];
    return (entry?.files ?? []).flatMap((file: any) => (file?.id ? [String(file.id)] : []));
  });
}

function slackDeleteAlreadyApplied(error: unknown): boolean {
  const code = (error as { data?: { error?: unknown } })?.data?.error;
  return (
    code === "not_found" || code === "message_not_found" || code === "file_not_found" || code === "already_deleted"
  );
}

export async function uploadAttachments(
  client: UploadClient,
  channel: string,
  threadTs: string | undefined,
  attachments: readonly OutgoingAttachment[],
  fetchBlob: (blobId: string) => Promise<Buffer>,
  fetchArtifact?: (artifactId: string, viewerId: string) => Promise<Buffer>,
  opts: {
    initialComment?: string;
    isCancelled?(): boolean | Promise<boolean>;
    idempotencyKey?: string;
    verifyOldest?: string;
  } = {},
): Promise<{ uploaded: boolean; messageTs?: string }> {
  const markerFor = (index: number, attachment: OutgoingAttachment): string | undefined =>
    opts.idempotencyKey
      ? `qm-attachment:${createHash("sha256")
          .update(JSON.stringify([opts.idempotencyKey, index, attachment.blobId, attachment.name]))
          .digest("hex")}`
      : undefined;
  const existingMarkers = new Set<string>();
  const existingCardTs = new Map<string, Set<string>>();
  const existingFileIds = new Map<string, Set<string>>();
  if (opts.idempotencyKey && client.conversations) {
    let cursor: string | undefined;
    do {
      const paging = {
        channel,
        limit: 100,
        include_all_metadata: true,
        ...(opts.verifyOldest ? { oldest: opts.verifyOldest, inclusive: true } : {}),
        ...(cursor ? { cursor } : {}),
      };
      const response = threadTs
        ? await client.conversations.replies({ ...paging, ts: threadTs })
        : await client.conversations.history(paging);
      for (const message of (response as any)?.messages ?? []) {
        const metadataKey = message?.metadata?.event_payload?.idempotency_key;
        if (typeof metadataKey === "string") {
          existingMarkers.add(metadataKey);
          if (typeof message?.ts === "string") {
            const timestamps = existingCardTs.get(metadataKey) ?? new Set<string>();
            timestamps.add(message.ts);
            existingCardTs.set(metadataKey, timestamps);
          }
        }
        for (const file of message?.files ?? []) {
          if (typeof file?.alt_txt !== "string") continue;
          const marker = file.alt_txt.match(/qm-attachment:[a-f0-9]{64}/)?.[0];
          if (marker) {
            existingMarkers.add(marker);
            if (typeof file.id === "string") {
              const fileIds = existingFileIds.get(marker) ?? new Set<string>();
              fileIds.add(file.id);
              existingFileIds.set(marker, fileIds);
            }
          }
        }
      }
      cursor = (response as any)?.response_metadata?.next_cursor?.trim() || undefined;
    } while (cursor);
  }
  const fileUploads: Array<{ filename: string; file: Buffer; alt_txt?: string }> = [];
  const cards: Array<{ fallbackText: string; blocks: Array<Record<string, unknown>>; marker?: string }> = [];
  const postedCardTs = new Set<string>();
  const postedFileIds = new Set<string>();
  const cleanupPosted = async (fileIds: readonly string[] = []): Promise<void> => {
    for (const fileId of fileIds) postedFileIds.add(fileId);
    const deleteCard = async (ts: string): Promise<void> => {
      if (!client.chat?.delete) throw new Error("Slack workflow card cleanup transport unavailable");
      try {
        await client.chat.delete({ channel, ts });
      } catch (error) {
        if (!slackDeleteAlreadyApplied(error)) throw error;
      }
    };
    const deleteFile = async (file: string): Promise<void> => {
      if (!client.files.delete) throw new Error("Slack file cleanup transport unavailable");
      try {
        await client.files.delete({ file });
      } catch (error) {
        if (!slackDeleteAlreadyApplied(error)) throw error;
      }
    };
    await Promise.all([...[...postedCardTs].map(deleteCard), ...[...postedFileIds].map(deleteFile)]);
  };
  const isCancelled = async (): Promise<boolean> => {
    try {
      return (await opts.isCancelled?.()) === true;
    } catch {
      return true;
    }
  };
  let messageTs: string | undefined;
  let reconciled = false;
  for (const [index, attachment] of attachments.entries()) {
    if (attachment.renderOnly && !client.chat?.postMessage) {
      throw new Error("render-only workflow card transport unavailable");
    }
    const marker = markerFor(index, attachment);
    if (marker && existingMarkers.has(marker)) {
      reconciled = true;
      if (isWorkflowArtifact(attachment)) {
        for (const ts of existingCardTs.get(marker) ?? []) {
          postedCardTs.add(ts);
          messageTs ??= ts;
        }
      }
      for (const fileId of existingFileIds.get(marker) ?? []) postedFileIds.add(fileId);
      continue;
    }
    let file: Buffer;
    try {
      file = await fetchBlob(attachment.blobId);
    } catch (err) {
      if (!fetchArtifact || !attachment.artifactId || !attachment.artifactViewerId) throw err;
      file = await fetchArtifact(attachment.artifactId, attachment.artifactViewerId);
    }
    if (await isCancelled()) {
      await cleanupPosted();
      return { uploaded: false };
    }
    if (file.length === 0) continue;
    if (isWorkflowArtifact(attachment) && client.chat) {
      try {
        const { envelope, card } = decodeWorkflowArtifactCard(file, SLACK_WORKFLOW_BASE_URL);
        cards.push({
          fallbackText: envelope.fallbackText,
          blocks: workflowArtifactBlocks(card),
          ...(marker ? { marker } : {}),
        });
        continue;
      } catch {
        if (attachment.renderOnly) throw new Error("render-only workflow card is invalid");
        throw new Error("workflow result could not be rendered safely");
      }
    }
    fileUploads.push({
      filename: attachment.name,
      file,
      ...(marker ? { alt_txt: `${attachment.name}\n${marker}` } : {}),
    });
  }

  if (await isCancelled()) {
    await cleanupPosted();
    return { uploaded: false };
  }
  for (let i = 0; i < cards.length; i++) {
    if (await isCancelled()) {
      await cleanupPosted();
      return { uploaded: false };
    }
    const card = cards[i]!;
    const lead = i === 0 ? opts.initialComment?.trim() : undefined;
    const blocks = [
      ...(lead
        ? [{ type: "section", text: { type: "mrkdwn", text: clipped(workflowArtifactSlackMrkdwn(lead), 3_000) } }]
        : []),
      ...card.blocks,
    ];
    const response = (await client.chat!.postMessage({
      channel,
      ...(threadTs ? { thread_ts: threadTs, reply_broadcast: false } : {}),
      text: neutralizeSlackFallbackText(lead ? `${lead}\n\n${card.fallbackText}` : card.fallbackText),
      blocks,
      mrkdwn: false,
      parse: "none",
      link_names: false,
      unfurl_links: false,
      unfurl_media: false,
      ...botIdentityArgs(),
      ...(card.marker
        ? { metadata: { event_type: "qm_delivery", event_payload: { idempotency_key: card.marker } } }
        : {}),
    })) as { ts?: unknown };
    if (response?.ts) {
      const ts = String(response.ts);
      postedCardTs.add(ts);
      messageTs ??= ts;
    }
    if (await isCancelled()) {
      await cleanupPosted();
      return { uploaded: false };
    }
  }

  if (!fileUploads.length) return { uploaded: reconciled || cards.length > 0, ...(messageTs ? { messageTs } : {}) };
  if (await isCancelled()) {
    await cleanupPosted();
    return { uploaded: false };
  }

  const response = await client.files.uploadV2({
    channel_id: channel,
    ...(threadTs ? { thread_ts: threadTs } : {}),
    ...(opts.initialComment && cards.length === 0 ? { initial_comment: opts.initialComment } : {}),
    file_uploads: fileUploads,
  });
  const fileIds = uploadedFileIds(response);
  for (const fileId of fileIds) postedFileIds.add(fileId);
  if (await isCancelled()) {
    await cleanupPosted();
    return { uploaded: false };
  }
  for (const fileId of fileIds) {
    const sharedTs = await waitForShareCommit(client, channel, fileId);
    messageTs ??= sharedTs;
  }
  if (await isCancelled()) {
    await cleanupPosted();
    return { uploaded: false };
  }
  return { uploaded: true, ...(messageTs ? { messageTs } : {}) };
}

export function uploadFailureNote(err: unknown): string {
  const e = err as { data?: { error?: string; needed?: string }; message?: string };
  const code = e?.data?.error ?? "";
  const msg = e?.message ?? String(err);
  const isPermission =
    code === "missing_scope" || code === "not_allowed_token_type" || code === "access_denied" || /scope/i.test(msg);
  if (isPermission) {
    const needed = e?.data?.needed ?? "files:write";
    return `⚠️ I couldn't attach the file(s) — check my upload permission (${needed}). (${msg})`;
  }
  return `⚠️ I couldn't attach the file(s): ${msg}`;
}
