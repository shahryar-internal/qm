import { normalizeEvidence } from "./evidence.mjs";
import { ReadOnlyHttpGateway } from "./http.mjs";
import {
  assertResolvedConnection,
  canonicalJson,
  ConnectorError,
  createDeadline,
  createResolvedConnection,
  createVolatileRequestState,
  defaultConnectorLimits,
  encodedJsonBytes,
  requestBinding,
  reserveVolatileRequestQuota,
  snapshotJson,
  validateConnectorLimits,
  verifyResponseBinding,
} from "./types.mjs";

const boundedInteger = (value, minimum, maximum) => {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new ConnectorError("invalid_request");
  }
  return value;
};

const boundedText = (value, maximum = 256) =>
  typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);

const responseArray = (content, key) => {
  if (!content || Array.isArray(content) || !Array.isArray(content[key])) {
    throw new ConnectorError("invalid_response");
  }
  return content[key];
};

const responseText = (content, key, maximum = 512) => {
  if (!content || Array.isArray(content) || !boundedText(content[key], maximum)) {
    throw new ConnectorError("invalid_response");
  }
  return content[key];
};

const boundedEvidence = (content, maxResponseBytes) => {
  if (encodedJsonBytes(content) > maxResponseBytes) {
    throw new ConnectorError("response_too_large");
  }
  return content;
};

const boundGateway = (connection, transport, limits) =>
  new ReadOnlyHttpGateway(transport, limits ?? defaultConnectorLimits);

export class InternalCalendarReadClient {
  constructor(connection, transport, limits) {
    this.connection = assertResolvedConnection(connection, "calendar");
    if (this.connection.rootResourceRef !== "primary") {
      throw new ConnectorError("untrusted_connection_resolution");
    }
    this.gateway = boundGateway(this.connection, transport, limits);
    Object.freeze(this);
  }

  async upcoming(window) {
    if (
      !window ||
      !(window.from instanceof Date) ||
      !(window.to instanceof Date) ||
      Number.isNaN(window.from.valueOf()) ||
      Number.isNaN(window.to.valueOf()) ||
      window.to <= window.from ||
      window.to.valueOf() - window.from.valueOf() > 31 * 86_400_000
    ) {
      throw new ConnectorError("invalid_request");
    }
    const maxResults = boundedInteger(window.maxResults, 1, 100);
    const maxPages = boundedInteger(window.maxPages ?? 1, 1, 4);
    const pages = [];
    const events = [];
    let pageToken;
    for (let page = 0; page < maxPages && events.length < maxResults; page += 1) {
      const result = await this.gateway.get(
        this.connection,
        "calendar_events",
        "/calendar/v3/calendars/primary/events",
        {
          timeMin: window.from.toISOString(),
          timeMax: window.to.toISOString(),
          maxResults: String(Math.min(50, maxResults - events.length)),
          singleEvents: "true",
          orderBy: "startTime",
          ...(pageToken ? { pageToken } : {}),
        },
      );
      const items = responseArray(result.content, "items");
      events.push(...items.slice(0, maxResults - events.length));
      pages.push(result);
      const candidate = result.content.nextPageToken;
      if (candidate === undefined) {
        break;
      }
      if (!boundedText(candidate, 512)) {
        throw new ConnectorError("invalid_response");
      }
      pageToken = candidate;
    }
    const content = boundedEvidence({ events, pageCount: pages.length }, this.gateway.limits.maxResponseBytes);
    return normalizeEvidence(
      "calendar",
      this.connection,
      "calendar.upcoming",
      { pages: pages.map((page) => page.request), maxResults, maxPages },
      content,
    );
  }
}

const gmailMessageId = /^[A-Za-z0-9_-]{3,160}$/;
const messageHeaderNames = new Set(["from", "to", "subject", "date", "reply-to"]);

const messageCandidates = (content) =>
  responseArray(content, "messages").map((entry) => {
    if (!entry || Array.isArray(entry) || !gmailMessageId.test(entry.id) || !gmailMessageId.test(entry.threadId)) {
      throw new ConnectorError("invalid_response");
    }
    return Object.freeze({ id: entry.id, threadId: entry.threadId });
  });

const chooseMessages = (candidates, maxMessages, maxThreads) => {
  const selected = [];
  const threads = new Set();
  for (const candidate of candidates) {
    if (selected.length >= maxMessages) {
      break;
    }
    if (!threads.has(candidate.threadId) && threads.size >= maxThreads) {
      continue;
    }
    threads.add(candidate.threadId);
    selected.push(candidate);
  }
  return selected;
};

const decodeBase64Url = (value) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new ConnectorError("invalid_response");
  }
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value) {
      throw new ConnectorError("invalid_response");
    }
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new ConnectorError("invalid_response");
  }
};

const normalizeHeaders = (headers) => {
  if (headers === undefined) {
    return Object.freeze({});
  }
  if (!Array.isArray(headers) || headers.length > 100) {
    throw new ConnectorError("invalid_response");
  }
  const output = Object.create(null);
  for (const header of headers) {
    if (!header || Array.isArray(header) || !boundedText(header.name, 128) || !boundedText(header.value, 2_048)) {
      throw new ConnectorError("invalid_response");
    }
    const name = header.name.toLowerCase();
    if (messageHeaderNames.has(name) && output[name] === undefined) {
      output[name] = header.value;
    }
  }
  return Object.freeze(output);
};

const dispositionToken = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const dispositionQuotedValue = /^"(?:[^"\\\r\n]|\\[^\r\n])*"$/;
const dispositionParameter = (value) => {
  const divider = value.indexOf("=");
  if (divider < 1) {
    return false;
  }
  const name = value.slice(0, divider).trim();
  const parameterValue = value.slice(divider + 1).trim();
  return (
    dispositionToken.test(name) &&
    (dispositionToken.test(parameterValue) || dispositionQuotedValue.test(parameterValue))
  );
};

const contentDisposition = (headers) => {
  if (headers === undefined) {
    return undefined;
  }
  if (!Array.isArray(headers)) {
    throw new ConnectorError("invalid_response");
  }
  const values = headers
    .filter((header) => boundedText(header?.name, 128) && header.name.toLowerCase() === "content-disposition")
    .map((header) => header.value);
  if (values.length === 0) {
    return undefined;
  }
  if (values.length !== 1 || !boundedText(values[0], 2_048)) {
    throw new ConnectorError("invalid_response");
  }
  const segments = values[0].split(";");
  const kind = segments.shift().trim().toLowerCase();
  if (!["inline", "attachment"].includes(kind) || segments.some((segment) => !dispositionParameter(segment.trim()))) {
    throw new ConnectorError("invalid_response");
  }
  return kind;
};

const attachmentPart = (part) => {
  const disposition = contentDisposition(part.headers);
  const fileAttachment = part.filename !== undefined || part.body?.attachmentId !== undefined;
  if (disposition === "inline" && fileAttachment) {
    throw new ConnectorError("invalid_response");
  }
  return fileAttachment || disposition === "attachment";
};

const collectPlainText = (part, state, depth = 0) => {
  if (!part || Array.isArray(part) || depth > 8 || state.parts >= 64) {
    throw new ConnectorError("invalid_response");
  }
  state.parts += 1;
  if (part.mimeType === "text/plain" && part.body?.data !== undefined && !attachmentPart(part)) {
    const text = decodeBase64Url(part.body.data);
    if (
      new TextEncoder().encode(text).byteLength > 16_384 ||
      state.bytes + new TextEncoder().encode(text).byteLength > 16_384
    ) {
      throw new ConnectorError("response_too_large");
    }
    state.bytes += new TextEncoder().encode(text).byteLength;
    state.sections.push(text);
  }
  if (part.parts !== undefined) {
    if (!Array.isArray(part.parts) || part.parts.length > 50) {
      throw new ConnectorError("invalid_response");
    }
    for (const child of part.parts) {
      collectPlainText(child, state, depth + 1);
    }
  }
};

const projectGmailMessage = (candidate, content) => {
  if (
    !content ||
    Array.isArray(content) ||
    content.id !== candidate.id ||
    content.threadId !== candidate.threadId ||
    !content.payload ||
    Array.isArray(content.payload)
  ) {
    throw new ConnectorError("invalid_response");
  }
  const state = { parts: 0, bytes: 0, sections: [] };
  collectPlainText(content.payload, state);
  const snippet = content.snippet === undefined ? "" : responseText(content, "snippet", 4_096);
  return Object.freeze({
    id: candidate.id,
    threadId: candidate.threadId,
    headers: normalizeHeaders(content.payload.headers),
    snippet,
    plainText: state.sections.join("\n\n"),
  });
};

export class InternalGmailContextReadClient {
  constructor(connection, transport, limits) {
    this.connection = assertResolvedConnection(connection, "gmail");
    if (this.connection.rootResourceRef !== "inbox") {
      throw new ConnectorError("untrusted_connection_resolution");
    }
    this.gateway = boundGateway(this.connection, transport, limits);
    Object.freeze(this);
  }

  async recentInbox(options) {
    if (!options) {
      throw new ConnectorError("invalid_request");
    }
    const maxMessages = boundedInteger(options.maxMessages, 1, 5);
    const maxThreads = boundedInteger(options.maxThreads, 1, 5);
    const list = await this.gateway.get(
      this.connection,
      "gmail_messages",
      "/gmail/v1/users/me/messages",
      {
        labelIds: "INBOX",
        maxResults: String(maxMessages * 4),
        includeSpamTrash: "false",
      },
      { maxResponseBytes: 32_768 },
    );
    const selected = chooseMessages(messageCandidates(list.content), maxMessages, maxThreads);
    const details = [];
    for (const candidate of selected) {
      const result = await this.gateway.get(
        this.connection,
        "gmail_message",
        `/gmail/v1/users/me/messages/${candidate.id}`,
        { format: "full" },
        { maxResponseBytes: 32_768 },
      );
      details.push(Object.freeze({ message: projectGmailMessage(candidate, result.content), request: result.request }));
    }
    const content = boundedEvidence({ messages: details.map(({ message }) => message) }, 131_072);
    return normalizeEvidence(
      "gmail",
      this.connection,
      "gmail.recent_inbox_context",
      {
        list: list.request,
        messages: details.map(({ message, request }) => ({ id: message.id, threadId: message.threadId, request })),
        maxMessages,
        maxThreads,
      },
      content,
    );
  }
}

export const clarifyObjectTypes = Object.freeze(["deal", "person", "company", "meeting", "task"]);

const validClarifyField = (value) => typeof value === "string" && /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(value);

const normalizeFilters = (filters = {}) => {
  if (!filters || typeof filters !== "object" || Array.isArray(filters)) {
    throw new ConnectorError("invalid_request");
  }
  const entries = Object.entries(filters);
  if (entries.length > 8 || !entries.every(([field, value]) => validClarifyField(field) && boundedText(value, 256))) {
    throw new ConnectorError("invalid_request");
  }
  return Object.fromEntries(entries.map(([field, value]) => [`filter[${field}]`, value]));
};

const normalizeSort = (sort) => {
  if (sort === undefined) {
    return {};
  }
  if (!sort || !validClarifyField(sort.column) || !["ASC", "DESC"].includes(sort.direction)) {
    throw new ConnectorError("invalid_request");
  }
  return { "sortOrder[column]": sort.column, "sortOrder[dir]": sort.direction };
};

export class InternalClarifyReadClient {
  constructor(connection, transport, limits) {
    this.connection = assertResolvedConnection(connection, "clarify");
    this.workspaceSlug = connection.rootResourceRef;
    this.gateway = boundGateway(this.connection, transport, limits);
    Object.freeze(this);
  }

  async listResources(query) {
    if (!query || !clarifyObjectTypes.includes(query.objectType)) {
      throw new ConnectorError("invalid_request");
    }
    const result = await this.gateway.get(
      this.connection,
      "clarify_resources",
      `/v1/workspaces/${this.workspaceSlug}/objects/${query.objectType}/resources`,
      {
        "page[limit]": String(boundedInteger(query.limit, 1, 100)),
        ...normalizeFilters(query.filters),
        ...normalizeSort(query.sort),
      },
    );
    return normalizeEvidence(
      "clarify",
      this.connection,
      `clarify.list_${query.objectType}`,
      result.request,
      boundedEvidence(result.content, this.gateway.limits.maxResponseBytes),
    );
  }
}

export const notionVersion = "2026-03-11";
const notionIdentifierPattern =
  /^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;
const notionHeaders = () => new Headers({ "Notion-Version": notionVersion });
const isNotionIdentifier = (value) => typeof value === "string" && notionIdentifierPattern.test(value);
const exactNotionParent = (value, relation, id) =>
  value &&
  !Array.isArray(value) &&
  typeof value === "object" &&
  Object.keys(value).length === 2 &&
  value.type === relation &&
  value[relation] === id;
const validNotionBlock = (block, target) =>
  block &&
  !Array.isArray(block) &&
  isNotionIdentifier(block.id) &&
  typeof block.has_children === "boolean" &&
  exactNotionParent(block.parent, target.depth === 0 ? "page_id" : "block_id", target.id);
const validNotionPage = (page, rootPageId) =>
  page && !Array.isArray(page) && page.object === "page" && page.id === rootPageId;

export class InternalNotionReadClient {
  constructor(connection, transport, limits) {
    this.connection = assertResolvedConnection(connection, "notion");
    if (!isNotionIdentifier(connection.rootResourceRef)) {
      throw new ConnectorError("untrusted_connection_resolution");
    }
    this.rootPageId = connection.rootResourceRef;
    this.gateway = boundGateway(this.connection, transport, limits);
    Object.freeze(this);
  }

  async rootPage() {
    const result = await this.gateway.get(
      this.connection,
      "notion_page",
      `/v1/pages/${this.rootPageId}`,
      {},
      { headers: notionHeaders() },
    );
    if (!validNotionPage(result.content, this.rootPageId)) {
      throw new ConnectorError("invalid_response");
    }
    return normalizeEvidence("notion", this.connection, "notion.root_page", result.request, result.content);
  }

  async rootTree(options) {
    if (!options) {
      throw new ConnectorError("invalid_request");
    }
    const pageSize = boundedInteger(options.pageSize, 1, 50);
    const maxPages = boundedInteger(options.maxPages, 1, 20);
    const maxBlocks = boundedInteger(options.maxBlocks, 1, 200);
    const maxDepth = boundedInteger(options.maxDepth, 0, 5);
    const pending = [{ id: this.rootPageId, parentId: null, depth: 0, cursor: undefined }];
    const pages = [];
    const blocks = [];
    let truncated = false;
    while (pending.length > 0 && pages.length < maxPages && blocks.length < maxBlocks) {
      const target = pending.shift();
      const result = await this.gateway.get(
        this.connection,
        "notion_children",
        `/v1/blocks/${target.id}/children`,
        {
          page_size: String(pageSize),
          ...(target.cursor ? { start_cursor: target.cursor } : {}),
        },
        { headers: notionHeaders() },
      );
      const results = responseArray(result.content, "results");
      pages.push(result);
      for (const block of results) {
        if (blocks.length >= maxBlocks) {
          truncated = true;
          break;
        }
        if (!validNotionBlock(block, target)) {
          throw new ConnectorError("invalid_response");
        }
        blocks.push(Object.freeze({ id: block.id, parentId: target.id, depth: target.depth, block }));
        if (block.has_children) {
          if (target.depth >= maxDepth) {
            truncated = true;
          } else {
            pending.push({ id: block.id, parentId: target.id, depth: target.depth + 1, cursor: undefined });
          }
        }
      }
      if (result.content.has_more === true) {
        pending.unshift({ ...target, cursor: responseText(result.content, "next_cursor") });
      } else if (result.content.has_more !== false) {
        throw new ConnectorError("invalid_response");
      }
    }
    if (pending.length > 0) {
      truncated = true;
    }
    const content = boundedEvidence(
      { blocks, pageCount: pages.length, complete: !truncated, limits: { pageSize, maxPages, maxBlocks, maxDepth } },
      this.gateway.limits.maxResponseBytes,
    );
    return normalizeEvidence(
      "notion",
      this.connection,
      "notion.root_tree",
      { pages: pages.map((page) => page.request), limits: { pageSize, maxPages, maxBlocks, maxDepth } },
      content,
    );
  }
}

export const commandCenterReadTools = Object.freeze([
  "brain_search",
  "brain_who_owns",
  "brain_project_status",
  "brain_person_context",
  "brain_what_changed_since",
  "brain_as_of",
  "brain_episodes_about",
  "brain_open_commitments_for_account",
  "brain_open_risks_for_account",
  "brain_slipped_initiatives",
  "brain_analytics_targetable_deployments",
]);

const brainVertexTypes = new Set([
  "Episode",
  "Person",
  "Organization",
  "Opportunity",
  "Deployment",
  "Initiative",
  "Workstream",
  "Task",
  "WeeklyOutcome",
  "Function",
  "Phase",
  "Decision",
  "Commitment",
  "Risk",
  "Objective",
  "KR",
  "KRScore",
]);
const brainEdgeLabels = new Set([
  "works_at",
  "champions",
  "participated_in",
  "knows",
  "introduced",
  "has",
  "partners_with",
  "competes_with",
  "converts_to",
  "expansion_of",
  "expanded_into",
  "integrates_with",
  "source_opportunity",
  "expansion_to_opportunity",
  "part_of",
  "has_subdeployment",
  "sponsor",
  "owning_org",
  "belongs_to",
  "owned_by",
  "has_task",
  "has_outcome",
  "has_workstream",
  "in_function",
  "in_phase",
  "advances",
  "depends_on",
  "blocked_by",
  "assigned_to",
  "contributes_to",
  "superseded_by",
  "cancelled_via",
  "constrains",
  "concerns",
  "decided_by",
  "supersedes",
  "references",
  "spawned",
  "triggered_in",
  "evidenced_by",
  "transfers_ownership_to",
  "owed_by",
  "owed_to",
  "fulfilled_via",
  "mitigated_by",
  "about",
  "mentions",
  "follows_from",
  "transcribes",
  "HAS_KR",
  "SCORE_OF",
  "SUPPORTS",
]);

const exactKeys = (value, required, optional = []) => {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const allowed = [...required, ...optional].sort();
  return required.every((key) => Object.hasOwn(value, key)) && actual.every((key) => allowed.includes(key));
};

const brainText = (value, maximum = 256) => boundedText(value, maximum);
const nullableText = (value, maximum = 256) => value === null || brainText(value, maximum);
const strictRfc3339 = (value) => {
  if (!brainText(value, 64)) {
    return false;
  }
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-](?:(?:0\d|1[0-3]):[0-5]\d|14:00))$/.exec(
      value,
    );
  if (!match) {
    return false;
  }
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    return false;
  }
  const offset =
    match[7] === "Z"
      ? 0
      : (match[7][0] === "+" ? 1 : -1) * (Number(match[7].slice(1, 3)) * 60 + Number(match[7].slice(4, 6)));
  const local = new Date(timestamp + offset * 60_000);
  return (
    local.getUTCFullYear() === Number(match[1]) &&
    local.getUTCMonth() + 1 === Number(match[2]) &&
    local.getUTCDate() === Number(match[3]) &&
    local.getUTCHours() === Number(match[4]) &&
    local.getUTCMinutes() === Number(match[5]) &&
    local.getUTCSeconds() === Number(match[6])
  );
};
const nullableIso = (value) => value === null || strictRfc3339(value);
const sourceUrl = (value) => {
  if (!brainText(value, 512)) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
};

const sameTextSet = (left, right) =>
  new Set(left).size === new Set(right).size && left.every((entry) => right.includes(entry));
const citedEpisode = (value) =>
  exactKeys(value, ["episodeId", "sourceUrl"]) && brainText(value.episodeId) && sourceUrl(value.sourceUrl);
const citation = (value) =>
  exactKeys(value, ["recordId", "episodeIds", "sourceUrls", "citedEpisodes"], ["evidence"]) &&
  brainText(value.recordId) &&
  Array.isArray(value.episodeIds) &&
  value.episodeIds.length >= 1 &&
  value.episodeIds.length <= 50 &&
  value.episodeIds.every((entry) => brainText(entry)) &&
  new Set(value.episodeIds).size === value.episodeIds.length &&
  Array.isArray(value.sourceUrls) &&
  value.sourceUrls.length >= 1 &&
  value.sourceUrls.length <= 50 &&
  value.sourceUrls.every(sourceUrl) &&
  new Set(value.sourceUrls).size === value.sourceUrls.length &&
  Array.isArray(value.citedEpisodes) &&
  value.citedEpisodes.length >= 1 &&
  value.citedEpisodes.length <= 50 &&
  value.citedEpisodes.every(citedEpisode) &&
  new Set(value.citedEpisodes.map((entry) => `${entry.episodeId}\u0000${entry.sourceUrl}`)).size ===
    value.citedEpisodes.length &&
  sameTextSet(
    value.episodeIds,
    value.citedEpisodes.map((entry) => entry.episodeId),
  ) &&
  sameTextSet(
    value.sourceUrls,
    value.citedEpisodes.map((entry) => entry.sourceUrl),
  ) &&
  (value.evidence === undefined || brainText(value.evidence, 20_000));

const passage = (value) =>
  exactKeys(value, ["passageId", "score", "text", "sourceId", "sourceUrl", "access"]) &&
  brainText(value.passageId) &&
  Number.isFinite(value.score) &&
  brainText(value.text, 20_000) &&
  brainText(value.sourceId) &&
  sourceUrl(value.sourceUrl) &&
  value.access === "normal";

const fact = (value) =>
  exactKeys(value, ["fromId", "label", "toId", "startedAt", "endedAt", "confidence", "citation"]) &&
  brainText(value.fromId) &&
  brainText(value.label) &&
  brainText(value.toId) &&
  nullableIso(value.startedAt) &&
  nullableIso(value.endedAt) &&
  Number.isFinite(value.confidence) &&
  value.confidence >= 0 &&
  value.confidence <= 1 &&
  citation(value.citation);

const all = (value, maximum, validator) => Array.isArray(value) && value.length <= maximum && value.every(validator);
const citationEquals = (left, right) => canonicalJson(left) === canonicalJson(right);
const citationSet = (value) => new Set(value.citations.map((entry) => entry.recordId));
const hasCitationsFor = (value, ids) => ids.every((id) => citationSet(value).has(id));
const hasExactCitationsFor = (value, citations) =>
  citations.every((entry) => value.citations.some((candidate) => citationEquals(candidate, entry)));
const citationCitesSource = (value, sourceId, sourceUrl) =>
  value.citedEpisodes.some((entry) => entry.episodeId === sourceId && entry.sourceUrl === sourceUrl);
const hasPassageCitations = (value, passages) =>
  passages.every((entry) =>
    value.citations.some(
      (citationEntry) =>
        citationEntry.recordId === entry.passageId &&
        citationCitesSource(citationEntry, entry.sourceId, entry.sourceUrl),
    ),
  );
const hasEpisodeCitations = (value, episodes) =>
  episodes.every((entry) =>
    value.citations.some(
      (citationEntry) =>
        citationEntry.recordId === entry.id && citationCitesSource(citationEntry, entry.id, entry.sourceUrl),
    ),
  );
const containsRestricted = (value) => {
  if (Array.isArray(value)) {
    return value.some(containsRestricted);
  }
  if (!value || typeof value !== "object") {
    return false;
  }
  return Object.entries(value).some(
    ([key, entry]) =>
      key === "includeRestricted" || (key === "access" && entry === "restricted") || containsRestricted(entry),
  );
};

const topCitations = (value) =>
  all(value.citations, 100, citation) &&
  new Set(value.citations.map((entry) => entry.recordId)).size === value.citations.length;
const outputValidators = Object.freeze({
  brain_search: (value) =>
    exactKeys(value, ["records", "citations"]) &&
    all(value.records, 100, passage) &&
    topCitations(value) &&
    hasPassageCitations(value, value.records),
  brain_who_owns: (value) =>
    exactKeys(value, ["owner", "citations"]) &&
    (value.owner === null
      ? topCitations(value)
      : exactKeys(value.owner, ["id", "name"]) &&
        brainText(value.owner.id) &&
        brainText(value.owner.name) &&
        topCitations(value) &&
        hasCitationsFor(value, [value.owner.id])),
  brain_project_status: (value) =>
    exactKeys(value, ["status", "evidence", "citations"]) &&
    value.status &&
    typeof value.status === "object" &&
    !Array.isArray(value.status) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value.status)) &&
    all(value.evidence, 100, passage) &&
    topCitations(value) &&
    hasPassageCitations(value, value.evidence) &&
    (Object.keys(value.status).length === 0 || (value.evidence.length > 0 && value.citations.length > 0)),
  brain_person_context: (value) =>
    exactKeys(value, ["facts", "passages", "citations"]) &&
    all(value.facts, 100, fact) &&
    all(value.passages, 100, passage) &&
    topCitations(value) &&
    hasExactCitationsFor(
      value,
      value.facts.map((entry) => entry.citation),
    ) &&
    hasPassageCitations(value, value.passages),
  brain_what_changed_since: (value) =>
    exactKeys(value, ["changes", "citations"]) &&
    all(value.changes, 100, fact) &&
    topCitations(value) &&
    hasExactCitationsFor(
      value,
      value.changes.map((entry) => entry.citation),
    ),
  brain_as_of: (value) =>
    exactKeys(value, ["records", "citations"]) &&
    all(value.records, 100, fact) &&
    topCitations(value) &&
    hasExactCitationsFor(
      value,
      value.records.map((entry) => entry.citation),
    ),
  brain_episodes_about: (value) =>
    exactKeys(value, ["episodes", "citations"]) &&
    all(
      value.episodes,
      100,
      (entry) =>
        exactKeys(entry, ["id", "title", "startedAt", "sourceUrl"]) &&
        brainText(entry.id) &&
        nullableText(entry.title) &&
        nullableIso(entry.startedAt) &&
        sourceUrl(entry.sourceUrl),
    ) &&
    topCitations(value) &&
    hasEpisodeCitations(value, value.episodes),
  brain_open_commitments_for_account: (value) =>
    exactKeys(value, ["commitments", "citations"]) &&
    all(
      value.commitments,
      100,
      (entry) =>
        exactKeys(entry, [
          "commitmentId",
          "description",
          "status",
          "kind",
          "dueAt",
          "overdue",
          "ownerId",
          "owedToId",
          "affectedEntityId",
          "citation",
        ]) &&
        brainText(entry.commitmentId) &&
        nullableText(entry.description, 20_000) &&
        nullableText(entry.status) &&
        nullableText(entry.kind) &&
        nullableIso(entry.dueAt) &&
        typeof entry.overdue === "boolean" &&
        nullableText(entry.ownerId) &&
        nullableText(entry.owedToId) &&
        brainText(entry.affectedEntityId) &&
        citation(entry.citation),
    ) &&
    topCitations(value) &&
    hasExactCitationsFor(
      value,
      value.commitments.map((entry) => entry.citation),
    ),
  brain_open_risks_for_account: (value) =>
    exactKeys(value, ["risks", "citations"]) &&
    all(
      value.risks,
      100,
      (entry) =>
        exactKeys(entry, [
          "riskId",
          "description",
          "severity",
          "likelihood",
          "status",
          "affectedEntityId",
          "mitigatedById",
          "mitigationOwnerId",
          "citation",
        ]) &&
        brainText(entry.riskId) &&
        nullableText(entry.description, 20_000) &&
        nullableText(entry.severity) &&
        nullableText(entry.likelihood) &&
        nullableText(entry.status) &&
        brainText(entry.affectedEntityId) &&
        nullableText(entry.mitigatedById) &&
        nullableText(entry.mitigationOwnerId) &&
        citation(entry.citation),
    ) &&
    topCitations(value) &&
    hasExactCitationsFor(
      value,
      value.risks.map((entry) => entry.citation),
    ),
  brain_slipped_initiatives: (value) =>
    exactKeys(value, ["initiatives", "citations"]) &&
    all(
      value.initiatives,
      100,
      (entry) =>
        exactKeys(entry, [
          "initiativeId",
          "workstreamId",
          "outcomeId",
          "outcomeStatus",
          "ownerId",
          "decisions",
          "citation",
        ]) &&
        brainText(entry.initiativeId) &&
        brainText(entry.workstreamId) &&
        brainText(entry.outcomeId) &&
        nullableText(entry.outcomeStatus) &&
        nullableText(entry.ownerId) &&
        all(
          entry.decisions,
          100,
          (decision) =>
            exactKeys(decision, ["decisionId", "description", "supersedesIds"]) &&
            brainText(decision.decisionId) &&
            nullableText(decision.description, 20_000) &&
            all(decision.supersedesIds, 100, (id) => brainText(id)),
        ) &&
        citation(entry.citation),
    ) &&
    topCitations(value) &&
    hasExactCitationsFor(
      value,
      value.initiatives.map((entry) => entry.citation),
    ),
  brain_analytics_targetable_deployments: (value) =>
    exactKeys(value, ["deployments"]) &&
    all(
      value.deployments,
      100,
      (entry) =>
        exactKeys(entry, ["id", "name", "orgDomain"]) &&
        brainText(entry.id) &&
        brainText(entry.name) &&
        nullableText(entry.orgDomain, 253),
    ),
});

const brainInputSchemas = Object.freeze({
  brain_search: Object.freeze({
    required: ["query"],
    optional: ["k"],
    validate: (input) =>
      brainText(input.query) && (input.k === undefined || boundedInteger(input.k, 1, 20) === input.k),
  }),
  brain_who_owns: Object.freeze({
    required: ["entityName"],
    optional: ["entityType"],
    validate: (input) =>
      brainText(input.entityName) && (input.entityType === undefined || brainVertexTypes.has(input.entityType)),
  }),
  brain_project_status: Object.freeze({
    required: ["entityName"],
    optional: ["entityType"],
    validate: (input) =>
      brainText(input.entityName) && (input.entityType === undefined || brainVertexTypes.has(input.entityType)),
  }),
  brain_person_context: Object.freeze({
    required: ["personName"],
    optional: [],
    validate: (input) => brainText(input.personName),
  }),
  brain_what_changed_since: Object.freeze({
    required: ["entityName", "sinceIso"],
    optional: ["label"],
    validate: (input) =>
      brainText(input.entityName) &&
      validInputDate(input.sinceIso) &&
      (input.label === undefined || brainEdgeLabels.has(input.label)),
  }),
  brain_as_of: Object.freeze({
    required: ["entityName", "asOfIso"],
    optional: ["label"],
    validate: (input) =>
      brainText(input.entityName) &&
      validInputDate(input.asOfIso) &&
      (input.label === undefined || brainEdgeLabels.has(input.label)),
  }),
  brain_episodes_about: Object.freeze({
    required: ["entityName"],
    optional: ["entityType", "k"],
    validate: (input) =>
      brainText(input.entityName) &&
      (input.entityType === undefined || brainVertexTypes.has(input.entityType)) &&
      (input.k === undefined || boundedInteger(input.k, 1, 50) === input.k),
  }),
  brain_open_commitments_for_account: Object.freeze({
    required: ["accountName"],
    optional: ["accountType"],
    validate: (input) =>
      brainText(input.accountName) && (input.accountType === undefined || brainVertexTypes.has(input.accountType)),
  }),
  brain_open_risks_for_account: Object.freeze({
    required: ["accountName"],
    optional: ["accountType"],
    validate: (input) =>
      brainText(input.accountName) && (input.accountType === undefined || brainVertexTypes.has(input.accountType)),
  }),
  brain_slipped_initiatives: Object.freeze({
    required: [],
    optional: ["initiativeName"],
    validate: (input) => input.initiativeName === undefined || brainText(input.initiativeName),
  }),
  brain_analytics_targetable_deployments: Object.freeze({ required: [], optional: [], validate: () => true }),
});

const validInputDate = (value) =>
  strictRfc3339(value) &&
  Date.parse(value) >= Date.parse("2010-01-01T00:00:00.000Z") &&
  Date.parse(value) <= Date.now() + 86_400_000;

const validateBrainInput = (tool, input) => {
  let snapshot;
  try {
    snapshot = snapshotJson(input);
  } catch {
    throw new ConnectorError("invalid_request");
  }
  const shape = brainInputSchemas[tool];
  if (!shape || !exactKeys(snapshot, shape.required, shape.optional) || !shape.validate(snapshot)) {
    throw new ConnectorError("invalid_request");
  }
  return snapshot;
};

const snapshotMcpResponse = (value) => {
  let snapshot;
  try {
    snapshot = snapshotJson(value);
  } catch {
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  if (
    !snapshot ||
    Array.isArray(snapshot) ||
    Object.keys(snapshot).length !== 2 ||
    !Object.hasOwn(snapshot, "binding") ||
    !Object.hasOwn(snapshot, "content")
  ) {
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  return snapshot;
};

export class InternalCommandCenterBrainReadClient {
  constructor(connection, transport, limits = defaultConnectorLimits) {
    this.connection = assertResolvedConnection(connection, "command_center_brain");
    if (!transport || typeof transport.invoke !== "function") {
      throw new ConnectorError("invalid_request");
    }
    this.transport = transport;
    this.limits = validateConnectorLimits(limits);
    this.state = createVolatileRequestState();
    Object.freeze(this);
  }

  async read(tool, input = {}) {
    if (!commandCenterReadTools.includes(tool)) {
      throw new ConnectorError("invalid_request");
    }
    const inputSnapshot = validateBrainInput(tool, input);
    if (encodedJsonBytes(inputSnapshot) > 8_192) {
      throw new ConnectorError("invalid_request");
    }
    reserveVolatileRequestQuota(this.state, this.limits);
    const binding = requestBinding(this.connection);
    const deadline = createDeadline(this.state, this.limits);
    try {
      const response = await deadline.race(() =>
        this.transport.invoke(
          Object.freeze({
            server: "command-center-brain",
            tool,
            input: inputSnapshot,
            signal: deadline.signal,
            maxResponseBytes: this.limits.maxResponseBytes,
            credentialLeaseRef: this.connection.credentialLeaseRef,
            actorRef: this.connection.principalRef,
            audit: Object.freeze({
              actorRef: this.connection.principalRef,
              serverAccountRef: this.connection.serverAccountRef,
              rootResourceRef: this.connection.rootResourceRef,
              bindingNonce: this.connection.bindingNonce,
            }),
            ...binding,
          }),
        ),
      );
      const responseSnapshot = snapshotMcpResponse(response);
      verifyResponseBinding(this.connection, responseSnapshot.binding);
      const content = responseSnapshot.content;
      if (
        !outputValidators[tool](content) ||
        containsRestricted(content) ||
        encodedJsonBytes(content) > this.limits.maxResponseBytes
      ) {
        throw new ConnectorError("invalid_response");
      }
      return normalizeEvidence(
        "command_center_brain",
        this.connection,
        `command_center_brain.${tool}`,
        { server: "command-center-brain", tool, input: inputSnapshot },
        content,
      );
    } finally {
      deadline.finish();
    }
  }
}

const validServiceReference = (value, pattern) => typeof value === "string" && pattern.test(value);
const serviceConnectionPattern = /^conn_[A-Za-z0-9_-]{8,160}$/;
const serviceActorPattern = /^usr_[A-Za-z0-9_-]{8,160}$/;

export class ConnectorService {
  constructor(resolver, limits = defaultConnectorLimits) {
    if (!resolver || typeof resolver.resolve !== "function") {
      throw new ConnectorError("invalid_request");
    }
    this.resolver = resolver;
    this.limits = validateConnectorLimits(limits);
    Object.freeze(this);
  }

  async inspect(connectionRef, actorRef) {
    if (
      !validServiceReference(connectionRef, serviceConnectionPattern) ||
      !validServiceReference(actorRef, serviceActorPattern)
    ) {
      throw new ConnectorError("invalid_request");
    }
    let record;
    try {
      record = await this.resolver.resolve(Object.freeze({ connectionRef, actorRef }));
    } catch (error) {
      if (error instanceof ConnectorError) {
        throw error;
      }
      throw new ConnectorError("connection_resolution_failed");
    }
    let connection;
    try {
      connection = createResolvedConnection(record);
    } catch (error) {
      if (error instanceof ConnectorError) {
        throw new ConnectorError("connection_not_active");
      }
      throw error;
    }
    if (connection.connectionRef !== connectionRef || connection.principalRef !== actorRef) {
      throw new ConnectorError("connection_not_active");
    }
    return Object.freeze({
      provider: connection.provider,
      connectionRef: connection.connectionRef,
      actorRef: connection.principalRef,
      state: "inert",
    });
  }

  async open(connectionRef, actorRef) {
    await this.inspect(connectionRef, actorRef);
    throw new ConnectorError("connector_live_adapter_unavailable");
  }
}

export const createConnectorService = (resolver, limits) => new ConnectorService(resolver, limits);
