import assert from "node:assert/strict";
import { mock, test } from "node:test";
import type { SlackCoreClient } from "../src/slack/index.ts";
import type { TurnResult } from "../src/types.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createSlackAgentContextStore } from "../src/surfaces/slack-agent-context.ts";
import { createSlackAgentSessionStore } from "../src/surfaces/slack-agent-session.ts";
import { slackAgentBindingToken } from "../src/surfaces/slack-agent-session.ts";
import { createSlackApprovalAuthorityStore } from "../src/surfaces/slack-approval-authority.ts";
import {
  createSlackReactionCleanupStore,
  recoverSlackReactionCleanupAdmissions,
} from "../src/surfaces/slack-reaction-cleanup.ts";
import { createSlackReactionDesireStore } from "../src/surfaces/slack-reaction-desire.ts";
import { createSlackAgentStatusIntentStore } from "../src/surfaces/slack-agent-status-intent.ts";
import { SECURITY_QUARANTINE_REFUSAL_TEXT } from "../plugins/chassis/src/security-quarantine.ts";

type Handler = (args: any) => Promise<void>;

class FakeSocketModeClient {
  on(): void {}
  async start(): Promise<void> {}
  async disconnect(): Promise<void> {}
}

class FakeSlackClient {
  readonly posts: any[] = [];
  readonly ephemerals: any[] = [];
  readonly updates: any[] = [];
  readonly deletes: any[] = [];
  readonly reactionsAdded: any[] = [];
  readonly reactionsRemoved: any[] = [];
  readonly usersById = new Map<string, any>();
  readonly channelsById = new Map<string, any>();
  readonly membersByChannel = new Map<string, string[]>();
  readonly messagesByChannel = new Map<string, any[]>();
  readonly membershipFailures = new Set<string>();
  readonly membershipListings = new Map<string, number>();
  readonly botsById = new Map<string, any>();
  membershipDelayMs = 0;
  activeMembershipListings = 0;
  maxActiveMembershipListings = 0;
  firstMembershipListingStartedAt: number | undefined;
  groupListings = 0;
  failGroupListing = false;
  failNextPostAfterRecord = false;
  failNextApprovalFinalUpdate = false;
  failNextUpdateText: string | undefined;
  private postSequence = 0;

  readonly auth = {
    test: async () => ({
      team_id: "T1",
      app_id: "A1",
      user_id: "UBOT",
      bot_id: "BBOT",
      user: "qmbot",
      team: "Acme",
      url: "https://acme.slack.com/",
    }),
  };
  readonly emoji = { list: async () => ({ emoji: {} }) };
  readonly users = {
    info: async ({ user }: { user: string }) => ({ user: this.usersById.get(user) }),
    lookupByEmail: async ({ email }: { email: string }) => ({
      user: [...this.usersById.values()].find((u) => u.profile?.email === email),
    }),
  };
  readonly conversations = {
    info: async ({ channel }: { channel: string }) => ({ channel: this.channelsById.get(channel) }),
    replies: async ({ channel, ts }: { channel: string; ts: string }) => ({
      messages: (this.messagesByChannel.get(channel) ?? []).filter((m) => m.ts === ts || m.thread_ts === ts),
      has_more: false,
    }),
    history: async ({ channel, latest }: { channel: string; latest?: string }) => ({
      messages: (this.messagesByChannel.get(channel) ?? []).filter((m) => !latest || m.ts === latest),
      has_more: false,
    }),
    open: async () => ({ channel: { id: "DOPEN" } }),
    setTopic: async ({ channel, topic }: { channel: string; topic: string }) => {
      this.topics.push({ channel, topic });
      const existing = this.channelsById.get(channel) ?? { id: channel };
      this.channelsById.set(channel, { ...existing, topic: { value: topic, creator: "UBOT" } });
      return { ok: true };
    },
  };
  readonly topics: { channel: string; topic: string }[] = [];
  readonly pinnedByChannel = new Map<string, { ts: string; user: string; text: string }[]>();
  readonly pins = {
    list: async ({ channel }: { channel: string }) => ({
      items: (this.pinnedByChannel.get(channel) ?? []).map((message) => ({ message })),
    }),
    add: async ({ channel, timestamp }: { channel: string; timestamp: string }) => {
      const lastPost = this.posts.filter((p) => p.channel === channel).at(-1);
      const pinned = this.pinnedByChannel.get(channel) ?? [];
      pinned.push({ ts: timestamp, user: "UBOT", text: lastPost?.text ?? "" });
      this.pinnedByChannel.set(channel, pinned);
      return { ok: true };
    },
    remove: async ({ channel, timestamp }: { channel: string; timestamp: string }) => {
      this.pinnedByChannel.set(
        channel,
        (this.pinnedByChannel.get(channel) ?? []).filter((m) => m.ts !== timestamp),
      );
      return { ok: true };
    },
  };
  readonly chat = {
    postMessage: async (body: any) => {
      const ts = `1700000000.${String(++this.postSequence).padStart(6, "0")}`;
      this.posts.push(body);
      this.messagesByChannel.set(body.channel, [
        ...(this.messagesByChannel.get(body.channel) ?? []),
        { ...body, ts, ...(body.thread_ts ? { thread_ts: body.thread_ts } : {}) },
      ]);
      if (this.failNextPostAfterRecord) {
        this.failNextPostAfterRecord = false;
        throw new Error("simulated unknown post outcome");
      }
      return { ok: true, ts };
    },
    postEphemeral: async (body: any) => {
      this.ephemerals.push(body);
      return { ok: true, message_ts: `ephemeral-${this.ephemerals.length}` };
    },
    update: async (body: any) => {
      this.updates.push(body);
      if (this.failNextApprovalFinalUpdate && String(body.text ?? "").startsWith("Approved; ran ")) {
        this.failNextApprovalFinalUpdate = false;
        throw new Error("simulated crash before approval settlement");
      }
      if (this.failNextUpdateText === body.text) {
        this.failNextUpdateText = undefined;
        throw new Error("simulated crash before terminal card settlement");
      }
      return { ok: true, ts: body.ts };
    },
    delete: async (body: any) => {
      this.deletes.push(body);
      return { ok: true };
    },
  };
  readonly reactions = {
    add: async (body: any) => {
      this.reactionsAdded.push(body);
      return { ok: true };
    },
    remove: async (body: any) => {
      this.reactionsRemoved.push(body);
      return { ok: true };
    },
    get: async () => ({}),
  };
  readonly filesById = new Map<string, any>();
  readonly fileInfoCalls: string[] = [];
  readonly fileUploads: any[] = [];
  readonly fileDeletes: any[] = [];
  readonly files = {
    uploadV2: async (args: any) => {
      this.fileUploads.push(args);
      const ts = `1700000000.${String(++this.postSequence).padStart(6, "0")}`;
      this.messagesByChannel.set(args.channel_id, [
        ...(this.messagesByChannel.get(args.channel_id) ?? []),
        {
          ts,
          ...(args.thread_ts ? { thread_ts: args.thread_ts } : {}),
          files: (args.file_uploads ?? []).map((file: any) => ({ name: file.filename, alt_txt: file.alt_txt })),
        },
      ]);
      return { ok: true };
    },
    info: async ({ file }: { file: string }) => {
      this.fileInfoCalls.push(file);
      return { file: this.filesById.get(file) ?? {} };
    },
    delete: async (args: any) => {
      this.fileDeletes.push(args);
      return { ok: true };
    },
  };
  readonly bots = { info: async ({ bot }: { bot: string }) => ({ bot: this.botsById.get(bot) }) };

  async *paginate(method: string, args: any): AsyncGenerator<any> {
    if (method === "users.list") {
      yield { members: [...this.usersById.values()] };
      return;
    }
    if (method === "conversations.list") {
      const types = String(args.types ?? "");
      if (types === "mpim") {
        this.groupListings++;
        if (this.failGroupListing) throw new Error("missing mpim:read");
      }
      yield {
        channels: [...this.channelsById.values()].filter((c) => (types === "mpim" ? c.is_mpim : !c.is_mpim)),
      };
      return;
    }
    if (method === "conversations.members") {
      this.firstMembershipListingStartedAt ??= Date.now();
      this.membershipListings.set(args.channel, (this.membershipListings.get(args.channel) ?? 0) + 1);
      this.activeMembershipListings++;
      this.maxActiveMembershipListings = Math.max(this.maxActiveMembershipListings, this.activeMembershipListings);
      try {
        if (this.membershipDelayMs) await new Promise((resolve) => setTimeout(resolve, this.membershipDelayMs));
        if (this.membershipFailures.has(args.channel)) throw new Error("missing conversations:read");
        yield { members: this.membersByChannel.get(args.channel) ?? [] };
      } finally {
        this.activeMembershipListings--;
      }
      return;
    }
    throw new Error(`unexpected pagination method: ${method}`);
  }
}

class FakeApp {
  static instances: FakeApp[] = [];
  readonly client = new FakeSlackClient();
  readonly receiver: any;
  readonly messageHandlers: Handler[] = [];
  readonly eventHandlers = new Map<string, Handler[]>();
  readonly actionHandlers: Array<{ pattern: RegExp | string; handler: Handler }> = [];
  readonly actionAcks: Array<{ actionId: string; value: string }> = [];
  failNextActionAckAfterAck = false;
  started = false;

  constructor(opts: any) {
    this.receiver = opts.receiver;
    FakeApp.instances.push(this);
  }

  message(handler: Handler): void {
    this.messageHandlers.push(handler);
  }

  event(name: string, handler: Handler): void {
    this.eventHandlers.set(name, [...(this.eventHandlers.get(name) ?? []), handler]);
  }

  action(pattern: RegExp | string, handler: Handler): void {
    this.actionHandlers.push({ pattern, handler });
  }

  async start(): Promise<void> {
    this.started = true;
  }

  async stop(): Promise<void> {
    this.started = false;
  }

  async emitMessage(
    message: any,
    eventId = `Ev-${message.channel}-${message.ts}`,
    context: Record<string, unknown> = {},
  ): Promise<void> {
    for (const handler of this.messageHandlers) {
      await handler({ message, body: { event_id: eventId }, client: this.client, context });
    }
  }

  async emitEvent(
    name: string,
    event: any,
    eventId = `Ev-${name}-${event.channel}-${event.ts}`,
    context: Record<string, unknown> = {},
  ): Promise<void> {
    for (const handler of this.eventHandlers.get(name) ?? []) {
      await handler({ event, body: { event_id: eventId }, client: this.client, context });
    }
  }

  async emitAction(actionId: string, value: string, body: any): Promise<void> {
    const registered = this.actionHandlers.find(({ pattern }) => {
      if (typeof pattern === "string") return pattern === actionId;
      pattern.lastIndex = 0;
      return pattern.test(actionId);
    });
    assert.ok(registered, `no action handler for ${actionId}`);
    const sourceTs = body.message?.thread_ts ?? body.message?.ts ?? "100.1";
    await registered.handler({
      ack: async () => {
        this.actionAcks.push({ actionId, value });
        if (this.failNextActionAckAfterAck) {
          this.failNextActionAckAfterAck = false;
          throw new Error("simulated crash after Slack action acknowledgment");
        }
      },
      body,
      action: {
        action_id: actionId,
        value,
        action_ts: body.action_ts ?? (Number(sourceTs) + 0.01).toFixed(6),
      },
      client: this.client,
    });
  }
}

mock.module("@slack/bolt", { defaultExport: { App: FakeApp, LogLevel: { INFO: "info" } } });
mock.module("@slack/socket-mode", { namedExports: { SocketModeClient: FakeSocketModeClient } });
mock.module("@slack/web-api", { namedExports: { WebClient: class {} } });

const { slackPluginConfigFromEnv, startSlackPlugin } = await import("../src/slack/index.ts");

class FakeCore implements SlackCoreClient {
  readonly turns: any[] = [];
  readonly ingests: any[][] = [];
  readonly directories: any[] = [];
  readonly ackPicks: Array<{ text: string; candidates: readonly string[] }> = [];
  externalParticipants = false;
  result: TurnResult = { status: "ok", reply: "agent reply" };
  submitError: Error | undefined;
  activeRun: string | undefined;
  abortedRuns: string[] = [];
  readonly stopInputs: Array<Parameters<SlackCoreClient["stopSlackAgentSession"]>[0]> = [];
  abortError: Error | undefined;
  private abortGate: Promise<void> | undefined;
  private releaseAbortGate: (() => void) | undefined;
  private blobGate: Promise<void> | undefined;
  private releaseBlobGate: (() => void) | undefined;
  queuedRunId: string | undefined;
  private heldRunClaimed = false;
  readonly polled: string[] = [];
  readonly ackedRunDeliveries: string[] = [];
  blobReads = 0;
  readonly deltasOnRelease: string[] = [];
  readonly tasksOnRelease: any[] = [];
  private runGate: Promise<void> | undefined;
  private releaseRun: (() => void) | undefined;
  private submitGate: Promise<void> | undefined;
  private releaseSubmit: (() => void) | undefined;
  submitStarted = 0;
  readonly modelChangeListeners: Array<(scope: any) => void> = [];
  readonly headerPinChangeListeners: Array<(scope: any) => void> = [];
  readonly headerPinScopes = new Set<string>();
  readonly approvalRecords = new Map<string, any>();
  readonly agentContexts = createSlackAgentContextStore(createMemoryMap<any>());
  readonly agentSessions = createSlackAgentSessionStore(createMemoryMap<any>());
  readonly agentStatusIntents = createSlackAgentStatusIntentStore(createMemoryMap<any>());
  readonly reactionDesires = createSlackReactionDesireStore(createMemoryMap<any>());
  readonly reactionCleanups = createSlackReactionCleanupStore(createMemoryMap<any>());
  readonly approvalAuthorityBacking = createMemoryMap<any>();
  readonly approvalContinuationBacking = createMemoryMap<any>();
  approvalNow = Date.now();
  readonly approvalAuthorities = createSlackApprovalAuthorityStore(
    this.approvalAuthorityBacking,
    () => this.approvalNow,
    this.approvalContinuationBacking,
  );
  readonly acceptedIntake = new Map<string, string>();
  readonly runRequests = new Map<string, any>();
  durableIntake = false;
  deferNextAgentStop = false;
  failNextApprovalSubmitMark = false;
  failNextApprovalSettle = false;
  approvalSettlementAttempts = 0;
  failNextWaitRun = false;
  crashAfterApprovalSubmitMark = false;
  approvalFetchError: Error | undefined;
  approvalAuthorityReadError: Error | undefined;

  async primeAgentSession(threadTs: string, runId: string, streamTs?: string): Promise<void> {
    const key = { teamId: "T1", agentId: "A1", channelId: "D1", threadTs };
    const token = slackAgentBindingToken(key, "U1", threadTs, threadTs);
    await this.agentSessions.begin({
      ...key,
      ownerUserId: "U1",
      token,
      triggerTs: threadTs,
      coreThreadRef: `dm:D1:${threadTs}`,
      authorityMessageTs: threadTs,
    });
    await this.agentSessions.bindRun({ ...key, token, runId });
    if (streamTs) await this.bindSlackAgentStream({ ...key, token, streamTs });
    this.activeRun = runId;
  }

  saveSlackAgentContext(input: Parameters<SlackCoreClient["saveSlackAgentContext"]>[0]) {
    return this.agentContexts.saveCurrent(input);
  }
  bindSlackAgentThread(input: Parameters<SlackCoreClient["bindSlackAgentThread"]>[0]) {
    return this.agentContexts.bindThread(input);
  }
  getSlackAgentThread(input: Parameters<SlackCoreClient["getSlackAgentThread"]>[0]) {
    return this.agentContexts.getThread(input);
  }
  renameSlackAgentSession(input: Parameters<SlackCoreClient["renameSlackAgentSession"]>[0]) {
    return this.agentSessions.rename(input);
  }
  beginSlackAgentSession(input: Parameters<SlackCoreClient["beginSlackAgentSession"]>[0]) {
    return this.agentSessions.begin(input);
  }
  prepareSlackAgentSubmission(input: Parameters<SlackCoreClient["prepareSlackAgentSubmission"]>[0]) {
    return this.agentSessions.prepareSubmission(input);
  }
  bindSlackAgentRun(input: Parameters<SlackCoreClient["bindSlackAgentRun"]>[0]) {
    return this.agentSessions.bindRun(input);
  }
  bindSlackAgentStream(input: Parameters<SlackCoreClient["bindSlackAgentStream"]>[0]) {
    return this.agentSessions.bindStream({
      ...input,
      streamTs: /^\d+(?:\.\d+)?$/.test(input.streamTs) ? input.streamTs : "9999999999.000001",
    });
  }
  slackAgentSessionCancelled(input: Parameters<SlackCoreClient["slackAgentSessionCancelled"]>[0]) {
    return this.agentSessions.cancelled(input);
  }
  finishSlackAgentSession(input: Parameters<SlackCoreClient["finishSlackAgentSession"]>[0]) {
    return this.agentSessions.finish(input);
  }
  completeSlackAgentSession(input: Parameters<SlackCoreClient["completeSlackAgentSession"]>[0]) {
    return this.agentSessions.complete(input);
  }
  async slackAgentSessionStatus(input: Parameters<SlackCoreClient["slackAgentSessionStatus"]>[0]) {
    return (await this.agentSessions.get(input))?.status ?? null;
  }
  claimSlackAgentProviderWrite(input: Parameters<SlackCoreClient["claimSlackAgentProviderWrite"]>[0]) {
    return this.agentSessions.claimProviderWrite(input);
  }
  deferSlackAgentProviderWrite(input: Parameters<SlackCoreClient["deferSlackAgentProviderWrite"]>[0]) {
    return this.agentSessions.deferProviderWrite(input);
  }
  completeSlackAgentProviderWrite(input: Parameters<SlackCoreClient["completeSlackAgentProviderWrite"]>[0]) {
    return this.agentSessions.completeProviderWrite(input);
  }
  releaseSlackAgentProviderWrite(input: Parameters<SlackCoreClient["releaseSlackAgentProviderWrite"]>[0]) {
    return this.agentSessions.releaseProviderWrite(input);
  }
  async enqueueSlackAgentStatusIntent(input: Parameters<SlackCoreClient["enqueueSlackAgentStatusIntent"]>[0]) {
    const session = await this.agentSessions.get(input);
    const authority = input.authority;
    let authorized: boolean;
    if (authority.kind === "binding") {
      authorized = session?.bindings.some((binding) => binding.token === authority.token) === true;
    } else if (authority.kind === "stop") {
      authorized =
        session?.stopEvents.some(
          (event) => event.eventId === authority.eventId && event.applicable && event.state === "pending",
        ) === true;
    } else {
      const approval = await this.approvalAuthorities.get({
        teamId: input.teamId,
        agentId: input.agentId,
        requesterUserId: authority.requesterUserId,
        requestId: authority.requestId,
      });
      authorized = approval?.channelId === authority.channelId && approval.messageTs === authority.messageTs;
    }
    if (!authorized) throw new Error("Slack Agent status intent authority was not accepted");
    return this.agentStatusIntents.enqueue(input);
  }
  claimSlackAgentStatusIntents(input: Parameters<SlackCoreClient["claimSlackAgentStatusIntents"]>[0]) {
    return this.agentStatusIntents.claimDue(input);
  }
  async slackAgentStatusIntentClaimActive(input: Parameters<SlackCoreClient["slackAgentStatusIntentClaimActive"]>[0]) {
    if (!(await this.agentStatusIntents.claimActive(input))) return false;
    const session = await this.agentSessions.get(input);
    const authority = input.authority;
    if (authority.kind === "binding") {
      const binding = session?.bindings.find((candidate) => candidate.token === authority.token);
      return !!binding && !binding.cancelEventId && !binding.cancelRequestedAt;
    }
    if (authority.kind === "stop") {
      return (
        session?.stopEvents.some(
          (event) => event.eventId === authority.eventId && event.applicable && event.state === "pending",
        ) === true
      );
    }
    const approval = await this.approvalAuthorities.get({
      teamId: input.teamId,
      agentId: input.agentId,
      requesterUserId: authority.requesterUserId,
      requestId: authority.requestId,
    });
    return approval?.channelId === authority.channelId && approval.messageTs === authority.messageTs;
  }
  completeSlackAgentStatusIntent(input: Parameters<SlackCoreClient["completeSlackAgentStatusIntent"]>[0]) {
    return this.agentStatusIntents.complete(input);
  }
  deferSlackAgentStatusIntent(
    claim: Parameters<SlackCoreClient["deferSlackAgentStatusIntent"]>[0],
    input: Parameters<SlackCoreClient["deferSlackAgentStatusIntent"]>[1],
  ) {
    return this.agentStatusIntents.defer(claim, input);
  }
  failSlackAgentStatusIntent(
    claim: Parameters<SlackCoreClient["failSlackAgentStatusIntent"]>[0],
    input: Parameters<SlackCoreClient["failSlackAgentStatusIntent"]>[1],
  ) {
    return this.agentStatusIntents.fail(claim, input);
  }
  reopenSlackAgentStatusIntentAfterStaleEffect(
    claim: Parameters<SlackCoreClient["reopenSlackAgentStatusIntentAfterStaleEffect"]>[0],
    input: Parameters<SlackCoreClient["reopenSlackAgentStatusIntentAfterStaleEffect"]>[1],
  ) {
    return this.agentStatusIntents.reopenCurrentAfterStaleEffect(claim, input);
  }
  getSlackAgentStatusIntent(input: Parameters<SlackCoreClient["getSlackAgentStatusIntent"]>[0]) {
    return this.agentStatusIntents.get(input);
  }
  async admitSlackReactionDesire(input: Parameters<SlackCoreClient["admitSlackReactionDesire"]>[0]) {
    const session = await this.agentSessions.get({
      teamId: input.teamId,
      agentId: input.agentId,
      channelId: input.sessionChannelId,
      threadTs: input.sessionThreadTs,
    });
    const binding = session?.bindings.find((candidate) => candidate.token === input.sessionToken);
    if (!binding || binding.cancelEventId || binding.cancelRequestedAt) {
      throw new Error("Slack reaction desire requires an exact active Agent Session binding");
    }
    return this.reactionDesires.admit(input);
  }
  async cancelSlackReactionDesire(input: Parameters<SlackCoreClient["cancelSlackReactionDesire"]>[0]) {
    const authorized = await this.agentSessions.cancellationLatched({
      teamId: input.teamId,
      agentId: input.agentId,
      channelId: input.sessionChannelId,
      threadTs: input.sessionThreadTs,
      token: input.sessionToken,
    });
    if (!authorized) throw new Error("Slack reaction desire cancellation requires an exact cancellation latch");
    return this.reactionDesires.cancel(input, { admitCleanup: true });
  }

  async withdrawSlackReactionDesire(input: Parameters<SlackCoreClient["withdrawSlackReactionDesire"]>[0]) {
    const session = await this.agentSessions.get({
      teamId: input.teamId,
      agentId: input.agentId,
      channelId: input.sessionChannelId,
      threadTs: input.sessionThreadTs,
    });
    if (!session?.bindings.some((binding) => binding.token === input.sessionToken)) {
      throw new Error("Slack reaction desire withdrawal requires an exact Agent Session binding");
    }
    return this.reactionDesires.cancel(input);
  }
  async enqueueSlackReactionCleanup(input: Parameters<SlackCoreClient["enqueueSlackReactionCleanup"]>[0]) {
    const authorized = await this.agentSessions.cancellationLatched({
      teamId: input.teamId,
      agentId: input.agentId,
      channelId: input.sessionChannelId,
      threadTs: input.sessionThreadTs,
      token: input.sessionToken,
    });
    if (!authorized)
      throw new Error("Slack reaction cleanup requires an exact accepted canceled Agent Session binding");
    await this.reactionDesires.cancel(input, { admitCleanup: true });
    const cleanup = await this.reactionCleanups.enqueue(input);
    await this.reactionDesires.completeCleanupAdmission(input);
    return cleanup;
  }
  async claimSlackReactionCleanups(input: Parameters<SlackCoreClient["claimSlackReactionCleanups"]>[0]) {
    await recoverSlackReactionCleanupAdmissions(this.reactionDesires, this.reactionCleanups, input, this.agentSessions);
    return this.reactionCleanups.claimDue(input);
  }
  async slackReactionCleanupAction(input: Parameters<SlackCoreClient["slackReactionCleanupAction"]>[0]) {
    if (!(await this.reactionCleanups.claimActive(input))) return "stale" as const;
    const current = await this.reactionDesires.get(input);
    if (!current?.desired) {
      return {
        action: "remove" as const,
        desireGeneration: current?.generation ?? 0,
        desireEffectId: current?.effectId ?? null,
      };
    }
    if (current.effectId === input.effectId) {
      throw new Error("Slack reaction cleanup conflicts with its current desired effect");
    }
    return { action: "preserve" as const, desireGeneration: current.generation, desireEffectId: current.effectId };
  }
  async completeSlackReactionCleanup(
    input: Parameters<SlackCoreClient["completeSlackReactionCleanup"]>[0],
    decision: Parameters<SlackCoreClient["completeSlackReactionCleanup"]>[1],
  ) {
    const current = await this.reactionDesires.get(input);
    const action = current?.desired ? "preserve" : "remove";
    if (
      action !== decision.action ||
      (current?.generation ?? 0) !== decision.desireGeneration ||
      (current?.effectId ?? null) !== decision.desireEffectId
    ) {
      return false;
    }
    return this.reactionCleanups.complete(input);
  }
  failSlackReactionCleanup(
    claim: Parameters<SlackCoreClient["failSlackReactionCleanup"]>[0],
    input: Parameters<SlackCoreClient["failSlackReactionCleanup"]>[1],
  ) {
    return this.reactionCleanups.fail(claim, input);
  }
  reopenSlackReactionCleanupAfterStaleEffect(
    claim: Parameters<SlackCoreClient["reopenSlackReactionCleanupAfterStaleEffect"]>[0],
    input: Parameters<SlackCoreClient["reopenSlackReactionCleanupAfterStaleEffect"]>[1],
  ) {
    return this.reactionCleanups.reopenAfterStaleEffect(claim, input);
  }
  getSlackReactionCleanup(input: Parameters<SlackCoreClient["getSlackReactionCleanup"]>[0]) {
    return this.reactionCleanups.get(input);
  }
  acknowledgeSlackAgentStop(input: Parameters<SlackCoreClient["acknowledgeSlackAgentStop"]>[0]) {
    return this.agentSessions.acknowledgeStop({
      ...input,
      ...(/^\d+(?:\.\d+)?$/.test(input.confirmationTs ?? "") ? {} : { confirmationTs: undefined }),
    });
  }
  bindSlackApprovalAuthority(input: Parameters<SlackCoreClient["bindSlackApprovalAuthority"]>[0]) {
    return this.approvalAuthorities.bind(input);
  }
  getSlackApprovalAuthority(input: Parameters<SlackCoreClient["getSlackApprovalAuthority"]>[0]) {
    if (this.approvalAuthorityReadError) throw this.approvalAuthorityReadError;
    return this.approvalAuthorities.get(input);
  }
  admitSlackApprovalContinuation(input: Parameters<SlackCoreClient["admitSlackApprovalContinuation"]>[0]) {
    return this.approvalAuthorities.admitContinuation(input);
  }
  markSlackApprovalContinuationSubmitted(
    input: Parameters<SlackCoreClient["markSlackApprovalContinuationSubmitted"]>[0],
  ) {
    if (this.failNextApprovalSubmitMark) {
      this.failNextApprovalSubmitMark = false;
      throw new Error("simulated crash before approval submission checkpoint");
    }
    return this.approvalAuthorities.markContinuationSubmitted(input).then((marked) => {
      if (this.crashAfterApprovalSubmitMark) {
        this.crashAfterApprovalSubmitMark = false;
        throw new Error("simulated crash after approval submission checkpoint");
      }
      return marked;
    });
  }
  renewSlackApprovalContinuation(input: Parameters<SlackCoreClient["renewSlackApprovalContinuation"]>[0]) {
    return this.approvalAuthorities.renewContinuation(input);
  }
  settleSlackApprovalContinuation(input: Parameters<SlackCoreClient["settleSlackApprovalContinuation"]>[0]) {
    this.approvalSettlementAttempts += 1;
    if (this.failNextApprovalSettle) {
      this.failNextApprovalSettle = false;
      throw new Error("simulated crash before approval settlement");
    }
    return this.approvalAuthorities.settleContinuation(input);
  }
  releaseSlackApprovalContinuation(input: Parameters<SlackCoreClient["releaseSlackApprovalContinuation"]>[0]) {
    return this.approvalAuthorities.releaseContinuation(input);
  }
  recoverableSlackApprovalContinuations(
    input: Parameters<SlackCoreClient["recoverableSlackApprovalContinuations"]>[0],
  ) {
    return this.approvalAuthorities.recoverableContinuations(input);
  }
  submittedSlackApprovalContinuations(input: Parameters<SlackCoreClient["submittedSlackApprovalContinuations"]>[0]) {
    return this.approvalAuthorities.submittedContinuations(input);
  }
  async slackApprovalRunRecovery(runId: string, input: Parameters<SlackCoreClient["slackApprovalRunRecovery"]>[1]) {
    const request = this.runRequests.get(runId);
    if (!request?.approval) return null;
    const deliveryTarget = request.deliveryTarget as string | undefined;
    const splitAt = deliveryTarget?.indexOf(":") ?? -1;
    const targetChannel = splitAt >= 0 ? deliveryTarget?.slice(0, splitAt) : deliveryTarget;
    const targetThreadTs = splitAt >= 0 ? deliveryTarget?.slice(splitAt + 1) : undefined;
    const sessionThreadTs = targetThreadTs ?? request.triggerTs;
    const recoveredSession =
      !request.slackAgentSession && targetChannel && sessionThreadTs
        ? await this.agentSessions.get({
            teamId: input.teamId,
            agentId: input.agentId,
            channelId: targetChannel,
            threadTs: sessionThreadTs,
          })
        : null;
    const native =
      request.slackAgentSession ??
      (recoveredSession
        ? {
            teamId: input.teamId,
            agentId: input.agentId,
            channelId: targetChannel!,
            threadTs: sessionThreadTs!,
          }
        : undefined);
    const details = request.gatewayContext?.details;
    const requestedByChannel = details?.requested_by_channel as string | undefined;
    const requestedByThreadTs = details?.requested_by_thread_ts as string | undefined;
    const requesterUserId = request.verifiedSlack?.userId ?? request.actor?.externalId;
    return {
      command: "the approved request",
      reason: "requires approval",
      ...(requesterUserId ? { approvalRequesterUserId: requesterUserId } : {}),
      ...(native
        ? {
            nativeAgentSession: {
              teamId: native.teamId,
              agentId: native.agentId,
              channelId: native.channelId,
              threadTs: native.threadTs,
            },
          }
        : {}),
      ...(requestedByChannel && targetChannel && requesterUserId
        ? {
            agentRequest: {
              requesterId: requesterUserId,
              targetUserId: requesterUserId,
              originChannel: requestedByChannel,
              originConversationKind: "channel" as const,
              ...(requestedByThreadTs ? { originThreadTs: requestedByThreadTs } : {}),
              originThreadOnly: !!requestedByThreadTs,
              dmChannel: targetChannel,
              task: request.text,
              originAgentLabel: "the channel agent",
              targetAgentLabel: "the personal agent",
              originResultIdempotencyKey: `run:${runId}:agent-request`,
            },
          }
        : {}),
      request,
    };
  }

  async externalSlackParticipants(): Promise<boolean> {
    return this.externalParticipants;
  }
  async stopSlackAgentSession(
    input: Parameters<SlackCoreClient["stopSlackAgentSession"]>[0],
  ): Promise<{ applicable: boolean; acknowledged: boolean; deferred?: boolean; runIds: string[] }> {
    this.stopInputs.push(input);
    const stopped = await this.agentSessions.recordStop(input);
    if (!stopped.event.applicable || stopped.event.state === "acknowledged")
      return { applicable: false, acknowledged: true, runIds: [] };
    if (this.deferNextAgentStop) {
      this.deferNextAgentStop = false;
      return { applicable: true, acknowledged: false, deferred: true, runIds: [] };
    }
    const runIds = this.activeRun
      ? [this.activeRun]
      : stopped.record.bindings
          .filter((binding) => stopped.event.bindingTokens.includes(binding.token))
          .flatMap((binding) => binding.runIds);
    for (const runId of runIds) await this.signalRunAbort(runId);
    return { applicable: true, acknowledged: false, runIds };
  }
  async ackEmojiOverride(): Promise<string[] | null> {
    return null;
  }
  async surfaceHeaderFacts(): Promise<{ agentLabel?: string; modelName: string }> {
    return { agentLabel: "Quartermaster", modelName: "Claude Opus 4.8" };
  }
  onScopeModelChanged(listener: (scope: any) => void): void {
    this.modelChangeListeners.push(listener);
  }
  async channelHeaderPinEnabled(scope: any): Promise<boolean> {
    return this.headerPinScopes.has(String(scope));
  }
  onChannelHeaderPinChanged(listener: (scope: any) => void): void {
    this.headerPinChangeListeners.push(listener);
  }
  async stageBlob(bytes: Uint8Array): Promise<{ blobId: string; sizeBytes: number }> {
    return { blobId: "blob-1", sizeBytes: bytes.byteLength };
  }
  async readBlob(): Promise<Buffer> {
    this.blobReads++;
    if (this.blobGate) await this.blobGate;
    return Buffer.from("artifact");
  }
  async readFileArtifact(): Promise<Buffer> {
    return Buffer.alloc(0);
  }
  async pickAckEmoji(text: string, candidates: readonly string[]): Promise<undefined> {
    this.ackPicks.push({ text, candidates });
    return undefined;
  }
  async recordAckPick(): Promise<void> {}
  async ingestSurfaceEvents(events: any[]): Promise<void> {
    this.ingests.push(events);
  }
  async submitTurn(body: any): Promise<TurnResult> {
    this.submitStarted += 1;
    if (this.submitGate) await this.submitGate;
    if (this.submitError) {
      if (!this.durableIntake) this.turns.push(body);
      throw this.submitError;
    }
    if (this.durableIntake && body.idempotencyKey) {
      const existing = this.acceptedIntake.get(body.idempotencyKey);
      if (existing) return { status: "queued", runId: existing, replayed: true };
      const runId = `R-intake-${this.acceptedIntake.size + 1}`;
      this.acceptedIntake.set(body.idempotencyKey, runId);
      this.runRequests.set(runId, body);
      this.turns.push(body);
      for (const approval of this.result.pendingApprovals ?? [])
        this.approvalRecords.set(approval.requestId, { ...approval, request: body });
      return { status: "queued", runId };
    }
    this.turns.push(body);
    if (this.queuedRunId) {
      // The first submit enqueues the run; a later one arrives while it is live, so core folds
      // it in as a steer and answers with the LIVE run's id (src/api/app-turn.ts).
      const steered = this.heldRunClaimed;
      this.heldRunClaimed = true;
      this.runRequests.set(this.queuedRunId, body);
      return { status: "queued", runId: this.queuedRunId, ...(steered ? { steered: true as const } : {}) };
    }
    for (const approval of this.result.pendingApprovals ?? [])
      this.approvalRecords.set(approval.requestId, { ...approval, request: body });
    return this.result;
  }
  async waitRun(runId: string, hooks: any = {}): Promise<TurnResult | null> {
    this.polled.push(runId);
    if (this.failNextWaitRun) {
      this.failNextWaitRun = false;
      throw new Error("simulated transient waitRun failure");
    }
    if (this.runGate) await this.runGate;
    for (const delta of this.deltasOnRelease) hooks.onDelta?.(delta);
    if (this.tasksOnRelease.length) await hooks.onTasks?.(this.tasksOnRelease);
    return this.result;
  }
  /** Enqueue `runId` on the first submit and hold waitRun open; every later submit is a
   *  mid-turn STEER answered with that same live run's id. `finishRun` releases the waiters. */
  holdRun(runId: string): void {
    this.queuedRunId = runId;
    this.heldRunClaimed = false;
    this.runGate = new Promise<void>((resolve) => (this.releaseRun = resolve));
  }
  finishRun(result: TurnResult): void {
    this.result = result;
    this.releaseRun?.();
  }
  holdSubmit(): void {
    this.submitGate = new Promise<void>((resolve) => (this.releaseSubmit = resolve));
  }
  resumeSubmit(): void {
    this.releaseSubmit?.();
    this.submitGate = undefined;
  }
  async activeRunForThread(): Promise<string | undefined> {
    return this.activeRun;
  }
  async signalRunAbort(runId: string): Promise<void> {
    this.abortedRuns.push(runId);
    if (this.abortGate) await this.abortGate;
    if (this.abortError) throw this.abortError;
  }
  holdAbort(): void {
    this.abortGate = new Promise<void>((resolve) => (this.releaseAbortGate = resolve));
  }
  releaseAbort(): void {
    this.releaseAbortGate?.();
  }
  holdBlob(): void {
    this.blobGate = new Promise<void>((resolve) => (this.releaseBlobGate = resolve));
  }
  releaseBlob(): void {
    this.releaseBlobGate?.();
  }
  async ackRunDelivery(runId: string): Promise<void> {
    this.ackedRunDeliveries.push(runId);
  }
  async reportTurnMetrics(): Promise<void> {}
  async reportRunEditRef(): Promise<void> {}
  async getApproval(requestId: string): Promise<any | null> {
    if (this.approvalFetchError) throw this.approvalFetchError;
    return this.approvalRecords.get(requestId) ?? null;
  }
  async pushDirectory(body: any): Promise<void> {
    this.directories.push(body);
  }
  async claimDeliveries(): Promise<[]> {
    return [];
  }
  async ackDelivery(): Promise<void> {}
  onDeliveryEnqueued(): () => void {
    return () => {};
  }
  async pendingContextRequests(): Promise<[]> {
    return [];
  }
  onContextRequest(): () => void {
    return () => {};
  }
  async fulfillContextRequest(): Promise<void> {}
}

const internalUser = (id: string, name: string) => ({
  id,
  team_id: "T1",
  name: name.toLowerCase(),
  real_name: name,
  profile: { display_name: name, real_name: name, email: `${name.toLowerCase()}@example.com` },
});

async function waitFor(cond: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function fixture(
  options: {
    externalParticipants?: boolean;
    webUiPublicUrl?: string;
    identityEmail?: "0" | "1";
    extraChannels?: number;
    membershipDelayMs?: number;
    core?: FakeCore;
    messagesByChannel?: ReadonlyMap<string, readonly any[]>;
    configureClient?: (client: FakeSlackClient) => void;
  } = {},
) {
  const core = options.core ?? new FakeCore();
  core.externalParticipants = options.externalParticipants ?? false;
  const started = startSlackPlugin(
    {
      botToken: "xoxb-test",
      appToken: "xapp-test",
      identityEmail: options.identityEmail ?? "0",
      ...(options.webUiPublicUrl ? { webUiPublicUrl: options.webUiPublicUrl } : {}),
    },
    core,
  );
  const app = FakeApp.instances.at(-1)!;
  options.configureClient?.(app.client);
  app.client.membershipDelayMs = options.membershipDelayMs ?? 0;
  app.client.usersById.set("U1", internalUser("U1", "Alice"));
  app.client.usersById.set("U2", internalUser("U2", "Bob"));
  app.client.usersById.set("UX", { id: "UX", team_id: "T2", name: "mallory", profile: { display_name: "Mallory" } });
  app.client.channelsById.set("C1", { id: "C1", name: "engineering", is_member: true, is_private: false });
  app.client.channelsById.set("CX", {
    id: "CX",
    name: "shared",
    is_member: true,
    is_private: false,
    is_ext_shared: true,
  });
  app.client.channelsById.set("CPX", {
    id: "CPX",
    name: "private-shared",
    is_member: true,
    is_private: true,
    is_ext_shared: true,
  });
  app.client.membersByChannel.set("C1", ["U1", "U2", "UBOT"]);
  app.client.membersByChannel.set("CX", ["U1", "UX", "UBOT"]);
  app.client.membersByChannel.set("CPX", ["U1", "UX", "UBOT"]);
  for (const [channel, messages] of options.messagesByChannel ?? []) {
    app.client.messagesByChannel.set(
      channel,
      messages.map((message) => ({ ...message })),
    );
  }
  for (let i = 0; i < (options.extraChannels ?? 0); i++) {
    const id = `CE${i}`;
    app.client.channelsById.set(id, { id, name: `extra-${i}`, is_member: true, is_private: false });
    app.client.membersByChannel.set(id, ["U1", "UBOT"]);
  }
  const plugin = await started;
  await new Promise((resolve) => setImmediate(resolve));
  return { app, client: app.client, core, stop: () => plugin.stop() };
}

test("config is all-or-nothing and numeric tuning fails closed", () => {
  assert.equal(slackPluginConfigFromEnv({ SLACK_BOT_TOKEN: "xoxb" }), null);
  assert.equal(slackPluginConfigFromEnv({ SLACK_APP_TOKEN: "xapp" }), null);
  const config = slackPluginConfigFromEnv({
    SLACK_BOT_TOKEN: "xoxb",
    SLACK_APP_TOKEN: "xapp",
    SLACK_USER_SNAPSHOT_TTL_MS: "-1",
    SLACK_CHANNEL_MEMBERS_TTL_MS: "NaN",
    SLACK_MAX_PRIVATE_CHANNELS: "10",
  });
  assert.deepEqual(config, { botToken: "xoxb", appToken: "xapp", maxPrivateChannels: 10 });
});

test("trusted Slack event identity dedupes message redelivery across plugin restart", async () => {
  const core = new FakeCore();
  core.durableIntake = true;
  const first = await fixture({ core });
  const message = {
    channel: "D1",
    channel_type: "im",
    user: "U1",
    text: "run this once",
    ts: "299.1",
  };
  await first.app.emitMessage(message, "Ev-trusted-redelivery");
  assert.equal(core.turns[0]?.idempotencyKey, "slack-event:T1:A1:Ev-trusted-redelivery");
  await first.stop();

  const restarted = await fixture({ core });
  try {
    await restarted.app.emitMessage(message, "Ev-trusted-redelivery");
    assert.equal(core.submitStarted, 2);
    assert.equal(core.turns.length, 1);
    assert.deepEqual(restarted.client.posts, []);
  } finally {
    await restarted.stop();
  }
});

test("trusted Slack event identity reaches app mention durable intake", async () => {
  const f = await fixture();
  try {
    await f.app.emitEvent(
      "app_mention",
      { channel: "C1", user: "U1", text: "<@UBOT> help", ts: "299.2" },
      "Ev-trusted-mention",
    );
    assert.equal(f.core.turns.at(-1)?.idempotencyKey, "slack-event:T1:A1:Ev-trusted-mention");
  } finally {
    await f.stop();
  }
});

test("a mid-turn message that STEERS the live run does not post the reply twice", async () => {
  const f = await fixture();
  try {
    // Core folds a message that lands mid-run into the LIVE run and answers the steering
    // request with that run's id, flagged `steered` (src/api/app-turn.ts). Only the handler
    // that started R1 owns its reply; the one that joined must not deliver it a second time.
    f.core.holdRun("R1");
    const first = f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "first ask", ts: "300.1" });
    await waitFor(() => f.core.polled.length === 1);
    const steer = f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U2",
      text: "and also this",
      ts: "300.2",
    });
    await waitFor(() => f.core.turns.length === 2);
    assert.deepEqual(f.core.polled, ["R1"], "only the handler that started the run waits on it");

    f.core.finishRun({ status: "ok", reply: "agent reply" });
    await Promise.all([first, steer]);

    assert.equal(
      f.client.posts.filter((p) => p.text === "agent reply").length,
      1,
      "the shared run's reply is posted once, by the handler that owns it",
    );
  } finally {
    await f.stop();
  }
});

test("a DM becomes one scoped live turn and one Slack reply", async () => {
  const f = await fixture();
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "hello agent", ts: "100.1" });
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].text, "hello agent");
    assert.equal(f.core.turns[0].trustedSlackTeamId, "T1");
    assert.equal(f.core.turns[0].trustedSlackUserId, "U1");
    assert.equal(f.core.turns[0].conversation.kind, "dm");
    assert.equal(f.core.turns[0].conversation.threadRef, "dm:D1");
    assert.equal(f.core.turns[0].conversation.audience[0].externalId, "U1");
    assert.equal(f.core.turns[0].deliveryTarget, "D1");
    assert.equal(f.core.turns[0].liveActor, true);
    assert.equal(f.core.turns[0].triggerTs, "100.1");
    assert.deepEqual(f.core.turns[0].verifiedSlack, {
      teamId: "T1",
      userId: "U1",
      channelId: "D1",
      messageTs: "100.1",
      threadTs: "100.1",
      threaded: false,
      liveHuman: true,
    });
    assert.equal(f.core.turns[0].gatewayContext.botHandle, "qmbot");
    assert.equal(f.core.ackPicks.length, 1);
    assert.equal(f.core.ackPicks[0]?.text, "hello agent");
    assert.ok((f.core.ackPicks[0]?.candidates.length ?? 0) > 0);
    assert.deepEqual(
      f.client.posts.map((p) => p.text),
      ["agent reply"],
    );
  } finally {
    await f.stop();
  }
});

test("a top-level DM uses the existing app's native agent session and stream when Slack supports it", async () => {
  const f = await fixture();
  const statusCalls: any[] = [];
  const starts: any[] = [];
  const stops: any[] = [];
  (f.client as any).apiCall = async (method: string, args: any) => void statusCalls.push({ method, args });
  (f.client.chat as any).startStream = async (args: any) => {
    starts.push(args);
    return { ts: "stream-1" };
  };
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async (args: any) => void stops.push(args);
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "hello agent", ts: "100.1" });
    assert.equal(statusCalls[0].method, "agents.sessions.setStatus");
    assert.equal(statusCalls[0].args.status, "processing");
    assert.equal(starts[0].channel, "D1");
    assert.equal(starts[0].thread_ts, "100.1");
    assert.equal(stops[0].session_status, "active");
    assert.equal(f.core.turns[0].conversation.threadRef, "dm:D1:100.1");
    assert.equal(f.core.turns[0].deliveryTarget, "D1:100.1");
    assert.equal(f.client.posts.length, 0);
    assert.equal(f.core.ackPicks.length, 0);
  } finally {
    await f.stop();
  }
});

test("a native stop racing a react-only result compensates the reaction", async () => {
  const f = await fixture();
  let releaseReaction!: () => void;
  let reactionStarted!: () => void;
  const reactionGate = new Promise<void>((resolve) => (releaseReaction = resolve));
  const reactionStartedGate = new Promise<void>((resolve) => (reactionStarted = resolve));
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async () => ({ ts: "react-stream" });
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  (f.client.reactions as any).add = async (body: any) => {
    f.client.reactionsAdded.push(body);
    reactionStarted();
    await reactionGate;
    return { ok: true };
  };
  f.core.result = { status: "react", reactions: ["eyes"] };
  try {
    const turn = f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "take a look",
      ts: "230.1",
    });
    await reactionStartedGate;
    const stop = f.app.emitEvent(
      "agent_session_stopped",
      { channel: "D1", thread_ts: "230.1", user: "U2", event_ts: "230.2" },
      "Ev-react-race",
    );
    await waitFor(() => f.core.stopInputs.some((input) => input.eventId === "Ev-react-race"));
    releaseReaction();
    await Promise.all([turn, stop]);

    assert.deepEqual(f.client.reactionsAdded, [{ channel: "D1", timestamp: "230.1", name: "eyes" }]);
    assert.deepEqual(f.client.reactionsRemoved, [{ channel: "D1", timestamp: "230.1", name: "eyes" }]);
    assert.equal(f.client.posts.filter((post) => post.text === "Stopped.").length, 1);
  } finally {
    releaseReaction();
    await f.stop();
  }
});

test("Agent View message context reaches only its owning DM turn as bounded gateway identifiers", async () => {
  const f = await fixture();
  try {
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "summarize what I am viewing",
      ts: "121.1",
      app_context: {
        entities: [
          {
            type: "slack#/types/message_context",
            team_id: "T1",
            value: { channel_id: "C2", message_ts: "120.9" },
          },
          { type: "slack#/types/channel_id", team_id: "T-OTHER", value: "C-SECRET" },
        ],
      },
    });

    assert.equal(f.core.turns.at(-1)?.gatewayContext?.details?.active_slack_view, "message_context:C2:120.9");
    assert.equal(JSON.stringify(f.core.turns.at(-1)).includes("C-SECRET"), false);
  } finally {
    await f.stop();
  }
});

test("native approval resumes processing and streams the result into the same agent session", async () => {
  const f = await fixture();
  const statusCalls: any[] = [];
  const starts: any[] = [];
  const stops: any[] = [];
  (f.client as any).apiCall = async (method: string, args: any) => void statusCalls.push({ method, args });
  (f.client.chat as any).startStream = async (args: any) => {
    starts.push(args);
    return { ts: "approval-stream" };
  };
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async (args: any) => void stops.push(args);
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-1", command: "send-email", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "send it",
      ts: "1788030001.000000",
    });
    assert.deepEqual(
      statusCalls.map((call) => call.args.status),
      ["processing", "suspended"],
    );

    f.core.result = { status: "ok", reply: "The approved email was sent." };
    await f.app.emitAction("hilo_allow_once", "approval-1", {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "1788030001.000000" },
      action_ts: "1788030003.000000",
    });

    assert.deepEqual(
      statusCalls.map((call) => call.args.status),
      ["processing", "suspended", "processing", "active"],
    );
    assert.equal(starts.length, 1);
    assert.equal(starts[0].channel, "D1");
    assert.equal(starts[0].thread_ts, "1788030001.000000");
    assert.match(JSON.stringify(starts[0].chunks), /approved email was sent/);
    assert.equal(stops.at(-1)?.session_status, "active");
    assert.match(f.client.updates.at(-1)?.text ?? "", /Approved; ran/);
    assert.ok(f.core.turns[0]!.verifiedSlack);
    assert.deepEqual(f.core.turns[1]!.verifiedSlack, {
      teamId: "T1",
      userId: "U1",
      channelId: "D1",
      messageTs: "1700000000.000001",
      threadTs: "1788030001.000000",
      threaded: true,
      liveHuman: true,
      actionTs: "1788030003.000000",
    });
  } finally {
    await f.stop();
  }
});

test("a submitted native delivery failure keeps its exact binding stoppable for recovery", async () => {
  const f = await fixture();
  f.core.durableIntake = true;
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async () => ({ ts: "1788030005.000001" });
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-native-retry-stop", command: "send-email", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "send it",
      ts: "1788030004.000000",
    });
    f.core.result = { status: "ok", reply: "The approved email was sent." };
    f.client.failNextApprovalFinalUpdate = true;
    await f.app.emitAction("hilo_allow_once", "approval-native-retry-stop", {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "1788030004.000000" },
      action_ts: "1788030005.000000",
    });
    const submitted = await f.core.approvalAuthorities.get({
      teamId: "T1",
      agentId: "A1",
      requesterUserId: "U1",
      requestId: "approval-native-retry-stop",
    });
    const runId = submitted!.continuation!.runId!;
    const session = await f.core.agentSessions.get({
      teamId: "T1",
      agentId: "A1",
      channelId: "D1",
      threadTs: "1788030004.000000",
    });
    const binding = session?.bindings.find((candidate) => candidate.runIds.includes(runId));
    assert.ok(binding);
    assert.equal(binding.finishedAt, undefined);

    await f.app.emitEvent(
      "agent_session_stopped",
      {
        channel: "D1",
        thread_ts: "1788030004.000000",
        user: "U1",
        message_ts: "1788030005.000001",
        event_ts: "1788030006.000000",
      },
      "Ev-native-retry-stop",
    );
    assert.ok(f.core.abortedRuns.includes(runId));
  } finally {
    await f.stop();
  }
});

test("an approval click from a copied or stale message fails exact message authority", async () => {
  const f = await fixture();
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-stale", command: "send-email", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "send it",
      ts: "1788030010.000000",
    });
    await f.app.emitAction("hilo_allow_once", "approval-stale", {
      user: { id: "U1" },
      channel: { id: "D1" },
      message: { ts: "1788030099.000000", thread_ts: "1788030010.000000" },
      action_ts: "1788030100.000000",
    });
    assert.equal(f.core.turns.length, 1);
    assert.match(f.client.ephemerals.at(-1)?.text ?? "", /not attached to the active approval message/i);
  } finally {
    await f.stop();
  }
});

test("approval click authority survives plugin restart and still rejects a copied card", async () => {
  const first = await fixture();
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-restart", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({
    channel: "D1",
    channel_type: "im",
    user: "U1",
    text: "send it",
    ts: "1788030020.000000",
  });
  await first.stop();

  const restarted = await fixture({ core: first.core });
  restarted.core.result = { status: "ok", reply: "Sent." };
  try {
    await restarted.app.emitAction("hilo_allow_once", "approval-restart", {
      user: { id: "U1" },
      channel: { id: "D1" },
      message: { ts: "1788030099.000000", thread_ts: "1788030020.000000" },
      action_ts: "1788030100.000000",
    });
    assert.equal(restarted.core.turns.length, 1);
    assert.match(restarted.client.ephemerals.at(-1)?.text ?? "", /not attached to the active approval message/i);

    await restarted.app.emitAction("hilo_allow_once", "approval-restart", {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "1788030020.000000" },
      action_ts: "1788030101.000000",
    });
    assert.equal(restarted.core.turns.length, 2);
  } finally {
    await restarted.stop();
  }
});

test("transient approval recovery and authority outages stay unacknowledged until restart retry succeeds", async () => {
  const first = await fixture();
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-outage", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "104.1" });
  await first.stop();

  first.core.result = { status: "ok", reply: "Sent after recovery." };
  first.core.approvalFetchError = new Error("core unavailable");
  const restarted = await fixture({ core: first.core });
  const body = {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "104.1" },
    action_ts: "104.2",
  };
  try {
    await assert.rejects(
      restarted.app.emitAction("hilo_allow_once", "approval-outage", body),
      /recovery is temporarily unavailable/,
    );
    assert.equal(restarted.app.actionAcks.length, 0);

    first.core.approvalFetchError = undefined;
    first.core.approvalAuthorityReadError = new Error("authority unavailable");
    await assert.rejects(
      restarted.app.emitAction("hilo_allow_once", "approval-outage", body),
      /authority is temporarily unavailable/,
    );
    assert.equal(restarted.app.actionAcks.length, 0);

    first.core.approvalAuthorityReadError = undefined;
    await restarted.app.emitAction("hilo_allow_once", "approval-outage", body);
    assert.equal(restarted.app.actionAcks.length, 1);
    assert.match(restarted.client.updates.at(-1)?.text ?? "", /Sent after recovery/);
  } finally {
    await restarted.stop();
  }
});

test("a transient approval continuation failure keeps a command-scoped card once-only", async () => {
  const f = await fixture();
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [
      {
        requestId: "approval-once-only",
        command: "fixed-tool create --request work/fixed-tool/event.json --request-sha256 " + "a".repeat(64),
        reason: "exact Google write",
        grantModes: { session: false, always: false },
      },
    ],
  };
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "schedule it", ts: "105.1" });
    f.core.submitError = new Error("temporary core failure");
    await f.app.emitAction("hilo_allow_once", "approval-once-only", {
      user: { id: "U1" },
      channel: { id: "D1" },
      message: { ts: "1700000000.000001", thread_ts: "105.1" },
    });
    const update = f.client.updates.at(-1);
    const actionIds = (update?.blocks ?? [])
      .filter((block: any) => block.type === "actions")
      .flatMap((block: any) => block.elements.map((element: any) => element.action_id));
    assert.deepEqual(actionIds, ["hilo_allow_once", "hilo_deny"]);
  } finally {
    await f.stop();
  }
});

test("durable approval admission coalesces competing plugin deliveries before core submit", async () => {
  const f = await fixture();
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-blue-green", command: "send-email", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.2" });
    f.core.result = { status: "ok", reply: "Sent once." };
    f.core.holdSubmit();
    const body = {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "105.2" },
      action_ts: "105.3",
    };
    const first = f.app.emitAction("hilo_allow_once", "approval-blue-green", body);
    await waitFor(() => f.core.submitStarted === 2);
    await f.app.emitAction("hilo_allow_once", "approval-blue-green", body);
    assert.equal(f.core.submitStarted, 2);
    assert.equal(f.app.actionAcks.length, 0);
    assert.match(f.client.ephemerals.at(-1)?.text ?? "", /still working/i);
    f.core.resumeSubmit();
    await first;
    assert.equal(f.app.actionAcks.length, 1);
    assert.equal(f.core.turns.length, 2);
    assert.match(f.core.turns[1]?.idempotencyKey ?? "", /^slack-approval:[a-f0-9]{64}$/);
  } finally {
    await f.stop();
  }
});

test("a failed approval admission resumes after restart with the same durable idempotency key", async () => {
  const first = await fixture();
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-resume", command: "calendar-write", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "book it", ts: "105.4" });
  first.core.submitError = new Error("temporary core failure");
  await first.app.emitAction("hilo_allow_once", "approval-resume", {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "105.4" },
    action_ts: "105.5",
  });
  assert.equal(first.app.actionAcks.length, 0);
  assert.equal(
    first.client.updates.some((update) => /; running /.test(update.text ?? "")),
    false,
  );
  const admittedKey = (
    await first.core.approvalAuthorities.get({
      teamId: "T1",
      agentId: "A1",
      requesterUserId: "U1",
      requestId: "approval-resume",
    })
  )?.continuation?.idempotencyKey;
  await first.stop();

  first.core.submitError = undefined;
  first.core.result = { status: "ok", reply: "Booked." };
  const restarted = await fixture({ core: first.core });
  try {
    await restarted.app.emitAction("hilo_allow_once", "approval-resume", {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "105.4" },
      action_ts: "105.6",
    });
    assert.equal(restarted.app.actionAcks.length, 1);
    assert.equal(first.core.turns.at(-1)?.idempotencyKey, admittedKey);
    assert.match(restarted.client.updates.at(-1)?.text ?? "", /Booked/);
  } finally {
    await restarted.stop();
  }
});

test("approval redelivery resumes an already accepted core run after its submission checkpoint crashes", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-accepted-resume", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.7" });
  first.core.result = { status: "ok", reply: "Sent exactly once." };
  first.core.failNextApprovalSubmitMark = true;
  const body = {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "105.7" },
    action_ts: "105.8",
  };
  await first.app.emitAction("hilo_allow_once", "approval-accepted-resume", body);
  assert.equal(first.app.actionAcks.length, 0);
  const acceptedTurns = first.core.turns.length;
  await first.stop();

  const restarted = await fixture({ core: first.core });
  try {
    await restarted.app.emitAction("hilo_allow_once", "approval-accepted-resume", {
      ...body,
      action_ts: "105.9",
    });
    assert.equal(first.core.turns.length, acceptedTurns);
    assert.equal(restarted.app.actionAcks.length, 1);
    assert.match(restarted.client.updates.at(-1)?.text ?? "", /Sent exactly once/);
  } finally {
    await restarted.stop();
  }
});

test("startup replays exact intake after the core accepted a continuation before its run marker", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-before-marker", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.81" });
  first.core.result = { status: "ok", reply: "Recovered before marker." };
  first.core.failNextApprovalSubmitMark = true;
  await first.app.emitAction("hilo_allow_once", "approval-before-marker", {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "105.81" },
    action_ts: "105.82",
  });
  const acceptedTurns = first.core.turns.length;
  first.core.approvalRecords.delete("approval-before-marker");
  await first.stop();

  const restarted = await fixture({ core: first.core });
  try {
    await waitFor(() => restarted.client.updates.some((update) => /Recovered before marker/.test(update.text ?? "")));
    assert.equal(first.core.turns.length, acceptedTurns);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-before-marker",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("startup migrates a baseline submitted row and rebuilds context from its exact run", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-legacy-submitted", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.83" });
  first.core.result = { status: "ok", reply: "Recovered legacy run." };
  first.core.crashAfterApprovalSubmitMark = true;
  await first.app.emitAction("hilo_allow_once", "approval-legacy-submitted", {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "105.83" },
    action_ts: "105.84",
  });
  for (const [id, record] of await first.core.approvalAuthorityBacking.entries()) {
    if (record.requestId !== "approval-legacy-submitted") continue;
    const { recovery: _recovery, ...legacy } = record;
    await first.core.approvalAuthorityBacking.put(id, legacy);
  }
  for (const [id, record] of await first.core.approvalContinuationBacking.entries()) {
    if (record.kind === "slack_approval_continuation") await first.core.approvalContinuationBacking.delete(id);
  }
  first.core.approvalRecords.delete("approval-legacy-submitted");
  first.core.approvalNow += 60_001;
  await first.stop();

  const restarted = await fixture({ core: first.core });
  try {
    await waitFor(() => restarted.client.updates.some((update) => /Recovered legacy run/.test(update.text ?? "")));
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-legacy-submitted",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("baseline native DM denial recovery reactivates the exact durable session", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  (first.client as any).apiCall = async () => ({ ok: true });
  (first.client.chat as any).startStream = async () => ({ ts: "legacy-deny-stream" });
  (first.client.chat as any).appendStream = async () => ({ ok: true });
  (first.client.chat as any).stopStream = async () => ({ ok: true });
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-legacy-native-deny", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({
    channel: "D1",
    channel_type: "im",
    user: "U1",
    text: "send it",
    ts: "1788030101.000000",
  });
  first.core.result = { status: "refused", reason: "approval denied" };
  first.core.crashAfterApprovalSubmitMark = true;
  await first.app.emitAction("hilo_deny", "approval-legacy-native-deny", {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "1788030101.000000" },
    action_ts: "1788030102.000000",
  });
  const submitted = await first.core.approvalAuthorities.get({
    teamId: "T1",
    agentId: "A1",
    requesterUserId: "U1",
    requestId: "approval-legacy-native-deny",
  });
  const runRequest = first.core.runRequests.get(submitted!.continuation!.runId!);
  assert.ok(runRequest);
  assert.equal(runRequest.slackAgentSession, undefined);
  runRequest.deliveryTarget = "D1";
  for (const [id, record] of await first.core.approvalAuthorityBacking.entries()) {
    if (record.requestId !== "approval-legacy-native-deny") continue;
    const { recovery: _recovery, ...legacy } = record;
    await first.core.approvalAuthorityBacking.put(id, legacy);
  }
  for (const [id, record] of await first.core.approvalContinuationBacking.entries()) {
    if (record.kind === "slack_approval_continuation") await first.core.approvalContinuationBacking.delete(id);
  }
  first.core.approvalRecords.delete("approval-legacy-native-deny");
  first.core.approvalNow += 60_001;
  await first.stop();

  const restartedStatuses: any[] = [];
  const restarted = await fixture({
    core: first.core,
    configureClient(client) {
      (client as any).apiCall = async (method: string, args: any) => {
        restartedStatuses.push({ method, args });
        return { ok: true };
      };
      (client.chat as any).startStream = async () => ({ ts: "unexpected-recovery-stream" });
      (client.chat as any).appendStream = async () => ({ ok: true });
      (client.chat as any).stopStream = async () => ({ ok: true });
    },
  });
  try {
    await waitFor(() => restartedStatuses.some((call) => call.args.status === "active"));
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-legacy-native-deny",
        })
      )?.continuation?.state,
      "settled",
    );
    assert.ok(restarted.client.updates.some((update) => String(update.text ?? "").startsWith("Denied ")));
  } finally {
    await restarted.stop();
  }
});

test("baseline personal-agent denial recovery posts the durable outcome to its origin", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = { status: "ok", reply: "[[ask-agent: <@U2> | Run the private check]]" };
  await first.app.emitEvent("app_mention", {
    channel: "C1",
    channel_type: "channel",
    user: "U1",
    text: "<@UBOT> ask Bob",
    ts: "1788030201.000000",
  });
  const handoffMessage = (first.client.messagesByChannel.get("DOPEN") ?? []).find((message) =>
    JSON.stringify(message.blocks ?? []).includes("agent_request_run"),
  );
  assert.ok(handoffMessage);
  const handoffAction = handoffMessage.blocks
    .flatMap((block: any) => block.elements ?? [])
    .find((element: any) => element.action_id === "agent_request_run");
  assert.ok(handoffAction?.value);

  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-legacy-agent-deny", command: "private-check", reason: "external write" }],
  };
  await first.app.emitAction("agent_request_run", handoffAction.value, {
    user: { id: "U2" },
    channel: { id: "DOPEN" },
    team: { id: "T1" },
    message: { ts: handoffMessage.ts },
    action_ts: "1788030202.000000",
  });
  const approvalMessage = (first.client.messagesByChannel.get("DOPEN") ?? []).find((message) =>
    JSON.stringify(message.blocks ?? []).includes("approval-legacy-agent-deny"),
  );
  assert.ok(approvalMessage);

  first.core.result = { status: "refused", reason: "approval denied" };
  first.core.crashAfterApprovalSubmitMark = true;
  await first.app.emitAction("hilo_deny", "approval-legacy-agent-deny", {
    user: { id: "U2" },
    channel: { id: "DOPEN" },
    team: { id: "T1" },
    message: { ts: approvalMessage.ts },
    action_ts: "1788030203.000000",
  });
  const submitted = await first.core.approvalAuthorities.get({
    teamId: "T1",
    agentId: "A1",
    requesterUserId: "U2",
    requestId: "approval-legacy-agent-deny",
  });
  const runRequest = first.core.runRequests.get(submitted!.continuation!.runId!);
  assert.equal(runRequest.gatewayContext.details.requested_by_channel, "C1");
  for (const [id, record] of await first.core.approvalAuthorityBacking.entries()) {
    if (record.requestId !== "approval-legacy-agent-deny") continue;
    const { recovery: _recovery, ...legacy } = record;
    await first.core.approvalAuthorityBacking.put(id, legacy);
  }
  for (const [id, record] of await first.core.approvalContinuationBacking.entries()) {
    if (record.kind === "slack_approval_continuation") await first.core.approvalContinuationBacking.delete(id);
  }
  first.core.approvalRecords.delete("approval-legacy-agent-deny");
  first.core.approvalNow += 60_001;
  const messagesByChannel = new Map(
    [...first.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
  );
  await first.stop();

  const firstRecovery = await fixture({
    core: first.core,
    messagesByChannel,
    configureClient(client) {
      client.failNextUpdateText = "Denied `the approved request`.";
    },
  });
  await waitFor(() =>
    firstRecovery.client.posts.some(
      (post) => post.channel === "C1" && /personal-agent handoff could not be completed/.test(post.text ?? ""),
    ),
  );
  await waitFor(() =>
    firstRecovery.client.updates.some((update) => /durable decision is still being finalized/.test(update.text ?? "")),
  );
  assert.equal(
    (
      await first.core.approvalAuthorities.get({
        teamId: "T1",
        agentId: "A1",
        requesterUserId: "U2",
        requestId: "approval-legacy-agent-deny",
      })
    )?.continuation?.state,
    "submitted",
  );
  first.core.approvalNow += 60_001;
  const recoveredMessages = new Map(
    [...firstRecovery.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
  );
  await firstRecovery.stop();

  const restarted = await fixture({ core: first.core, messagesByChannel: recoveredMessages });
  try {
    await waitFor(() => restarted.client.updates.some((update) => update.text === "Denied `the approved request`."));
    assert.equal(
      firstRecovery.client.posts.filter(
        (post) => post.channel === "C1" && /personal-agent handoff could not be completed/.test(post.text ?? ""),
      ).length,
      1,
    );
    assert.equal(
      restarted.client.posts.filter(
        (post) => post.channel === "C1" && /personal-agent handoff could not be completed/.test(post.text ?? ""),
      ).length,
      0,
    );
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U2",
          requestId: "approval-legacy-agent-deny",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("startup recovers the exact submitted approval run after a crash before action acknowledgment", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-crash-before-ack", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.91" });
  first.core.result = { status: "ok", reply: "Sent after restart." };
  first.core.crashAfterApprovalSubmitMark = true;
  const body = {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "105.91" },
    action_ts: "105.92",
  };
  await first.app.emitAction("hilo_allow_once", "approval-crash-before-ack", body);
  assert.equal(first.app.actionAcks.length, 0);
  const submitted = await first.core.approvalAuthorities.get({
    teamId: "T1",
    agentId: "A1",
    requesterUserId: "U1",
    requestId: "approval-crash-before-ack",
  });
  assert.equal(submitted?.continuation?.state, "submitted");
  assert.ok(submitted?.continuation?.runId);
  first.core.approvalRecords.delete("approval-crash-before-ack");
  const acceptedTurns = first.core.turns.length;
  first.core.approvalNow += 60_001;
  await first.stop();

  const restarted = await fixture({ core: first.core });
  try {
    await waitFor(() => restarted.client.updates.some((update) => /Sent after restart/.test(update.text ?? "")));
    assert.equal(first.core.turns.length, acceptedTurns);
    assert.ok(first.core.polled.includes(submitted!.continuation!.runId!));
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-crash-before-ack",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("action redelivery takes over an expired submitted claim and polls its original run", async () => {
  const f = await fixture();
  f.core.durableIntake = true;
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-submitted-redelivery", command: "send-email", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.921" });
    f.core.result = { status: "ok", reply: "Sent on redelivery." };
    f.core.crashAfterApprovalSubmitMark = true;
    const body = {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "105.921" },
      action_ts: "105.922",
    };
    await f.app.emitAction("hilo_allow_once", "approval-submitted-redelivery", body);
    const submitted = await f.core.approvalAuthorities.get({
      teamId: "T1",
      agentId: "A1",
      requesterUserId: "U1",
      requestId: "approval-submitted-redelivery",
    });
    const acceptedTurns = f.core.turns.length;
    f.core.approvalNow += 60_001;
    await f.app.emitAction("hilo_allow_once", "approval-submitted-redelivery", {
      ...body,
      action_ts: "105.923",
    });
    assert.equal(f.core.turns.length, acceptedTurns);
    assert.ok(f.core.polled.includes(submitted!.continuation!.runId!));
    assert.match(f.client.updates.at(-1)?.text ?? "", /Sent on redelivery/);
  } finally {
    await f.stop();
  }
});

test("startup delivers a refused submitted result after the original handler acknowledged and crashed", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-refused-after-ack", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.93" });
  first.core.result = { status: "refused", reason: "policy refused" };
  first.app.failNextActionAckAfterAck = true;
  await first.app.emitAction("hilo_allow_once", "approval-refused-after-ack", {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "105.93" },
    action_ts: "105.94",
  });
  assert.equal(first.app.actionAcks.length, 1);
  first.core.approvalRecords.delete("approval-refused-after-ack");
  first.core.approvalNow += 60_001;
  await first.stop();

  const restarted = await fixture({ core: first.core });
  try {
    await waitFor(() => restarted.client.updates.some((update) => /policy refused/.test(update.text ?? "")));
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-refused-after-ack",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("recovered quarantine refusal ACKs its exact run only after the terminal card is visible", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-quarantine", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.945" });
  first.core.result = { status: "refused", reason: "quarantined", refusalKind: "security_quarantine" };
  first.core.crashAfterApprovalSubmitMark = true;
  await first.app.emitAction("hilo_allow_once", "approval-quarantine", {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "105.945" },
    action_ts: "105.946",
  });
  const submitted = await first.core.approvalAuthorities.get({
    teamId: "T1",
    agentId: "A1",
    requesterUserId: "U1",
    requestId: "approval-quarantine",
  });
  first.core.approvalRecords.delete("approval-quarantine");
  first.core.approvalNow += 60_001;
  await first.stop();

  const restarted = await fixture({ core: first.core });
  try {
    await waitFor(() => restarted.client.updates.some((update) => update.text === SECURITY_QUARANTINE_REFUSAL_TEXT));
    assert.equal(
      restarted.client.updates.find((update) => update.text === SECURITY_QUARANTINE_REFUSAL_TEXT)?.text,
      SECURITY_QUARANTINE_REFUSAL_TEXT,
    );
    assert.ok(first.core.ackedRunDeliveries.includes(submitted!.continuation!.runId!));
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-quarantine",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("startup finalizes an acknowledged submitted denial without resubmitting its exact run", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-deny-after-ack", command: "send-email", reason: "external write" }],
  };
  await first.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "105.95" });
  first.core.result = { status: "refused", reason: "approval denied" };
  first.app.failNextActionAckAfterAck = true;
  await first.app.emitAction("hilo_deny", "approval-deny-after-ack", {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "105.95" },
    action_ts: "105.96",
  });
  first.core.approvalRecords.delete("approval-deny-after-ack");
  const acceptedTurns = first.core.turns.length;
  first.core.approvalNow += 60_001;
  await first.stop();

  const restarted = await fixture({ core: first.core });
  try {
    await waitFor(() => restarted.client.updates.some((update) => String(update.text ?? "").startsWith("Denied ")));
    assert.equal(first.core.turns.length, acceptedTurns);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-deny-after-ack",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("stopping a native approval continuation aborts its exact run and suppresses the late result", async () => {
  const f = await fixture();
  const statuses: string[] = [];
  const starts: any[] = [];
  const stops: any[] = [];
  (f.client as any).apiCall = async (_method: string, args: any) => void statuses.push(args.status);
  (f.client.chat as any).startStream = async (args: any) => {
    starts.push(args);
    return { ts: "late-approval-stream" };
  };
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async (args: any) => void stops.push(args);
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-stop", command: "send-email", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "110.1" });
    f.core.holdRun("R-approval-stop");
    const approval = f.app.emitAction("hilo_allow_once", "approval-stop", {
      user: { id: "U1" },
      channel: { id: "D1" },
      message: { ts: "1700000000.000001", thread_ts: "110.1" },
    });
    await waitFor(() => f.core.polled.includes("R-approval-stop"));
    f.core.holdAbort();
    const stop = f.app.emitEvent("agent_session_stopped", {
      channel: "D1",
      thread_ts: "110.1",
      user: "U1",
      message_ts: "approval-stream-in-progress",
      event_ts: "110.2",
    });
    await waitFor(() => f.core.abortedRuns.includes("R-approval-stop"));
    f.core.deltasOnRelease.push("This post-stop delta must stay hidden. ".repeat(20));
    f.core.tasksOnRelease.push({ id: "late-task", title: "Late task", status: "completed" });
    f.core.finishRun({ status: "ok", reply: "This late result must never appear." });
    await approval;
    f.core.releaseAbort();
    await stop;

    assert.deepEqual(f.core.abortedRuns, ["R-approval-stop"]);
    assert.equal(f.client.posts.filter((post) => post.text === "Stopped.").length, 1);
    assert.deepEqual(stops, []);
    assert.equal(starts.length, 0, "the late result never starts a replacement stream");
    assert.doesNotMatch(JSON.stringify([...f.client.posts, ...f.client.updates]), /late result/i);
    assert.equal(statuses.at(-1), "active");
  } finally {
    await f.stop();
  }
});

test("an abort transport failure still suppresses the exact stopped run's late result", async () => {
  const f = await fixture();
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async () => ({ ts: "failed-abort-stream" });
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  f.core.holdRun("R-abort-failure");
  f.core.abortError = new Error("abort transport unavailable");
  try {
    const turn = f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "work", ts: "115.1" });
    await waitFor(() => f.core.polled.includes("R-abort-failure"));
    await assert.rejects(
      f.app.emitEvent("agent_session_stopped", {
        channel: "D1",
        thread_ts: "115.1",
        user: "U1",
        message_ts: "failed-abort-stream",
        event_ts: "115.2",
      }),
      /abort transport unavailable/,
    );
    f.core.finishRun({ status: "ok", reply: "Late even though abort transport failed." });
    await turn;

    assert.deepEqual(f.core.abortedRuns, ["R-abort-failure"]);
    assert.equal(f.client.posts.length, 0);
    assert.doesNotMatch(JSON.stringify([...f.client.posts, ...f.client.updates]), /Late even though/);
  } finally {
    await f.stop();
  }
});

test("Stop after core completion cancels a deferred attachment before any final Slack delivery", async () => {
  const f = await fixture();
  const starts: any[] = [];
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async (args: any) => {
    starts.push(args);
    return { ts: "late-main-stream" };
  };
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  f.core.result = {
    status: "ok",
    reply: "This final answer must stay hidden.",
    attachments: [{ name: "late.txt", mimetype: "text/plain", sizeBytes: 8, blobId: "blob-late" }],
  };
  f.core.holdBlob();
  try {
    const turn = f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "work", ts: "115.5" });
    await waitFor(() => f.core.blobReads === 1);
    await f.app.emitEvent("agent_session_stopped", {
      channel: "D1",
      thread_ts: "115.5",
      user: "U1",
      message_ts: "main-stream-in-progress",
      event_ts: "115.6",
    });
    f.core.releaseBlob();
    await turn;

    assert.equal(f.client.fileUploads.length, 0);
    assert.equal(starts.length, 0);
    assert.deepEqual(
      f.client.posts.map((post) => post.text),
      ["Stopped."],
    );
    assert.doesNotMatch(JSON.stringify([...f.client.posts, ...f.client.updates]), /final answer/i);
  } finally {
    await f.stop();
  }
});

test("a blocked approval-card post is deleted when session stop wins the publication race", async () => {
  const f = await fixture();
  let releaseCard: (() => void) | undefined;
  let cardBlocked = false;
  const originalPost = f.client.chat.postMessage;
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async () => ({ ts: "unused-approval-stream" });
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  (f.client.chat as any).postMessage = async (args: any) => {
    if (!cardBlocked && JSON.stringify(args.blocks ?? []).includes("hilo_allow_once")) {
      cardBlocked = true;
      await new Promise<void>((resolve) => (releaseCard = resolve));
    }
    return originalPost(args);
  };
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-publish-race", command: "send-email", reason: "external write" }],
  };
  try {
    const turn = f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "send it",
      ts: "225.1",
    });
    await waitFor(() => !!releaseCard);
    await f.app.emitEvent(
      "agent_session_stopped",
      { channel: "D1", thread_ts: "225.1", user: "U2", event_ts: "225.2" },
      "Ev-approval-publish-race",
    );
    releaseCard!();
    await turn;

    const card = f.client.posts.find((post) => JSON.stringify(post.blocks ?? []).includes("hilo_allow_once"));
    assert.ok(card);
    assert.ok(f.client.deletes.some((entry) => entry.channel === "D1" && entry.ts !== undefined));
    assert.equal(f.client.posts.filter((post) => post.text === "Stopped.").length, 1);
  } finally {
    await f.stop();
  }
});

test("a blocked agent-request DM and its origin status are compensated after stop", async () => {
  const f = await fixture();
  let releaseDm: (() => void) | undefined;
  let dmBlocked = false;
  const originalPost = f.client.chat.postMessage;
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async () => ({ ts: "unused-agent-request-stream" });
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  (f.client.chat as any).postMessage = async (args: any) => {
    if (!dmBlocked && JSON.stringify(args.blocks ?? []).includes("agent_request_run")) {
      dmBlocked = true;
      await new Promise<void>((resolve) => (releaseDm = resolve));
    }
    return originalPost(args);
  };
  f.core.result = { status: "ok", reply: "[[ask-agent: U2 | Research this privately]]" };
  try {
    const turn = f.app.emitEvent("app_mention", {
      channel: "C1",
      channel_type: "channel",
      user: "U1",
      text: "<@UBOT> ask Bob",
      ts: "230.1",
    });
    await waitFor(() => !!releaseDm);
    await f.app.emitEvent(
      "agent_session_stopped",
      { channel: "C1", thread_ts: "230.1", user: "U2", event_ts: "230.2" },
      "Ev-agent-request-publish-race",
    );
    releaseDm!();
    await turn;

    assert.ok(f.client.deletes.some((entry) => entry.channel === "DOPEN"));
    assert.ok(f.client.deletes.some((entry) => entry.channel === "C1"));
    assert.equal(f.client.posts.filter((post) => post.text === "Stopped.").length, 1);
  } finally {
    await f.stop();
  }
});

test("Stop during approval finalization discards the late stream and skips attachments", async () => {
  const f = await fixture();
  let releaseLateStart: ((value: { ts: string }) => void) | undefined;
  const starts: any[] = [];
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async (args: any) => {
    starts.push(args);
    return new Promise<{ ts: string }>((resolve) => (releaseLateStart = resolve));
  };
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-final-race", command: "send-email", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "115.7" });
    f.core.result = {
      status: "ok",
      reply: "This approved result must stay hidden.",
      attachments: [{ name: "late.txt", mimetype: "text/plain", sizeBytes: 8, blobId: "blob-late" }],
    };
    const approval = f.app.emitAction("hilo_allow_once", "approval-final-race", {
      user: { id: "U1" },
      channel: { id: "D1" },
      message: { ts: "1700000000.000001", thread_ts: "115.7" },
    });
    await waitFor(() => !!releaseLateStart);
    await f.app.emitEvent("agent_session_stopped", {
      channel: "D1",
      thread_ts: "115.7",
      user: "U1",
      message_ts: "approval-final-in-progress",
      event_ts: "115.8",
    });
    releaseLateStart!({ ts: "late-approval-final-stream" });
    await approval;

    assert.equal(starts.length, 1);
    assert.equal(f.client.fileUploads.length, 0);
    assert.ok(f.client.deletes.some((entry) => entry.ts === "late-approval-final-stream"));
    assert.equal(f.client.updates.at(-1)?.text, "Canceled.");
    assert.doesNotMatch(JSON.stringify([...f.client.posts, ...f.client.updates]), /approved result/i);
  } finally {
    await f.stop();
  }
});

test("Stop during an approved attachment keeps settlement open and suppresses the file", async () => {
  const f = await fixture();
  f.core.durableIntake = true;
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async () => ({ ts: "1788030302.000001" });
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-attachment-stop", command: "export-file", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "export it",
      ts: "1788030301.000000",
    });
    f.core.result = {
      status: "ok",
      reply: "Exported.",
      attachments: [{ name: "export.txt", mimetype: "text/plain", sizeBytes: 8, blobId: "blob-export" }],
    };
    f.core.holdBlob();
    const approval = f.app.emitAction("hilo_allow_once", "approval-attachment-stop", {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "1788030301.000000" },
      action_ts: "1788030302.000000",
    });
    await waitFor(() => f.core.blobReads === 1);
    assert.equal(
      (
        await f.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-attachment-stop",
        })
      )?.continuation?.state,
      "submitted",
    );
    await f.app.emitEvent(
      "agent_session_stopped",
      {
        channel: "D1",
        thread_ts: "1788030301.000000",
        user: "U1",
        message_ts: "1788030302.000001",
        event_ts: "1788030303.000000",
      },
      "Ev-approval-attachment-stop",
    );
    f.core.releaseBlob();
    await approval;
    assert.equal(f.client.fileUploads.length, 0);
    assert.equal(f.client.updates.at(-1)?.text, "Canceled.");
    assert.equal(
      (
        await f.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-attachment-stop",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    f.core.releaseBlob();
    await f.stop();
  }
});

test("Stop during a failed native approval begin never falls through to ordinary delivery", async () => {
  const f = await fixture();
  const starts: any[] = [];
  let processingCalls = 0;
  let rejectContinuationBegin: ((error: Error) => void) | undefined;
  (f.client as any).apiCall = async (_method: string, args: any) => {
    if (args.status === "processing" && ++processingCalls === 2) {
      return new Promise((_resolve, reject) => {
        rejectContinuationBegin = reject;
      });
    }
    return { ok: true };
  };
  (f.client.chat as any).startStream = async (args: any) => {
    starts.push(args);
    return { ts: "unexpected-stream" };
  };
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-begin-race", command: "send-email", reason: "external write" }],
  };
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "send it", ts: "116.1" });
    f.core.result = { status: "ok", reply: "This fallback result must stay hidden." };
    const approval = f.app.emitAction("hilo_allow_once", "approval-begin-race", {
      user: { id: "U1" },
      channel: { id: "D1" },
      message: { ts: "1700000000.000001", thread_ts: "116.1" },
    });
    await waitFor(() => !!rejectContinuationBegin);
    const stopEvent = {
      channel: "D1",
      thread_ts: "116.1",
      user: "U1",
      message_ts: "begin-race-stream",
      event_ts: "116.2",
    };
    await assert.rejects(
      () => f.app.emitEvent("agent_session_stopped", stopEvent, "Ev-approval-begin-stop"),
      (error: any) => {
        assert.match(String(error?.cause?.message), /durable Slack Agent stop status intent is pending/);
        return true;
      },
    );
    assert.equal(
      f.client.posts.filter((post) => post.text === "Stopped.").length,
      0,
      "a held status lease must leave the stop unacknowledged for redelivery",
    );
    rejectContinuationBegin!(new Error("feature_disabled"));
    await approval;
    await f.app.emitEvent("agent_session_stopped", stopEvent, "Ev-approval-begin-stop");

    assert.equal(f.core.turns.length, 1, "Stop wins before the approval is submitted to core");
    assert.equal(starts.length, 0);
    assert.equal(f.client.posts.filter((post) => post.text === "Stopped.").length, 1);
    assert.doesNotMatch(JSON.stringify([...f.client.posts, ...f.client.updates]), /fallback result/i);
    assert.equal(f.client.updates.at(-1)?.text, "Canceled.");
  } finally {
    await f.stop();
  }
});

test("a channel approval continuation keeps its recipient team on the same native session", async () => {
  const f = await fixture();
  const starts: any[] = [];
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async (args: any) => {
    starts.push(args);
    return { ts: "channel-approval-stream" };
  };
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-channel", command: "calendar-write", reason: "external write" }],
  };
  try {
    await f.app.emitEvent("app_mention", {
      channel: "C1",
      channel_type: "channel",
      user: "U1",
      text: "<@UBOT> schedule it",
      ts: "120.1",
    });
    f.core.result = { status: "ok", reply: "The approved calendar event was created." };
    await f.app.emitAction("hilo_allow_once", "approval-channel", {
      user: { id: "U1" },
      channel: { id: "DOPEN" },
      message: { ts: "1700000000.000001" },
      action_ts: "120.2",
    });

    assert.equal(starts.at(-1)?.channel, "C1");
    assert.equal(starts.at(-1)?.thread_ts, "120.1");
    assert.equal(starts.at(-1)?.recipient_user_id, "U1");
    assert.equal(starts.at(-1)?.recipient_team_id, "T1");
    assert.match(String(f.core.turns.at(-1)?.slackAgentSessionToken), /^binding:/);
    assert.equal(f.core.turns.at(-1)?.slackAgentSession?.channelId, "C1");
    assert.equal(f.core.turns.at(-1)?.slackAgentSession?.threadTs, "120.1");
    assert.equal(f.core.turns.at(-1)?.verifiedSlack.channelId, "DOPEN");
    assert.equal(f.core.turns.at(-1)?.conversation.threadRef, "ch:C1:120.1");
  } finally {
    await f.stop();
  }
});

test("remote approval result verifies the origin post before settling after restart", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-remote-result", command: "calendar-write", reason: "external write" }],
  };
  await first.app.emitEvent("app_mention", {
    channel: "C1",
    channel_type: "channel",
    user: "U1",
    text: "<@UBOT> schedule it",
    ts: "120.21",
  });
  first.core.result = { status: "ok", reply: "Remote result exactly once." };
  first.client.failNextApprovalFinalUpdate = true;
  await first.app.emitAction("hilo_allow_once", "approval-remote-result", {
    user: { id: "U1" },
    channel: { id: "DOPEN" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001" },
    action_ts: "120.22",
  });
  assert.equal(first.client.posts.filter((post) => post.text === "Remote result exactly once.").length, 1);
  first.core.approvalRecords.delete("approval-remote-result");
  first.core.approvalNow += 60_001;
  const messagesByChannel = new Map(
    [...first.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
  );
  await first.stop();

  const restarted = await fixture({ core: first.core, messagesByChannel });
  try {
    await waitFor(() =>
      restarted.client.updates.some((update) => String(update.text ?? "").startsWith("Approved; ran ")),
    );
    assert.equal(restarted.client.posts.filter((post) => post.text === "Remote result exactly once.").length, 0);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-remote-result",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("approval recovery reuses exact personal-agent handoff cards after a pre-settlement crash", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [
      { requestId: "approval-agent-request-result", command: "calendar-write", reason: "external write" },
    ],
  };
  await first.app.emitEvent("app_mention", {
    channel: "C1",
    channel_type: "channel",
    user: "U1",
    text: "<@UBOT> schedule and ask Bob",
    ts: "120.26",
  });
  first.core.result = { status: "ok", reply: "[[ask-agent: <@U2> | Verify the private calendar]]" };
  first.core.failNextApprovalSettle = true;
  await first.app.emitAction("hilo_allow_once", "approval-agent-request-result", {
    user: { id: "U1" },
    channel: { id: "DOPEN" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001" },
    action_ts: "120.27",
  });
  const firstHandoffs = first.client.posts.filter((post) =>
    JSON.stringify(post.blocks ?? []).includes("agent_request_run"),
  );
  assert.equal(firstHandoffs.length, 1);
  const submitted = await first.core.approvalAuthorities.get({
    teamId: "T1",
    agentId: "A1",
    requesterUserId: "U1",
    requestId: "approval-agent-request-result",
  });
  assert.equal(submitted?.continuation?.state, "submitted");
  first.core.approvalNow += 60_001;
  const messagesByChannel = new Map(
    [...first.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
  );
  await first.stop();

  const restarted = await fixture({ core: first.core, messagesByChannel });
  try {
    await waitFor(() =>
      restarted.client.updates.some((update) => String(update.text ?? "").startsWith("Approved; ran ")),
    );
    assert.equal(
      restarted.client.posts.filter((post) => JSON.stringify(post.blocks ?? []).includes("agent_request_run")).length,
      0,
    );
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-agent-request-result",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("approval recovery verifies exact uploaded attachment markers before retrying settlement", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-attachment-replay", command: "export-file", reason: "external write" }],
  };
  await first.app.emitMessage({
    channel: "D1",
    channel_type: "im",
    user: "U1",
    text: "export it",
    ts: "120.28",
  });
  first.core.result = {
    status: "ok",
    reply: "Exported.",
    attachments: [{ name: "export.txt", mimetype: "text/plain", sizeBytes: 8, blobId: "blob-replay" }],
  };
  first.core.failNextApprovalSettle = true;
  await first.app.emitAction("hilo_allow_once", "approval-attachment-replay", {
    user: { id: "U1" },
    channel: { id: "D1" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001", thread_ts: "120.28" },
    action_ts: "120.29",
  });
  assert.equal(first.client.fileUploads.length, 1);
  assert.match(first.client.fileUploads[0].file_uploads[0].alt_txt, /qm-attachment:[a-f0-9]{64}/);
  first.core.approvalNow += 60_001;
  const messagesByChannel = new Map(
    [...first.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
  );
  await first.stop();

  const restarted = await fixture({ core: first.core, messagesByChannel });
  try {
    await waitFor(() => restarted.client.updates.some((update) => /Exported/.test(update.text ?? "")));
    assert.equal(restarted.client.fileUploads.length, 0);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-attachment-replay",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await restarted.stop();
  }
});

test("stopped approval recovery settles only after recovered and new Slack output cleanup converges", async () => {
  const first = await fixture();
  const enableNative = (client: FakeSlackClient): void => {
    (client as any).apiCall = async () => ({ ok: true });
    (client.chat as any).startStream = async () => ({ ts: "1788030402.000001" });
    (client.chat as any).appendStream = async () => ({ ok: true });
    (client.chat as any).stopStream = async () => ({ ok: true });
  };
  const workflow = Buffer.from(
    JSON.stringify({
      version: 1,
      renderer: "qm.card.v1",
      fallbackText: "Private export",
      payload: { heading: "Private export", sections: [] },
    }),
  );
  const attachments = [
    {
      name: "private.workflow.json",
      mimetype: "application/vnd.qm.workflow-card+json",
      sizeBytes: workflow.length,
      blobId: "blob-workflow",
      renderOnly: true as const,
    },
    { name: "recovered.txt", mimetype: "text/plain", sizeBytes: 9, blobId: "blob-recovered" },
    { name: "new.txt", mimetype: "text/plain", sizeBytes: 3, blobId: "blob-new" },
  ];
  const blobs = new Map([
    ["blob-workflow", workflow],
    ["blob-recovered", Buffer.from("recovered")],
    ["blob-new", Buffer.from("new")],
  ]);
  (first.core as any).readBlob = async (blobId: string) => blobs.get(blobId)!;
  first.core.durableIntake = true;
  enableNative(first.client);
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-cleanup-retry", command: "export-file", reason: "external write" }],
  };
  let messagesAfterCrash: Map<string, any[]>;
  let workflowCardTs = "";
  try {
    await first.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "export it",
      ts: "1788030401.000000",
    });
    first.core.result = { status: "ok", reply: "Exported.", attachments };
    const postMessage = first.client.chat.postMessage.bind(first.client.chat);
    (first.client.chat as any).postMessage = async (args: any) => {
      if (String(args.text ?? "").startsWith("⚠️ I couldn't attach")) {
        throw new Error("simulated crash after partial Slack output");
      }
      return postMessage(args);
    };
    (first.client.files as any).uploadV2 = async (args: any) => {
      first.client.fileUploads.push(args);
      first.client.messagesByChannel.set(args.channel_id, [
        ...(first.client.messagesByChannel.get(args.channel_id) ?? []),
        {
          ts: "1788030402.000002",
          ...(args.thread_ts ? { thread_ts: args.thread_ts } : {}),
          files: [
            {
              id: "F-recovered",
              name: args.file_uploads[0].filename,
              alt_txt: args.file_uploads[0].alt_txt,
            },
          ],
        },
      ]);
      throw new Error("simulated partial file upload outcome");
    };
    await first.app.emitAction("hilo_allow_once", "approval-cleanup-retry", {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "1788030401.000000" },
      action_ts: "1788030402.000000",
    });
    workflowCardTs = String(
      (first.client.messagesByChannel.get("D1") ?? []).find((message) => message.metadata?.event_type === "qm_delivery")
        ?.ts ?? "",
    );
    assert.ok(workflowCardTs);
    assert.equal(first.core.approvalSettlementAttempts, 0);
    assert.equal(first.app.actionAcks.length, 1);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-cleanup-retry",
        })
      )?.continuation?.state,
      "submitted",
    );
    messagesAfterCrash = new Map(
      [...first.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
    );
    first.core.approvalNow += 60_001;
  } finally {
    await first.stop();
  }

  let uploadStarted = false;
  let releaseNewUpload: (() => void) | undefined;
  const retrying = await fixture({
    core: first.core,
    messagesByChannel: messagesAfterCrash!,
    configureClient: (client) => {
      enableNative(client);
      (client.files as any).uploadV2 = async (args: any) => {
        client.fileUploads.push(args);
        uploadStarted = true;
        return new Promise<{ files: Array<{ id: string }> }>((resolve) => {
          releaseNewUpload = () => {
            client.messagesByChannel.set(args.channel_id, [
              ...(client.messagesByChannel.get(args.channel_id) ?? []),
              {
                ts: "1788030403.000002",
                ...(args.thread_ts ? { thread_ts: args.thread_ts } : {}),
                files: [
                  {
                    id: "F-new",
                    name: args.file_uploads[0].filename,
                    alt_txt: args.file_uploads[0].alt_txt,
                  },
                ],
              },
            ]);
            resolve({ files: [{ id: "F-new" }] });
          };
        });
      };
      (client.chat as any).delete = async (args: any) => {
        client.deletes.push(args);
        if (args.ts === workflowCardTs) {
          throw { code: "slack_webapi_rate_limited_error", data: { error: "ratelimited" } };
        }
        return { ok: true };
      };
      (client.files as any).delete = async (args: any) => {
        client.fileDeletes.push(args);
        throw { statusCode: 503, data: { error: "internal_error" } };
      };
    },
  });
  let messagesAfterFailedCleanup: Map<string, any[]>;
  try {
    await waitFor(() => uploadStarted && !!releaseNewUpload);
    await retrying.app.emitEvent(
      "agent_session_stopped",
      {
        channel: "D1",
        thread_ts: "1788030401.000000",
        user: "U1",
        message_ts: "1788030402.000001",
        event_ts: "1788030403.000000",
      },
      "Ev-approval-cleanup-retry",
    );
    releaseNewUpload!();
    await waitFor(() =>
      retrying.client.updates.some((update) => String(update.text ?? "").includes("durable result will be delivered")),
    );
    assert.equal(first.core.approvalSettlementAttempts, 0);
    assert.equal(retrying.app.actionAcks.length, 0);
    assert.ok(retrying.client.deletes.some((args) => args.ts === workflowCardTs));
    assert.deepEqual(retrying.client.fileDeletes.map((args) => args.file).sort(), ["F-new", "F-recovered"]);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-cleanup-retry",
        })
      )?.continuation?.state,
      "submitted",
    );
    messagesAfterFailedCleanup = new Map(
      [...retrying.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
    );
    first.core.approvalNow += 60_001;
  } finally {
    releaseNewUpload?.();
    await retrying.stop();
  }

  const converged = await fixture({
    core: first.core,
    messagesByChannel: messagesAfterFailedCleanup!,
    configureClient: enableNative,
  });
  try {
    await waitFor(() => first.core.approvalSettlementAttempts === 1);
    assert.equal(converged.client.fileUploads.length, 0);
    assert.equal(converged.app.actionAcks.length, 0);
    assert.ok(converged.client.deletes.some((args) => args.ts === workflowCardTs));
    assert.deepEqual(converged.client.fileDeletes.map((args) => args.file).sort(), ["F-new", "F-recovered"]);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-cleanup-retry",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await converged.stop();
  }
});

test("stopped approval recovery retains unresolved results before reconciling prior output markers", async () => {
  const first = await fixture();
  const enableNative = (client: FakeSlackClient): void => {
    (client as any).apiCall = async () => ({ ok: true });
    (client.chat as any).startStream = async () => ({ ts: "1788030502.000001" });
    (client.chat as any).appendStream = async () => ({ ok: true });
    (client.chat as any).stopStream = async () => ({ ok: true });
  };
  const workflow = Buffer.from(
    JSON.stringify({
      version: 1,
      renderer: "qm.card.v1",
      fallbackText: "Stopped export",
      payload: { heading: "Stopped export", sections: [] },
    }),
  );
  const attachments = [
    {
      name: "stopped.workflow.json",
      mimetype: "application/vnd.qm.workflow-card+json",
      sizeBytes: workflow.length,
      blobId: "blob-stopped-workflow",
      renderOnly: true as const,
    },
    { name: "stopped.txt", mimetype: "text/plain", sizeBytes: 7, blobId: "blob-stopped-file" },
  ];
  const blobs = new Map([
    ["blob-stopped-workflow", workflow],
    ["blob-stopped-file", Buffer.from("stopped")],
  ]);
  (first.core as any).readBlob = async (blobId: string) => blobs.get(blobId)!;
  first.core.durableIntake = true;
  enableNative(first.client);
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-unresolved-cleanup", command: "export-file", reason: "external write" }],
  };
  let uploadStarted = false;
  let releaseUpload: (() => void) | undefined;
  let messagesAfterCrash: Map<string, any[]>;
  let workflowCardTs = "";
  try {
    await first.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "export it",
      ts: "1788030501.000000",
    });
    first.core.result = { status: "ok", reply: "Exported.", attachments };
    (first.client.files as any).uploadV2 = async (args: any) => {
      first.client.fileUploads.push(args);
      uploadStarted = true;
      return new Promise<{ files: Array<{ id: string }> }>((resolve) => {
        releaseUpload = () => {
          first.client.messagesByChannel.set(args.channel_id, [
            ...(first.client.messagesByChannel.get(args.channel_id) ?? []),
            {
              ts: "1788030502.000002",
              ...(args.thread_ts ? { thread_ts: args.thread_ts } : {}),
              files: [
                {
                  id: "F-unresolved",
                  name: args.file_uploads[0].filename,
                  alt_txt: args.file_uploads[0].alt_txt,
                },
              ],
            },
          ]);
          resolve({ files: [{ id: "F-unresolved" }] });
        };
      });
    };
    (first.client.chat as any).delete = async (args: any) => {
      first.client.deletes.push(args);
      const message = (first.client.messagesByChannel.get(args.channel) ?? []).find(
        (candidate) => candidate.ts === args.ts,
      );
      if (message?.metadata?.event_type === "qm_delivery") {
        throw Object.assign(new Error("simulated cleanup network failure"), { code: "ECONNRESET" });
      }
      return { ok: true };
    };
    (first.client.files as any).delete = async (args: any) => {
      first.client.fileDeletes.push(args);
      throw Object.assign(new Error("simulated cleanup network failure"), { code: "ECONNRESET" });
    };
    const approval = first.app.emitAction("hilo_allow_once", "approval-unresolved-cleanup", {
      user: { id: "U1" },
      channel: { id: "D1" },
      team: { id: "T1" },
      message: { ts: "1700000000.000001", thread_ts: "1788030501.000000" },
      action_ts: "1788030502.000000",
    });
    await waitFor(() => uploadStarted && !!releaseUpload);
    await first.app.emitEvent(
      "agent_session_stopped",
      {
        channel: "D1",
        thread_ts: "1788030501.000000",
        user: "U1",
        message_ts: "1788030502.000001",
        event_ts: "1788030503.000000",
      },
      "Ev-approval-unresolved-cleanup",
    );
    releaseUpload!();
    await approval;
    workflowCardTs = String(
      (first.client.messagesByChannel.get("D1") ?? []).find((message) => message.metadata?.event_type === "qm_delivery")
        ?.ts ?? "",
    );
    assert.ok(workflowCardTs);
    assert.equal(first.core.approvalSettlementAttempts, 0);
    assert.equal(first.app.actionAcks.length, 1);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-unresolved-cleanup",
        })
      )?.continuation?.state,
      "submitted",
    );
    messagesAfterCrash = new Map(
      [...first.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
    );
    first.core.approvalNow += 60_001;
  } finally {
    releaseUpload?.();
    await first.stop();
  }

  first.core.failNextWaitRun = true;
  const unresolved = await fixture({
    core: first.core,
    messagesByChannel: messagesAfterCrash!,
    configureClient: enableNative,
  });
  let messagesAfterUnresolvedRecovery: Map<string, any[]>;
  try {
    await waitFor(() =>
      unresolved.client.updates.some((update) =>
        String(update.text ?? "").includes("durable result will be delivered"),
      ),
    );
    assert.equal(first.core.approvalSettlementAttempts, 0);
    assert.equal(unresolved.app.actionAcks.length, 0);
    assert.deepEqual(unresolved.client.deletes, []);
    assert.deepEqual(unresolved.client.fileDeletes, []);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-unresolved-cleanup",
        })
      )?.continuation?.state,
      "submitted",
    );
    messagesAfterUnresolvedRecovery = new Map(
      [...unresolved.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
    );
    first.core.approvalNow += 60_001;
  } finally {
    await unresolved.stop();
  }

  const recovered = await fixture({
    core: first.core,
    messagesByChannel: messagesAfterUnresolvedRecovery!,
    configureClient: enableNative,
  });
  try {
    await waitFor(() => first.core.approvalSettlementAttempts === 1);
    assert.equal(recovered.client.fileUploads.length, 0);
    assert.equal(recovered.app.actionAcks.length, 0);
    assert.ok(recovered.client.deletes.some((args) => args.ts === workflowCardTs));
    assert.deepEqual(recovered.client.fileDeletes, [{ file: "F-unresolved" }]);
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-unresolved-cleanup",
        })
      )?.continuation?.state,
      "settled",
    );
  } finally {
    await recovered.stop();
  }
});

test("remote quarantine posts one safe origin reply before ACK and settles after restart", async () => {
  const first = await fixture();
  first.core.durableIntake = true;
  first.core.result = {
    status: "pending_approval",
    pendingApprovals: [
      { requestId: "approval-remote-quarantine", command: "calendar-write", reason: "external write" },
    ],
  };
  await first.app.emitEvent("app_mention", {
    channel: "C1",
    channel_type: "channel",
    user: "U1",
    text: "<@UBOT> schedule it",
    ts: "120.31",
  });
  first.core.result = {
    status: "refused",
    reason: "internal quarantine details",
    adminUrl: "https://internal.example.test/quarantine/1",
    refusalKind: "security_quarantine",
  };
  first.client.failNextUpdateText = SECURITY_QUARANTINE_REFUSAL_TEXT;
  await first.app.emitAction("hilo_allow_once", "approval-remote-quarantine", {
    user: { id: "U1" },
    channel: { id: "DOPEN" },
    team: { id: "T1" },
    message: { ts: "1700000000.000001" },
    action_ts: "120.32",
  });
  const submitted = await first.core.approvalAuthorities.get({
    teamId: "T1",
    agentId: "A1",
    requesterUserId: "U1",
    requestId: "approval-remote-quarantine",
  });
  assert.equal(
    first.client.posts.filter((post) => post.channel === "C1" && post.text === SECURITY_QUARANTINE_REFUSAL_TEXT).length,
    1,
  );
  assert.doesNotMatch(JSON.stringify([...first.client.posts, ...first.client.updates]), /internal quarantine details/);
  assert.doesNotMatch(JSON.stringify([...first.client.posts, ...first.client.updates]), /internal\.example\.test/);
  assert.equal(first.core.ackedRunDeliveries.includes(submitted!.continuation!.runId!), false);

  first.core.approvalRecords.delete("approval-remote-quarantine");
  first.core.approvalNow += 60_001;
  const messagesByChannel = new Map(
    [...first.client.messagesByChannel.entries()].map(([channel, messages]) => [channel, [...messages]]),
  );
  await first.stop();

  const restarted = await fixture({ core: first.core, messagesByChannel });
  try {
    await waitFor(() => restarted.client.updates.some((update) => update.text === SECURITY_QUARANTINE_REFUSAL_TEXT));
    assert.equal(
      restarted.client.posts.filter((post) => post.channel === "C1" && post.text === SECURITY_QUARANTINE_REFUSAL_TEXT)
        .length,
      0,
    );
    assert.ok(first.core.ackedRunDeliveries.includes(submitted!.continuation!.runId!));
    assert.equal(
      (
        await first.core.approvalAuthorities.get({
          teamId: "T1",
          agentId: "A1",
          requesterUserId: "U1",
          requestId: "approval-remote-quarantine",
        })
      )?.continuation?.state,
      "settled",
    );
    assert.doesNotMatch(JSON.stringify([...restarted.client.posts, ...restarted.client.updates]), /internal/);
  } finally {
    await restarted.stop();
  }
});

test("a failed approval DM open never leaks the command card into its origin channel", async () => {
  const f = await fixture();
  (f.client.conversations as any).open = async () => {
    throw new Error("cannot_dm_bot");
  };
  f.core.result = {
    status: "pending_approval",
    pendingApprovals: [{ requestId: "approval-private", command: "send-email --private", reason: "external write" }],
  };
  try {
    await f.app.emitEvent("app_mention", {
      channel: "C1",
      channel_type: "channel",
      user: "U1",
      text: "<@UBOT> send it",
      ts: "121.1",
    });
    assert.equal(
      f.client.posts.some((post) => JSON.stringify(post).includes("send-email --private")),
      false,
    );
    assert.equal(f.client.ephemerals.length, 1);
    assert.match(f.client.ephemerals[0].text, /couldn't open a private approval message/i);
  } finally {
    await f.stop();
  }
});

test("agent_session_stopped aborts the mapped run and clears native processing state", async () => {
  const f = await fixture();
  const statusCalls: any[] = [];
  const stopCalls: any[] = [];
  (f.client as any).apiCall = async (method: string, args: any) => void statusCalls.push({ method, args });
  (f.client.chat as any).stopStream = async (args: any) => void stopCalls.push(args);
  f.core.activeRun = "R-stop";
  try {
    await f.core.primeAgentSession("100.1", "R-stop", "stream-1");
    await f.app.emitEvent("agent_session_stopped", {
      channel_id: "D1",
      thread_ts: "100.1",
      user: "U2",
      message_ts: "stream-1",
      event_ts: "100.2",
    });
    assert.deepEqual(f.core.abortedRuns, ["R-stop"]);
    assert.equal(statusCalls[0].method, "agents.sessions.setStatus");
    assert.equal(statusCalls[0].args.status, "active");
    assert.deepEqual(stopCalls, []);
    assert.equal(f.client.posts.at(-1)?.text, "Stopped.");
    assert.equal(f.client.posts.at(-1)?.thread_ts, "100.1");
  } finally {
    await f.stop();
  }
});

test("official Agent Sessions stop forwards exact durable authority and every streaming message", async () => {
  const f = await fixture();
  const statusCalls: any[] = [];
  const stopCalls: any[] = [];
  (f.client as any).apiCall = async (method: string, args: any) => void statusCalls.push({ method, args });
  (f.client.chat as any).stopStream = async (args: any) => void stopCalls.push(args);
  f.core.activeRun = "R-official-stop";
  try {
    await f.core.primeAgentSession("100.1", "R-official-stop", "stream-1");
    await f.app.emitEvent("agent_session_stopped", {
      channel: "D1",
      thread_ts: "100.1",
      streaming_message_ts: ["stream-1", "stream-2"],
      user: "U2",
      event_ts: "100.2",
    });
    assert.deepEqual(f.core.stopInputs, [
      {
        teamId: "T1",
        agentId: "A1",
        channelId: "D1",
        threadTs: "100.1",
        eventId: "Ev-agent_session_stopped-D1-undefined",
        eventTs: "100.2",
        stoppedByUserId: "U2",
        streamingMessageTs: ["stream-1", "stream-2"],
      },
    ]);
    assert.deepEqual(f.core.abortedRuns, ["R-official-stop"]);
    assert.deepEqual(stopCalls, []);
    assert.equal(statusCalls.at(-1)?.method, "agents.sessions.setStatus");
    assert.equal(statusCalls.at(-1)?.args.status, "active");
  } finally {
    await f.stop();
  }
});

test("a second channel participant stops every run bound to the exact Agent Session", async () => {
  const f = await fixture();
  const key = { teamId: "T1", agentId: "A1", channelId: "C1", threadTs: "200.1" };
  const token = slackAgentBindingToken(key, "U1", "200.1", "200.1");
  (f.client as any).apiCall = async () => ({ ok: true });
  try {
    await f.core.agentSessions.begin({
      ...key,
      ownerUserId: "U1",
      token,
      triggerTs: "200.1",
      coreThreadRef: "ch:C1:200.1",
      authorityMessageTs: "200.1",
    });
    await f.core.agentSessions.bindRun({ ...key, token, runId: "R-channel-one" });
    await f.core.agentSessions.bindRun({ ...key, token, runId: "R-channel-two" });
    await f.app.emitEvent(
      "agent_session_stopped",
      { channel: "C1", thread_ts: "200.1", user: "U2", event_ts: "200.2" },
      "Ev-channel-stop-all",
    );

    assert.deepEqual(f.core.abortedRuns, ["R-channel-one", "R-channel-two"]);
    assert.equal(f.core.stopInputs[0]?.stoppedByUserId, "U2");
    assert.equal(f.client.posts.filter((post) => post.text === "Stopped.").length, 1);
    const record = await f.core.agentSessions.get(key);
    assert.equal(record?.bindings[0]?.ownerUserId, "U1");
    assert.equal(record?.stopEvents[0]?.state, "acknowledged");
  } finally {
    await f.stop();
  }
});

test("an already-stopped native stream confirms once and stays acknowledged across restart and redelivery", async () => {
  const first = await fixture();
  const firstStatuses: any[] = [];
  let firstStopped = false;
  (first.client as any).apiCall = async (method: string, args: any) => void firstStatuses.push({ method, args });
  (first.client.chat as any).stopStream = async () => {
    throw { data: { error: "stopped_by_user" } };
  };
  try {
    await first.core.primeAgentSession("210.1", "R-already-stopped", "210.9");
    await first.app.emitEvent(
      "agent_session_stopped",
      {
        channel: "D1",
        thread_ts: "210.1",
        streaming_message_ts: ["210.9"],
        user: "U2",
        event_ts: "210.2",
      },
      "Ev-already-stopped",
    );

    assert.deepEqual(first.core.abortedRuns, ["R-already-stopped"]);
    assert.deepEqual(
      firstStatuses.map((call) => call.args.status),
      ["active"],
    );
    assert.equal(first.client.posts.filter((post) => post.text === "Stopped.").length, 1);
    const persisted = await first.core.agentSessions.get({
      teamId: "T1",
      agentId: "A1",
      channelId: "D1",
      threadTs: "210.1",
    });
    assert.equal(persisted?.stopEvents[0]?.state, "acknowledged");
    assert.ok(persisted?.stopEvents[0]?.confirmationTs);
    await first.stop();
    firstStopped = true;

    const restarted = await fixture({ core: first.core });
    const restartedStatuses: any[] = [];
    (restarted.client as any).apiCall = async (method: string, args: any) =>
      void restartedStatuses.push({ method, args });
    (restarted.client.chat as any).stopStream = async () => {
      throw { data: { error: "message_not_in_streaming_state" } };
    };
    try {
      await restarted.app.emitEvent(
        "agent_session_stopped",
        {
          channel: "D1",
          thread_ts: "210.1",
          streaming_message_ts: ["210.9"],
          user: "U2",
          event_ts: "210.2",
        },
        "Ev-already-stopped",
      );
      assert.deepEqual(restartedStatuses, []);
      assert.deepEqual(restarted.client.posts, []);
      assert.equal(first.core.stopInputs.filter((input) => input.eventId === "Ev-already-stopped").length, 2);
    } finally {
      await restarted.stop();
    }
  } finally {
    if (!firstStopped) await first.stop();
  }
});

test("Agent Session stop redelivery honors a durable provider Retry-After before making another call", async () => {
  const f = await fixture();
  let statusCalls = 0;
  (f.client as any).apiCall = async () => {
    statusCalls += 1;
    throw { code: "slack_webapi_rate_limited_error", retryAfter: 90, data: { error: "ratelimited" } };
  };
  try {
    await f.core.primeAgentSession("220.1", "R-retry-window", "220.9");
    const event = {
      channel: "D1",
      thread_ts: "220.1",
      streaming_message_ts: ["220.9"],
      user: "U2",
      event_ts: "220.2",
    };
    await assert.rejects(
      f.app.emitEvent("agent_session_stopped", event, "Ev-retry-window"),
      /Slack requested retry after (?:8\d{4}|90000)ms/,
    );
    const retry = await f.core.agentSessions.retryWindow({
      teamId: "T1",
      agentId: "A1",
      channelId: "D1",
      threadTs: "220.1",
      method: "agents.sessions.setStatus",
    });
    const statusIntent = await f.core.agentStatusIntents.get({
      teamId: "T1",
      agentId: "A1",
      channelId: "D1",
      threadTs: "220.1",
    });
    assert.equal(statusCalls, 1);
    assert.ok((retry?.notBefore ?? 0) >= Date.now() + 89_000);
    assert.equal(statusIntent?.state, "pending");
    assert.deepEqual(statusIntent?.authority, { kind: "stop", eventId: "Ev-retry-window" });
    await assert.rejects(
      f.app.emitEvent("agent_session_stopped", event, "Ev-retry-window"),
      /Slack requested retry after/,
    );
    assert.equal(statusCalls, 1);
    assert.equal(f.client.posts.length, 0);
  } finally {
    await f.stop();
  }
});

test("Agent Session stop recovers after more than three durable provider deferrals", async (t) => {
  let now = 1_000_000;
  t.mock.method(Date, "now", () => now);
  const f = await fixture();
  let statusCalls = 0;
  (f.client as any).apiCall = async () => {
    statusCalls += 1;
    if (statusCalls <= 4) {
      throw { code: "slack_webapi_rate_limited_error", retryAfter: 3, data: { error: "ratelimited" } };
    }
    return { ok: true };
  };
  try {
    await f.core.primeAgentSession("225.1", "R-retry-recovery", "225.9");
    const event = {
      channel: "D1",
      thread_ts: "225.1",
      streaming_message_ts: ["225.9"],
      user: "U2",
      event_ts: "225.2",
    };
    const retryKey = {
      teamId: "T1",
      agentId: "A1",
      channelId: "D1",
      threadTs: "225.1",
      method: "agents.sessions.setStatus",
    };
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      await assert.rejects(
        f.app.emitEvent("agent_session_stopped", event, "Ev-retry-recovery"),
        /Slack requested retry after 3000ms/,
      );
      const retry = await f.core.agentSessions.retryWindow(retryKey);
      assert.equal(retry?.attempts, attempt);
      assert.equal(statusCalls, attempt);
      now = (retry?.notBefore ?? now) + 1;
    }

    await f.app.emitEvent("agent_session_stopped", event, "Ev-retry-recovery");
    assert.equal(statusCalls, 5);
    assert.equal(await f.core.agentSessions.retryWindow(retryKey), null);
    assert.equal(f.client.posts.filter((post) => post.text === "Stopped.").length, 1);
    assert.equal(
      (
        await f.core.agentSessions.get({
          teamId: "T1",
          agentId: "A1",
          channelId: "D1",
          threadTs: "225.1",
        })
      )?.stopEvents[0]?.state,
      "acknowledged",
    );
  } finally {
    await f.stop();
  }
});

test("a stop awaiting durable submission binding withholds confirmation and acknowledgment", async () => {
  const f = await fixture();
  const key = { teamId: "T1", agentId: "A1", channelId: "D1", threadTs: "224.1" };
  const token = slackAgentBindingToken(key, "U1", "224.1", "224.1");
  let statusCalls = 0;
  (f.client as any).apiCall = async () => void (statusCalls += 1);
  try {
    await f.core.agentSessions.begin({
      ...key,
      ownerUserId: "U1",
      token,
      triggerTs: "224.1",
      coreThreadRef: "dm:D1:224.1",
      authorityMessageTs: "224.1",
    });
    f.core.deferNextAgentStop = true;
    await assert.rejects(
      f.app.emitEvent(
        "agent_session_stopped",
        { channel: "D1", thread_ts: "224.1", user: "U2", event_ts: "224.2" },
        "Ev-pending-submission",
      ),
      /waiting for durable submission binding/,
    );
    assert.equal(statusCalls, 0);
    assert.equal(f.client.posts.length, 0);
    assert.equal((await f.core.agentSessions.get(key))?.stopEvents[0]?.state, "pending");
  } finally {
    await f.stop();
  }
});

test("an unverified official Agent Sessions stop fails closed", async () => {
  const f = await fixture();
  const statusCalls: any[] = [];
  const stopCalls: any[] = [];
  (f.client as any).apiCall = async (method: string, args: any) => void statusCalls.push({ method, args });
  (f.client.chat as any).stopStream = async (args: any) => void stopCalls.push(args);
  try {
    await f.app.emitEvent("agent_session_stopped", {
      channel: "D1",
      thread_ts: "100.1",
      streaming_message_ts: ["stream-current"],
      user: "U1",
      event_ts: "100.2",
    });
    assert.equal(f.core.stopInputs.length, 1);
    assert.deepEqual(f.core.abortedRuns, []);
    assert.deepEqual(stopCalls, []);
    assert.deepEqual(statusCalls, []);
    assert.deepEqual(f.client.posts, []);
  } finally {
    await f.stop();
  }
});

test("a stopped native run posts one confirmation and suppresses its later result", async () => {
  const f = await fixture();
  const stopCalls: any[] = [];
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async () => ({ ts: "stream-1" });
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async (args: any) => void stopCalls.push(args);
  f.core.holdRun("R-stop");
  try {
    const turn = f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "work", ts: "100.1" });
    await waitFor(() => f.core.polled.length === 1);
    f.core.activeRun = "R-stop";
    await f.app.emitEvent("agent_session_stopped", {
      channel: "D1",
      thread_ts: "100.1",
      user: "U1",
      message_ts: "stream-1",
      event_ts: "100.2",
    });
    f.core.finishRun({ status: "ok", reply: "late result" });
    await turn;
    assert.deepEqual(f.core.abortedRuns, ["R-stop"]);
    assert.deepEqual(stopCalls, []);
    assert.deepEqual(
      f.client.posts.map((post) => post.text),
      ["Stopped."],
    );
  } finally {
    await f.stop();
  }
});

test("a stop event with no active run does not suppress the next turn in that thread", async () => {
  const f = await fixture();
  const stopCalls: any[] = [];
  (f.client as any).apiCall = async () => ({ ok: true });
  (f.client.chat as any).startStream = async () => ({ ts: "stream-1" });
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async (args: any) => void stopCalls.push(args);
  try {
    await f.app.emitEvent("agent_session_stopped", {
      channel: "D1",
      thread_ts: "100.1",
      user: "U1",
      event_ts: "100.2",
    });
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "new work",
      thread_ts: "100.1",
      ts: "100.3",
    });
    assert.deepEqual(
      f.client.posts.map((post) => post.text),
      [],
    );
    assert.equal(stopCalls.length, 1);
    assert.equal(f.core.turns.at(-1)?.text, "new work");
  } finally {
    await f.stop();
  }
});

test("native stream failure after core completion falls back once without failing the handler", async () => {
  const f = await fixture();
  const statuses: string[] = [];
  (f.client as any).apiCall = async (_method: string, args: any) => void statuses.push(args.status);
  (f.client.chat as any).startStream = async () => {
    throw new Error("feature_disabled");
  };
  (f.client.chat as any).appendStream = async () => ({ ok: true });
  (f.client.chat as any).stopStream = async () => ({ ok: true });
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "hello", ts: "100.1" });
    assert.deepEqual(statuses, ["processing", "active"]);
    assert.deepEqual(
      f.client.posts.map((post) => post.text),
      ["agent reply"],
    );
  } finally {
    await f.stop();
  }
});

test("a forwarded Slack message reaches the turn with labeled nested content and files", async (t) => {
  const fetchMock = t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response("data", {
        status: 200,
        headers: { "content-type": "text/plain", "content-length": "4" },
      }),
  );
  const f = await fixture();
  try {
    f.client.filesById.set("F1", {
      id: "F1",
      name: "notes.txt",
      mimetype: "text/plain",
      size: 4,
      url_private_download: "https://files.slack.com/files-pri/F1/notes.txt",
    });
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "please review",
      ts: "100.15",
      attachments: [
        {
          is_msg_unfurl: true,
          author_id: "U2",
          author_name: "Bob",
          channel_name: "project-notes",
          text: "outer message",
          files: [
            {
              id: "F1",
              name: "notes.txt",
              is_hidden_by_limit: 1,
            },
          ],
          message_blocks: [
            {
              message: {
                attachments: [
                  {
                    is_msg_unfurl: true,
                    author_name: "Carol",
                    channel_name: "research",
                    text: "nested message",
                  },
                ],
              },
            },
          ],
        },
      ],
    });

    assert.deepEqual(f.client.fileInfoCalls, ["F1"]);
    assert.equal(fetchMock.mock.callCount(), 1);
    assert.equal(f.core.turns.length, 1);
    assert.equal(
      f.core.turns[0].text,
      "please review\n[forwarded message from Bob in #project-notes] outer message\n" +
        "[forwarded message from Carol in #research] nested message",
    );
    assert.deepEqual(f.core.turns[0].attachments, [
      {
        name: "notes.txt",
        mimetype: "text/plain",
        sizeBytes: 4,
        blobId: "blob-1",
        sourceId: "F1",
        author: "Bob",
      },
    ]);
  } finally {
    await f.stop();
  }
});

test("public channel rosters stay current in the core directory", async () => {
  const f = await fixture();
  try {
    assert.ok(f.core.directories.some((d: any) => d.channelMembers));
    assert.deepEqual(
      f.core.directories
        .at(-1)
        .channelMembers.filter((m: any) => m.channelId === "C1")
        .map((m: any) => m.principalId)
        .sort(),
      ["U1", "U2"],
    );

    f.client.membersByChannel.set("C1", ["U1", "UBOT"]);
    const pushes = f.core.directories.length;
    await f.app.emitEvent("member_left_channel", { user: "U2", channel: "C1", event_ts: "100.2" }, "Ev-u2-left");
    await waitFor(() => f.core.directories.length > pushes);
    assert.deepEqual(
      f.core.directories
        .at(-1)
        .channelMembers.filter((m: any) => m.channelId === "C1")
        .map((m: any) => m.principalId),
      ["U1"],
    );
  } finally {
    await f.stop();
  }
});

test("full directory refreshes bound concurrent Slack roster reads", async () => {
  const f = await fixture({ extraChannels: 5, membershipDelayMs: 10 });
  try {
    assert.equal(f.client.membershipListings.size, 8);
    assert.ok(f.client.maxActiveMembershipListings > 1);
    assert.ok(f.client.maxActiveMembershipListings <= 4);
    assert.ok(f.core.directories.at(-1).channelsSyncedAt <= f.client.firstMembershipListingStartedAt!);
  } finally {
    await f.stop();
  }
});

test("large public channels publish their complete roster and accept internal turns", async () => {
  const f = await fixture();
  try {
    const members = Array.from({ length: 201 }, (_, i) => `UL${i}`);
    for (const id of members) f.client.usersById.set(id, internalUser(id, id));
    f.client.membersByChannel.set("C1", [...members, "UBOT"]);
    const pushes = f.core.directories.length;
    await f.app.emitEvent("member_joined_channel", { user: members[0], channel: "C1", event_ts: "100.3" });
    await waitFor(() => f.core.directories.length > pushes);
    assert.equal(
      f.core.directories.at(-1).channelMembers.filter((m: any) => m.channelId === "C1").length,
      members.length,
    );

    await f.app.emitEvent("app_mention", {
      channel: "C1",
      channel_type: "channel",
      user: members[0],
      text: "<@UBOT> hello",
      ts: "100.4",
    });
    assert.equal(f.core.turns.length, 1);
  } finally {
    await f.stop();
  }
});

test("failed background roster reads are marked unknown instead of clearing known capabilities", async () => {
  const f = await fixture();
  try {
    assert.ok(f.core.directories.at(-1).channelRosterIds.includes("CPX"));
    f.client.membershipFailures.add("CPX");
    const pushes = f.core.directories.length;
    await f.app.emitEvent("channel_rename", { channel: { id: "CPX" }, event_ts: "100.5" });
    await waitFor(() => f.core.directories.length > pushes);
    assert.ok(!f.core.directories.at(-1).channelRosterIds.includes("CPX"));
  } finally {
    await f.stop();
  }
});

test("a failed refresh after a leave event revokes only the departing member", async () => {
  const f = await fixture();
  try {
    f.client.membershipFailures.add("CPX");
    const pushes = f.core.directories.length;
    await f.app.emitEvent("member_left_channel", { user: "U1", channel: "CPX", event_ts: "100.6" });
    await waitFor(() => f.core.directories.length > pushes);
    const pushed = f.core.directories.at(-1);
    assert.ok(!pushed.channelRosterIds.includes("CPX"));
    assert.deepEqual(pushed.channelRevocations, [{ channelId: "CPX", principalId: "U1" }]);
  } finally {
    await f.stop();
  }
});

test("a failed email-mode refresh revokes the departing canonical principal", async () => {
  const f = await fixture({ identityEmail: "1" });
  try {
    f.client.membershipFailures.add("CPX");
    const pushes = f.core.directories.length;
    await f.app.emitEvent("member_left_channel", { user: "U1", channel: "CPX", event_ts: "100.7" });
    await waitFor(() => f.core.directories.length > pushes);
    assert.deepEqual(f.core.directories.at(-1).channelRevocations, [
      { channelId: "CPX", principalId: "alice@example.com" },
    ]);
  } finally {
    await f.stop();
  }
});

test("Slack Connect directory rosters contain only internal principals", async () => {
  const f = await fixture({ externalParticipants: true });
  try {
    const pushed = f.core.directories.at(-1);
    assert.ok(pushed.channelRosterIds.includes("CX"));
    assert.ok(pushed.channelRosterIds.includes("CPX"));
    assert.equal(pushed.channels.find((channel: any) => channel.channelId === "CPX")?.isExternal, true);
    assert.deepEqual(
      pushed.channelMembers.filter((m: any) => m.channelId === "CX").map((m: any) => m.principalId),
      ["U1"],
    );
    assert.deepEqual(
      pushed.channelMembers.filter((m: any) => m.channelId === "CPX").map((m: any) => m.principalId),
      ["U1"],
    );
    assert.ok(pushed.channelRosterIds.includes("CPX"));
    f.client.membershipListings.set("CPX", 0);
    f.client.membershipListings.set("C1", 0);
    const pushes = f.core.directories.length;
    await f.app.emitEvent("channel_rename", { channel: { id: "CPX" }, event_ts: "100.7" });
    await waitFor(() => f.core.directories.length > pushes);
    assert.equal(f.client.membershipListings.get("CPX"), 1);
    assert.equal(f.client.membershipListings.get("C1"), 0);
  } finally {
    await f.stop();
  }
});

test("a human's DM sets the conversation header to the serving model + web surface", async () => {
  const f = await fixture({ webUiPublicUrl: "https://claw.example.dev" });
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "hello", ts: "100.1" });
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(f.client.topics, [
      {
        channel: "D1",
        topic: "Using Claude Opus 4.8 here. <https://claw.example.dev/contexts?scope=personal%3AU1|More settings>",
      },
    ]);
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "again", ts: "100.2" });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(f.client.topics.length, 1);
  } finally {
    await f.stop();
  }
});

test("joining a channel posts the welcome and a pinned header naming the model and project page", async () => {
  const f = await fixture({ webUiPublicUrl: "https://claw.example.dev" });
  try {
    f.core.headerPinScopes.add("channel:C1");
    await f.app.emitEvent("member_joined_channel", { user: "UBOT", channel: "C1", event_ts: "100.1" }, "Ev-bot-join");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(
      f.client.pinnedByChannel.get("C1")?.map((m) => m.text),
      ["Using Claude Opus 4.8 here. <https://claw.example.dev/projects/channel/C1|More settings>"],
    );
    assert.deepEqual(f.client.topics, [], "a channel's topic stays the members' own scratch space");
  } finally {
    await f.stop();
  }
});

test("joining a channel with the toggle off (the default) posts only the welcome — no pin", async () => {
  const f = await fixture({ webUiPublicUrl: "https://claw.example.dev" });
  try {
    await f.app.emitEvent("member_joined_channel", { user: "UBOT", channel: "C1", event_ts: "100.1" }, "Ev-bot-join");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(f.client.posts.length, 1, "only the welcome message lands");
    assert.equal(f.client.pinnedByChannel.get("C1"), undefined);
  } finally {
    await f.stop();
  }
});

test("flipping the toggle on creates the pinned header; flipping it off removes it", async () => {
  const f = await fixture({ webUiPublicUrl: "https://claw.example.dev" });
  try {
    assert.equal(f.core.headerPinChangeListeners.length, 1, "the plugin subscribes to toggle changes");
    f.core.headerPinScopes.add("channel:C1");
    for (const listener of f.core.headerPinChangeListeners) listener("channel:C1");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(
      f.client.pinnedByChannel.get("C1")?.map((m) => m.text),
      ["Using Claude Opus 4.8 here. <https://claw.example.dev/projects/channel/C1|More settings>"],
      "toggle-on posts and pins the header",
    );
    f.core.headerPinScopes.delete("channel:C1");
    for (const listener of f.core.headerPinChangeListeners) listener("channel:C1");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(f.client.pinnedByChannel.get("C1"), [], "toggle-off unpins the header");
    assert.equal(f.client.deletes.length, 1, "and deletes the bot's header message");
  } finally {
    await f.stop();
  }
});

test("a mention in a channel with no pinned header never creates one", async () => {
  const f = await fixture({ webUiPublicUrl: "https://claw.example.dev" });
  try {
    const mention = { channel: "C1", channel_type: "channel", user: "U1", text: "<@UBOT> hi", ts: "100.1" };
    f.client.messagesByChannel.set("C1", [mention]);
    await f.app.emitEvent("app_mention", mention, "Ev-channel-header");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(f.client.pinnedByChannel.get("C1"), undefined);
    assert.deepEqual(f.client.updates, []);
  } finally {
    await f.stop();
  }
});

test("a scope's model change rewrites its channel's pinned header without waiting for a message", async () => {
  const f = await fixture({ webUiPublicUrl: "https://claw.example.dev" });
  try {
    assert.equal(f.core.modelChangeListeners.length, 1, "the plugin subscribes to core's model changes");
    f.core.headerPinScopes.add("channel:C1");
    f.client.pinnedByChannel.set("C1", [
      {
        ts: "50.0",
        user: "UBOT",
        text: "Using Claude Sonnet 5 here. <https://claw.example.dev/projects/channel/C1|More settings>",
      },
    ]);
    for (const listener of f.core.modelChangeListeners) listener("channel:C1");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(
      f.client.updates.map((u) => ({ channel: u.channel, ts: u.ts, text: u.text })),
      [
        {
          channel: "C1",
          ts: "50.0",
          text: "Using Claude Opus 4.8 here. <https://claw.example.dev/projects/channel/C1|More settings>",
        },
      ],
    );
    for (const listener of f.core.modelChangeListeners) listener("personal:alice@example.com");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(f.client.topics, [], "a DM's topic settles on the person's next message, not on a push");
  } finally {
    await f.stop();
  }
});

test("an external guest's DM never reveals the model or the web surface", async () => {
  const f = await fixture({ externalParticipants: true, webUiPublicUrl: "https://claw.example.dev" });
  try {
    await f.app.emitMessage({ channel: "DX", channel_type: "im", user: "UX", text: "hello", ts: "100.1" });
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(f.client.topics, []);
  } finally {
    await f.stop();
  }
});

test("a DM containing !version follows the ordinary turn path", async () => {
  const f = await fixture();
  try {
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "!version", ts: "100.2" });
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].text, "!version");
    assert.deepEqual(
      f.client.posts.map((p) => p.text),
      ["agent reply"],
    );
  } finally {
    await f.stop();
  }
});

test("Slack redelivery and app_mention/message fan-out cannot duplicate a turn", async () => {
  const f = await fixture();
  try {
    const dm = { channel: "D1", channel_type: "im", user: "U1", text: "once", ts: "101.1" };
    await f.app.emitMessage(dm, "Ev-first-delivery");
    await f.app.emitMessage(dm, "Ev-second-delivery");

    const mention = { channel: "C1", channel_type: "channel", user: "U1", text: "<@UBOT> once too", ts: "101.2" };
    f.client.messagesByChannel.set("C1", [mention]);
    await f.app.emitEvent("app_mention", mention, "Ev-mention");
    await f.app.emitMessage(mention, "Ev-message-copy");

    assert.equal(f.core.turns.length, 2);
    assert.equal(f.client.posts.length, 2);
  } finally {
    await f.stop();
  }
});

test("concurrent redelivery waits for the first durable intake boundary", async () => {
  const f = await fixture();
  const delivery = { channel: "D1", channel_type: "im", user: "U1", text: "accept once", ts: "101.25" };
  const firstOutcomes: string[] = [];
  const replayOutcomes: string[] = [];
  f.core.holdSubmit();
  try {
    const first = f.app.emitMessage(delivery, "Ev-intake-first", {
      ackGate: {
        persisted: () => void firstOutcomes.push("persisted"),
        failed: () => void firstOutcomes.push("failed"),
      },
    });
    await waitFor(() => f.core.submitStarted === 1);
    const replay = f.app.emitMessage(delivery, "Ev-intake-replay", {
      ackGate: {
        persisted: () => void replayOutcomes.push("persisted"),
        failed: () => void replayOutcomes.push("failed"),
      },
    });
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(firstOutcomes, []);
    assert.deepEqual(replayOutcomes, []);
    assert.equal(f.core.submitStarted, 1);

    f.core.resumeSubmit();
    await Promise.all([first, replay]);
    assert.deepEqual(firstOutcomes, ["persisted"]);
    assert.deepEqual(replayOutcomes, ["persisted"]);
    assert.equal(f.core.turns.length, 1);
  } finally {
    f.core.resumeSubmit();
    await f.stop();
  }
});

test("a core failure before durable intake rejects every concurrent delivery", async () => {
  const f = await fixture();
  const delivery = { channel: "D1", channel_type: "im", user: "U1", text: "retry me", ts: "101.26" };
  const firstOutcomes: string[] = [];
  const replayOutcomes: string[] = [];
  f.core.submitError = new Error("core unavailable");
  f.core.holdSubmit();
  try {
    const first = f.app.emitMessage(delivery, "Ev-failed-intake-first", {
      ackGate: {
        persisted: () => void firstOutcomes.push("persisted"),
        failed: () => void firstOutcomes.push("failed"),
      },
    });
    await waitFor(() => f.core.submitStarted === 1);
    const replay = f.app.emitMessage(delivery, "Ev-failed-intake-replay", {
      ackGate: {
        persisted: () => void replayOutcomes.push("persisted"),
        failed: () => void replayOutcomes.push("failed"),
      },
    });
    f.core.resumeSubmit();
    await Promise.all([first, replay]);
    assert.deepEqual(firstOutcomes, ["failed"]);
    assert.deepEqual(replayOutcomes, ["failed"]);
    assert.equal(f.core.turns.length, 1);
  } finally {
    f.core.resumeSubmit();
    await f.stop();
  }
});

test("an unknown user fails closed even when Slack lookup returns no record", async () => {
  const f = await fixture();
  try {
    await f.app.emitMessage({ channel: "DU", channel_type: "im", user: "UUNKNOWN", text: "hello", ts: "101.3" });
    assert.equal(f.core.turns.length, 0);
    assert.equal(
      f.core.ingests.flat().some((event) => event.text === "hello"),
      false,
    );
    assert.match(f.client.posts[0].text, /isn't fully internal/);
  } finally {
    await f.stop();
  }
});

test("an external principal is refused in a DM before core sees the text", async () => {
  const f = await fixture();
  try {
    await f.app.emitMessage({ channel: "DX", channel_type: "im", user: "UX", text: "exfiltrate this", ts: "102.1" });
    assert.equal(f.core.turns.length, 0);
    assert.equal(f.client.posts.length, 1);
    assert.match(f.client.posts[0].text, /isn't fully internal/);
    assert.equal(
      f.core.ingests.flat().some((event) => event.text === "exfiltrate this"),
      false,
    );
  } finally {
    await f.stop();
  }
});

test("a bot-authored mention can become a turn", async () => {
  const f = await fixture();
  try {
    f.client.usersById.set("B1", {
      id: "B1",
      team_id: "T1",
      is_bot: true,
      name: "peerbot",
      profile: { display_name: "Peer Bot" },
    });
    f.client.membersByChannel.set("C1", ["U1", "U2", "B1", "UBOT"]);
    await f.app.emitEvent("app_mention", {
      channel: "C1",
      channel_type: "channel",
      user: "B1",
      bot_id: "B-PEER",
      text: "<@UBOT> hello",
      ts: "102.2",
    });
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].actor.externalId, "B1");
    assert.equal(f.client.posts[0].text, "agent reply");
  } finally {
    await f.stop();
  }
});

test("a bot-authored mention without a user resolves its bot principal", async () => {
  const f = await fixture();
  try {
    f.client.usersById.set("B1", {
      id: "B1",
      team_id: "T1",
      is_bot: true,
      name: "peerbot",
      profile: { display_name: "Peer Bot" },
    });
    f.client.botsById.set("B-PEER", { id: "B-PEER", user_id: "B1", name: "Peer Bot" });
    f.client.membersByChannel.set("C1", ["U1", "U2", "B1", "UBOT"]);
    await f.app.emitEvent("app_mention", {
      channel: "C1",
      channel_type: "channel",
      bot_id: "B-PEER",
      text: "<@UBOT> hello",
      ts: "102.25",
    });
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].actor.externalId, "B1");
  } finally {
    await f.stop();
  }
});

test("a verified legacy bot without a user principal can become a turn", async () => {
  const f = await fixture();
  try {
    f.client.botsById.set("B-LEGACY", { id: "B-LEGACY", name: "Legacy Bot" });
    await f.app.emitEvent("app_mention", {
      channel: "C1",
      channel_type: "channel",
      bot_id: "B-LEGACY",
      text: "<@UBOT> hello",
      ts: "102.26",
    });
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].actor.externalId, "B-LEGACY");
  } finally {
    await f.stop();
  }
});

test("a bot-authored stop can abort a live run", async () => {
  const f = await fixture();
  try {
    f.client.usersById.set("B1", {
      id: "B1",
      team_id: "T1",
      is_bot: true,
      name: "peerbot",
      profile: { display_name: "Peer Bot" },
    });
    f.core.activeRun = "run-active";
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      subtype: "bot_message",
      user: "B1",
      bot_id: "B-PEER",
      text: "stop",
      ts: "102.3",
    });
    assert.deepEqual(f.core.abortedRuns, ["run-active"]);
    assert.equal(f.core.turns.length, 0);
    assert.equal(f.core.ackPicks.length, 0);
  } finally {
    await f.stop();
  }
});

test("a Slack Connect mention is refused ephemerally and never mirrored", async () => {
  const f = await fixture();
  try {
    f.core.activeRun = "run-active";
    const event = { channel: "CX", channel_type: "channel", user: "U1", text: "<@UBOT> stop", ts: "103.1" };
    await f.app.emitEvent("app_mention", event);
    assert.equal(f.core.turns.length, 0);
    assert.equal(f.core.abortedRuns.length, 0);
    assert.equal(f.core.ackPicks.length, 0);
    assert.equal(f.core.ingests.length, 0);
    assert.equal(f.client.posts.length, 0);
    assert.equal(f.client.ephemerals.length, 1);
    assert.match(f.client.ephemerals[0].text, /isn't fully internal/);
  } finally {
    await f.stop();
  }
});

test("an unreadable channel roster fails closed before core or mirror ingestion", async () => {
  const f = await fixture();
  try {
    f.client.membershipFailures.add("C1");
    await f.app.emitEvent("app_mention", {
      channel: "C1",
      channel_type: "channel",
      user: "U1",
      text: "<@UBOT> hello",
      ts: "103.2",
    });
    assert.equal(f.core.turns.length, 0);
    assert.equal(f.core.ingests.length, 0);
    assert.equal(f.client.ephemerals.length, 1);
  } finally {
    await f.stop();
  }
});

test("the admin external-participant toggle permits capability without hiding the guest audience", async () => {
  const f = await fixture({ externalParticipants: true });
  try {
    const event = { channel: "CX", channel_type: "channel", user: "U1", text: "<@UBOT> collaborate", ts: "103.3" };
    f.client.messagesByChannel.set("CX", [event]);
    await f.app.emitEvent("app_mention", event);
    assert.equal(f.core.turns.length, 1);
    assert.equal(
      f.core.turns[0].conversation.audience.some((a: any) => a.externalId === "UX" && a.isExternalGuest),
      true,
    );
    assert.equal(f.client.posts[0].text, "agent reply");
    assert.equal(
      f.core.ingests.flat().some((e: any) => e.ts === "103.3"),
      true,
    );
  } finally {
    await f.stop();
  }
});

test("a core boundary refusal stays requester-only in a channel", async () => {
  const f = await fixture({ externalParticipants: true });
  try {
    f.core.result = { status: "refused", reason: "conversation must be fully internal" };
    const event = { channel: "CX", channel_type: "channel", user: "U1", text: "<@UBOT> collaborate", ts: "103.4" };
    f.client.messagesByChannel.set("CX", [event]);
    await f.app.emitEvent("app_mention", event);
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.client.posts.length, 0);
    assert.equal(f.client.ephemerals.length, 1);
    assert.match(f.client.ephemerals[0].text, /fully internal/);
  } finally {
    await f.stop();
  }
});

test("an internal channel mention carries the complete audience and thread context", async () => {
  const f = await fixture();
  try {
    const event = { channel: "C1", channel_type: "channel", user: "U1", text: "<@UBOT> status?", ts: "104.1" };
    f.client.messagesByChannel.set("C1", [event]);
    await f.app.emitEvent("app_mention", event);
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].text, "status?");
    assert.equal(f.core.turns[0].conversation.threadRef, "ch:C1:104.1");
    assert.equal(f.core.turns[0].conversation.channelRef, "C1");
    assert.deepEqual(f.core.turns[0].conversation.audience.map((a: any) => a.externalId).sort(), ["U1", "U2"]);
    assert.equal(f.core.turns[0].deliveryTarget, "C1:104.1");
    assert.equal(f.client.posts[0].thread_ts, "104.1");
    assert.equal(
      f.core.ingests.flat().some((e: any) => e.ts === "104.1" && e.handled && e.mentionsSelf),
      true,
    );
  } finally {
    await f.stop();
  }
});

test("an unaddressed top-level channel message is mirrored but never becomes a turn", async () => {
  const f = await fixture();
  try {
    await f.app.emitMessage({
      channel: "C1",
      channel_type: "channel",
      user: "U2",
      text: "ambient update",
      ts: "104.2",
    });
    assert.equal(f.core.turns.length, 0);
    assert.equal(f.client.posts.length, 0);
    assert.equal(
      f.core.ingests.flat().some((e: any) => e.ts === "104.2" && e.text === "ambient update" && !e.handled),
      true,
    );
  } finally {
    await f.stop();
  }
});

test("a group-DM thread-follow runs unprompted yet attests its author's liveness", async () => {
  const f = await fixture();
  try {
    f.client.channelsById.set("G1", { id: "G1", name: "", is_member: true, is_private: true, is_mpim: true });
    f.client.membersByChannel.set("G1", ["U1", "U2", "UBOT"]);
    f.client.messagesByChannel.set("G1", [
      { channel: "G1", user: "U1", text: "kick off", ts: "300.1" },
      { channel: "G1", user: "UBOT", text: "on it", ts: "300.2", thread_ts: "300.1" },
    ]);
    await f.app.emitMessage({
      channel: "G1",
      channel_type: "mpim",
      user: "U2",
      text: "also update the skill",
      ts: "300.3",
      thread_ts: "300.1",
    });
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].unprompted, true);
    assert.equal(f.core.turns[0].entryTs, "300.3");
    assert.equal(f.core.turns[0].liveActor, true, "a member's own verbatim follow-up is a live act");
    assert.equal(f.core.turns[0].conversation.kind, "group");
    assert.equal(f.core.turns[0].conversation.threadRef, "grp:G1:300.1");
    assert.equal(f.core.turns[0].verifiedSlack, undefined);
  } finally {
    await f.stop();
  }
});

test("a message from an unseen group DM resyncs the directory so it becomes addressable", async () => {
  const f = await fixture();
  try {
    f.client.channelsById.set("G9", { id: "G9", name: "", is_member: true, is_private: true, is_mpim: true });
    f.client.membersByChannel.set("G9", ["U1", "U2", "UBOT"]);
    const listedBefore = f.client.groupListings;
    await f.app.emitMessage({ channel: "G9", channel_type: "mpim", user: "U1", text: "hi", ts: "400.1" });
    await waitFor(() => f.client.groupListings > listedBefore);
    await waitFor(() => (f.core.directories.at(-1)?.groupMembers ?? []).some((g: any) => g.groupId === "G9"));
    assert.deepEqual(
      f.core.directories
        .at(-1)
        .groupMembers.filter((g: any) => g.groupId === "G9")
        .map((g: any) => g.principalId)
        .sort(),
      ["U1", "U2"],
      "the new group's internal roster reaches core, bot excluded",
    );

    const listedAfter = f.client.groupListings;
    await f.app.emitMessage({ channel: "G9", channel_type: "mpim", user: "U1", text: "again", ts: "400.2" });
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(f.client.groupListings, listedAfter, "a group DM already seen does not resync on every message");
  } finally {
    await f.stop();
  }
});

test("a failed group listing pushes its fallback rows under the OLD stamp, never a fresh one", async () => {
  const f = await fixture();
  try {
    f.client.channelsById.set("G7", { id: "G7", name: "", is_member: true, is_private: true, is_mpim: true });
    f.client.membersByChannel.set("G7", ["U1", "U2", "UBOT"]);
    await f.app.emitMessage({ channel: "G7", channel_type: "mpim", user: "U1", text: "hi", ts: "402.1" });
    await waitFor(() =>
      f.core.directories.some((d: any) => (d.groupMembers ?? []).some((g: any) => g.groupId === "G7")),
    );
    const goodStamp = f.core.directories.findLast((d: any) => d.groupsSyncedAt !== undefined).groupsSyncedAt;
    assert.ok(goodStamp > 0);

    f.client.failGroupListing = true;
    f.client.channelsById.set("G6", { id: "G6", name: "", is_member: true, is_private: true, is_mpim: true });
    await f.app.emitMessage({ channel: "G6", channel_type: "mpim", user: "U1", text: "hi", ts: "402.2" });
    await waitFor(() => f.core.directories.findLast((d: any) => d.channels)?.channelsSyncedAt > goodStamp);
    const last = f.core.directories.findLast((d: any) => d.channels);
    assert.equal(
      last.groupMembers,
      undefined,
      "a failed group listing must omit the groups section, never ship rows under a fresh stamp",
    );
  } finally {
    await f.stop();
  }
});

test("a failed group member read marks only that roster unknown", async () => {
  const f = await fixture();
  try {
    f.client.channelsById.set("G5", { id: "G5", name: "", is_member: true, is_private: true, is_mpim: true });
    f.client.membersByChannel.set("G5", ["U1", "U2", "UBOT"]);
    await f.app.emitMessage({ channel: "G5", channel_type: "mpim", user: "U1", text: "hi", ts: "403.1" });
    await waitFor(() =>
      f.core.directories.some((d: any) => (d.groupMembers ?? []).some((g: any) => g.groupId === "G5")),
    );
    const good = f.core.directories.findLast((d: any) => d.groupsSyncedAt !== undefined);
    f.client.membershipFailures.add("G5");
    const pushes = f.core.directories.length;
    await f.app.emitMessage({ channel: "G5", channel_type: "mpim", subtype: "group_join", ts: "403.2" });
    await waitFor(() => f.core.directories.length > pushes);
    const last = f.core.directories.at(-1);
    assert.ok(last.groupsSyncedAt > good.groupsSyncedAt);
    assert.ok(last.groupIds.includes("G5"));
    assert.ok(!last.groupRosterIds.includes("G5"));
    assert.equal(last.groupMembers.filter((member: any) => member.groupId === "G5").length, 0);
  } finally {
    await f.stop();
  }
});

test("all listed group DMs reach the directory past the legacy private-channel cap", async () => {
  const f = await fixture();
  try {
    for (let i = 0; i < 51; i++) {
      const id = `G${i}`;
      f.client.channelsById.set(id, { id, name: "", is_member: true, is_private: true, is_mpim: true });
      f.client.membersByChannel.set(id, ["U1", "U2", "UBOT"]);
    }
    const pushes = f.core.directories.length;
    await f.app.emitMessage({ channel: "G0", channel_type: "mpim", subtype: "group_join", ts: "403.3" });
    await waitFor(() => f.core.directories.length > pushes);
    assert.equal(new Set(f.core.directories.at(-1).groupMembers.map((member: any) => member.groupId)).size, 51);
  } finally {
    await f.stop();
  }
});

test("a group DM whose listing fails is retried at most once, never once per message", async () => {
  const f = await fixture();
  try {
    f.client.channelsById.set("G8", { id: "G8", name: "", is_member: true, is_private: true, is_mpim: true });
    f.client.membersByChannel.set("G8", ["U1", "U2", "UBOT"]);
    f.client.failGroupListing = true;
    const listedBefore = f.client.groupListings;
    for (const ts of ["401.1", "401.2", "401.3"]) {
      await f.app.emitMessage({ channel: "G8", channel_type: "mpim", user: "U1", text: "hi", ts });
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(
      f.client.groupListings - listedBefore,
      1,
      "a failing listing must not make every message trigger another full sync",
    );
  } finally {
    await f.stop();
  }
});

test("a peer bot's thread reply dispatches without attesting liveness", async () => {
  const f = await fixture();
  try {
    f.client.usersById.set("UB2", { id: "UB2", team_id: "T1", name: "copilot", is_bot: true });
    f.client.membersByChannel.set("C1", ["U1", "U2", "UB2", "UBOT"]);
    f.client.messagesByChannel.set("C1", [
      { channel: "C1", user: "U1", text: "kick off", ts: "301.1" },
      { channel: "C1", user: "UBOT", text: "on it", ts: "301.2", thread_ts: "301.1" },
    ]);
    await f.app.emitMessage({
      channel: "C1",
      channel_type: "channel",
      subtype: "bot_message",
      user: "UB2",
      text: "automated status: done",
      ts: "301.3",
      thread_ts: "301.1",
    });
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].unprompted, true);
    assert.equal(f.core.turns[0].entryTs, "301.3");
    assert.equal(f.core.turns[0].liveActor, undefined, "a bot author is automation, never a live act");
  } finally {
    await f.stop();
  }
});

test("an untrusted inbound file URL is never fetched and reaches core only as a missing-file note", async (t) => {
  const f = await fixture();
  const fetchMock = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("untrusted URL was fetched");
  });
  try {
    await f.app.emitMessage({
      channel: "D1",
      channel_type: "im",
      user: "U1",
      text: "inspect this",
      ts: "104.3",
      files: [{ id: "F1", name: "payload.txt", url_private_download: "https://evil.example/payload.txt" }],
    });
    assert.equal(fetchMock.mock.callCount(), 0);
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.core.turns[0].attachments, undefined);
    assert.match(f.core.turns[0].inboundNotes[0], /payload\.txt/);
  } finally {
    await f.stop();
  }
});

test("message edits and deletes update the mirror without creating turns", async () => {
  const f = await fixture();
  try {
    await f.app.emitMessage({
      channel: "C1",
      channel_type: "channel",
      subtype: "message_changed",
      message: { channel_type: "channel", user: "U1", text: "edited", ts: "105.1" },
      ts: "105.2",
    });
    await f.app.emitMessage({
      channel: "C1",
      channel_type: "channel",
      subtype: "message_deleted",
      deleted_ts: "105.1",
      ts: "105.3",
    });
    assert.equal(f.core.turns.length, 0);
    const events = f.core.ingests.flat();
    assert.equal(
      events.some((e: any) => e.ts === "105.1" && e.text === "edited" && typeof e.editedAt === "number"),
      true,
    );
    assert.equal(
      events.some((e: any) => e.ts === "105.1" && e.deleted === true),
      true,
    );
  } finally {
    await f.stop();
  }
});

test("raw core failures never leak through Slack", async () => {
  const f = await fixture();
  try {
    f.core.submitError = new Error("password=super-secret postgres://internal-db/run/abc");
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "hello", ts: "106.1" });
    assert.equal(f.core.turns.length, 1);
    assert.equal(f.client.posts.length, 1);
    assert.match(f.client.posts[0].text, /couldn't reach the agent core/);
    assert.doesNotMatch(f.client.posts[0].text, /super-secret|postgres|run\/abc/);
  } finally {
    await f.stop();
  }
});

test("stop aborts the active run without enqueuing a second turn", async () => {
  const f = await fixture();
  try {
    f.core.activeRun = "run-active";
    await f.app.emitMessage({ channel: "D1", channel_type: "im", user: "U1", text: "stop", ts: "107.1" });
    assert.deepEqual(f.core.abortedRuns, ["run-active"]);
    assert.equal(f.core.turns.length, 0);
    assert.equal(f.client.posts.length, 0);
  } finally {
    await f.stop();
  }
});
