import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { Readable } from "node:stream";
import { canonicalJson } from "../cron/schedule-authority.ts";
import { isPublicNetworkIp } from "../util/network.ts";
import type {
  BackgroundJobAdmission,
  BackgroundJobAuthoritySigner,
  BackgroundJobClient,
  BackgroundJobDefinition,
  BackgroundJobReceipt,
} from "./types.ts";
import { parsePublicHttpsUrl, validateDefinition } from "./validation.ts";

const MAX_RESPONSE_BYTES = 256 * 1024;

export interface BackgroundJobResponseParsers<TStatus, TCancellation> {
  admission(value: unknown): Readonly<BackgroundJobAdmission>;
  status(value: unknown, origin: string): Readonly<TStatus>;
  cancellation(value: unknown): Readonly<TCancellation>;
  statusRunId(value: Readonly<TStatus>): string;
  cancellationRunId(value: Readonly<TCancellation>): string;
}

export interface BackgroundJobHttpResponse {
  status: number;
  url: string;
  headers: Readonly<{ get(name: string): string | null }>;
  body: ReadableStream<Uint8Array> | null;
  cancel(): Promise<void>;
}

export type BackgroundJobResolveHost = (hostname: string) => Promise<readonly string[]>;

export type BackgroundJobPinnedRequest = (
  url: string,
  init: Readonly<{
    method: "POST";
    headers: Readonly<Record<string, string>>;
    body: Uint8Array;
    signal: AbortSignal;
    resolvedAddress: string;
    resolvedAddresses: readonly string[];
    servername: string;
    redirect: "error";
    proxy: "disabled";
  }>,
) => Promise<BackgroundJobHttpResponse>;

interface FixedClientConfig<TStatus, TCancellation> {
  origin: string;
  definition: Readonly<BackgroundJobDefinition>;
  parsers: Readonly<BackgroundJobResponseParsers<TStatus, TCancellation>>;
  timeoutMs?: number;
  resolveHost?: BackgroundJobResolveHost;
  request?: BackgroundJobPinnedRequest;
}

async function cancelResponse(response: BackgroundJobHttpResponse): Promise<void> {
  await response.cancel().catch(() => undefined);
}

async function responseBytes(response: BackgroundJobHttpResponse, signal: AbortSignal): Promise<Uint8Array> {
  if (!response.body) {
    await cancelResponse(response);
    throw new Error("background job server returned no response body");
  }
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) {
    await cancelResponse(response);
    throw new Error("background job server response is invalid");
  }
  if (response.headers.get("content-encoding") !== null) {
    await cancelResponse(response);
    throw new Error("background job server response is invalid");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const aborted = new Promise<never>((_resolve, reject) => {
    const fail = () => reject(new Error("background job request failed"));
    if (signal.aborted) fail();
    else signal.addEventListener("abort", fail, { once: true });
  });
  try {
    for (;;) {
      const next = await Promise.race([reader.read(), aborted]);
      if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await cancelResponse(response);
        throw new Error("background job server response is too large");
      }
      chunks.push(next.value);
    }
  } catch (error) {
    await cancelResponse(response);
    throw error;
  } finally {
    reader.releaseLock();
  }
  if (declared !== null && Number(declared) !== size) {
    await cancelResponse(response);
    throw new Error("background job server response is invalid");
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function createPinnedBackgroundJobLookup(address: string, expectedHostname: string): LookupFunction {
  const family = isIP(address);
  if (family === 0 || !isPublicNetworkIp(address)) throw new Error("background job request requires a public address");
  return (hostname, options, callback) => {
    if (hostname !== expectedHostname) {
      callback(new Error("background job request hostname changed"), undefined as never);
      return;
    }
    if (options.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}

const realResolveHost: BackgroundJobResolveHost = async (hostname) =>
  (await lookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address);

const realPinnedRequest: BackgroundJobPinnedRequest = (url, init) =>
  new Promise((resolve, reject) => {
    const target = new URL(url);
    let pinnedLookup: LookupFunction;
    try {
      pinnedLookup = createPinnedBackgroundJobLookup(init.resolvedAddress, init.servername);
    } catch (error) {
      reject(error);
      return;
    }
    const request = httpsRequest(
      target,
      {
        agent: false,
        method: init.method,
        headers: init.headers,
        servername: init.servername,
        family: isIP(init.resolvedAddress),
        lookup: pinnedLookup,
      },
      (response) => {
        resolve({
          status: response.statusCode ?? 0,
          url: target.toString(),
          headers: Object.freeze({
            get(name: string) {
              const value = response.headers[name.toLowerCase()];
              return Array.isArray(value) ? value.join(", ") : (value ?? null);
            },
          }),
          body: Readable.toWeb(response) as ReadableStream<Uint8Array>,
          cancel: async () => {
            response.destroy();
          },
        });
      },
    );
    const abort = () => request.destroy(new Error("background job request failed"));
    if (init.signal.aborted) abort();
    else init.signal.addEventListener("abort", abort, { once: true });
    request.on("error", reject);
    request.end(Buffer.from(init.body));
  });

async function resolvePublicAddresses(
  hostname: string,
  resolveHost: BackgroundJobResolveHost,
  signal: AbortSignal,
): Promise<string[]> {
  let resolved: readonly string[];
  try {
    resolved = await Promise.race([
      resolveHost(hostname),
      new Promise<never>((_resolve, reject) => {
        const fail = () => reject(new Error("background job hostname resolution failed"));
        if (signal.aborted) fail();
        else signal.addEventListener("abort", fail, { once: true });
      }),
    ]);
  } catch {
    throw new Error("background job hostname resolution failed");
  }
  const addresses = [...new Set(resolved)].sort((left, right) => isIP(left) - isIP(right) || left.localeCompare(right));
  if (
    addresses.length < 1 ||
    addresses.length > 16 ||
    addresses.some((address) => isIP(address) === 0 || !isPublicNetworkIp(address))
  ) {
    throw new Error("background job hostname did not resolve only to public addresses");
  }
  return addresses;
}

function decode(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("background job server response is invalid");
  }
}

export function createFixedBackgroundJobClient<TStatus, TCancellation>(
  config: Readonly<FixedClientConfig<TStatus, TCancellation>>,
  signer: BackgroundJobAuthoritySigner,
): BackgroundJobClient<TStatus, TCancellation> {
  const definition = Object.freeze({
    ...config.definition,
    ...(config.definition.prepare ? { prepare: Object.freeze({ ...config.definition.prepare }) } : {}),
    start: Object.freeze({ ...config.definition.start }),
    status: Object.freeze({ ...config.definition.status }),
    cancel: Object.freeze({ ...config.definition.cancel }),
  });
  validateDefinition(definition);
  const origin = parsePublicHttpsUrl(config.origin, "background job origin", true).origin;
  const timeoutMs = config.timeoutMs ?? 5_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new TypeError("background job timeout is invalid");
  }
  const resolveHost = config.resolveHost ?? realResolveHost;
  const request = config.request ?? realPinnedRequest;
  const post = async (path: string, maxBytes: number, body: Uint8Array, token: string): Promise<unknown> => {
    if (!(body instanceof Uint8Array) || body.byteLength < 2 || body.byteLength > maxBytes) {
      throw new TypeError("background job request body is invalid");
    }
    const expectedUrl = `${origin}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const target = new URL(expectedUrl);
      const addresses = await resolvePublicAddresses(target.hostname, resolveHost, controller.signal);
      let response: BackgroundJobHttpResponse;
      try {
        response = await request(expectedUrl, {
          method: "POST",
          redirect: "error",
          proxy: "disabled",
          signal: controller.signal,
          resolvedAddress: addresses[0]!,
          resolvedAddresses: Object.freeze(addresses),
          servername: target.hostname,
          headers: {
            "content-type": "application/json",
            "content-length": String(body.byteLength),
            [definition.authorityHeader]: token,
          },
          body: Uint8Array.from(body),
        });
      } catch {
        throw new Error("background job request failed");
      }
      if (response.url !== expectedUrl) {
        await cancelResponse(response);
        throw new Error("background job response origin is invalid");
      }
      if (response.status < 200 || response.status >= 300) {
        await cancelResponse(response);
        throw new Error(`background job server rejected the request (${response.status})`);
      }
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get("content-type") ?? "")) {
        await cancelResponse(response);
        throw new Error("background job server response is invalid");
      }
      return decode(await responseBytes(response, controller.signal));
    } finally {
      clearTimeout(timer);
    }
  };
  const controlBody = (receipt: Readonly<BackgroundJobReceipt>) =>
    Buffer.from(canonicalJson({ authorityId: receipt.authorityId, runId: receipt.runId }), "utf8");
  return Object.freeze({
    async start(
      body: Parameters<BackgroundJobClient<TStatus, TCancellation>["start"]>[0],
      grant: Parameters<BackgroundJobClient<TStatus, TCancellation>["start"]>[1],
      idempotencyKey: string,
      authorizedAt: number,
    ) {
      const exactBody = Uint8Array.from(body);
      const token = await signer.signStart(exactBody, grant, idempotencyKey, authorizedAt);
      return config.parsers.admission(
        await post(definition.start.path, definition.start.maxRequestBytes, exactBody, token),
      );
    },
    async status(receipt: Readonly<BackgroundJobReceipt>) {
      const body = controlBody(receipt);
      const token = await signer.signStatus(body, receipt);
      const status = config.parsers.status(
        await post(definition.status.path, definition.status.maxRequestBytes, body, token),
        origin,
      );
      if (config.parsers.statusRunId(status) !== receipt.runId)
        throw new Error("background job response binding is invalid");
      return status;
    },
    async cancel(
      receipt: Parameters<BackgroundJobClient<TStatus, TCancellation>["cancel"]>[0],
      grant: Parameters<BackgroundJobClient<TStatus, TCancellation>["cancel"]>[1],
      authorizedAt: number,
    ) {
      const body = controlBody(receipt);
      const token = await signer.signCancel(body, receipt, grant, authorizedAt);
      const cancellation = config.parsers.cancellation(
        await post(definition.cancel.path, definition.cancel.maxRequestBytes, body, token),
      );
      if (config.parsers.cancellationRunId(cancellation) !== receipt.runId)
        throw new Error("background job response binding is invalid");
      return cancellation;
    },
  });
}
