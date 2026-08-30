import { canonicalJson } from "../cron/schedule-authority.ts";
import type {
  BackgroundJobAdmission,
  BackgroundJobAuthoritySigner,
  BackgroundJobClient,
  BackgroundJobDefinition,
  BackgroundJobReceipt,
} from "./types.ts";
import { parseStrictHttpsUrl, validateDefinition } from "./validation.ts";

const MAX_RESPONSE_BYTES = 256 * 1024;

export interface BackgroundJobResponseParsers<TStatus, TCancellation> {
  admission(value: unknown): Readonly<BackgroundJobAdmission>;
  status(value: unknown, origin: string): Readonly<TStatus>;
  cancellation(value: unknown): Readonly<TCancellation>;
  statusRunId(value: Readonly<TStatus>): string;
  cancellationRunId(value: Readonly<TCancellation>): string;
}

interface FixedClientConfig<TStatus, TCancellation> {
  origin: string;
  definition: Readonly<BackgroundJobDefinition>;
  parsers: Readonly<BackgroundJobResponseParsers<TStatus, TCancellation>>;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

async function responseBytes(response: Response): Promise<Uint8Array> {
  if (!response.body) throw new Error("background job server returned no response body");
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) {
    throw new Error("background job server response is invalid");
  }
  if (response.headers.has("content-encoding")) throw new Error("background job server response is invalid");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("background job server response is too large");
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  if (declared !== null && Number(declared) !== size) throw new Error("background job server response is invalid");
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
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
  validateDefinition(config.definition);
  const origin = parseStrictHttpsUrl(config.origin, "background job origin", true).origin;
  const timeoutMs = config.timeoutMs ?? 5_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new TypeError("background job timeout is invalid");
  }
  const fetcher = config.fetch ?? fetch;
  const post = async (path: string, maxBytes: number, body: Uint8Array, token: string): Promise<unknown> => {
    if (!(body instanceof Uint8Array) || body.byteLength < 2 || body.byteLength > maxBytes) {
      throw new TypeError("background job request body is invalid");
    }
    const expectedUrl = `${origin}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
      response = await fetcher(expectedUrl, {
        method: "POST",
        redirect: "error",
        signal: controller.signal,
        headers: {
          "content-type": "application/json",
          "content-length": String(body.byteLength),
          [config.definition.authorityHeader]: token,
        },
        body: Buffer.from(body),
      });
    } catch {
      throw new Error("background job request failed");
    } finally {
      clearTimeout(timer);
    }
    if (response.url && response.url !== expectedUrl) throw new Error("background job response origin is invalid");
    if (response.status < 200 || response.status >= 300)
      throw new Error(`background job server rejected the request (${response.status})`);
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get("content-type") ?? "")) {
      throw new Error("background job server response is invalid");
    }
    return decode(await responseBytes(response));
  };
  const controlBody = (receipt: Readonly<BackgroundJobReceipt>) =>
    Buffer.from(canonicalJson({ authorityId: receipt.authorityId, runId: receipt.runId }), "utf8");
  return Object.freeze({
    async start(body: Uint8Array, threadTs: string, idempotencyKey: string) {
      const token = await signer.signStart(body, threadTs, idempotencyKey);
      return config.parsers.admission(
        await post(config.definition.start.path, config.definition.start.maxRequestBytes, body, token),
      );
    },
    async status(receipt: Readonly<BackgroundJobReceipt>) {
      const body = controlBody(receipt);
      const token = await signer.signStatus(body, receipt.threadTs);
      const status = config.parsers.status(
        await post(config.definition.status.path, config.definition.status.maxRequestBytes, body, token),
        origin,
      );
      if (config.parsers.statusRunId(status) !== receipt.runId)
        throw new Error("background job response binding is invalid");
      return status;
    },
    async cancel(receipt: Readonly<BackgroundJobReceipt>) {
      const body = controlBody(receipt);
      const token = await signer.signCancel(body, receipt.threadTs);
      const cancellation = config.parsers.cancellation(
        await post(config.definition.cancel.path, config.definition.cancel.maxRequestBytes, body, token),
      );
      if (config.parsers.cancellationRunId(cancellation) !== receipt.runId)
        throw new Error("background job response binding is invalid");
      return cancellation;
    },
  });
}
