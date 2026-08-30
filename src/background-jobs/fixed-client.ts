import { canonicalJson } from "../cron/schedule-authority.ts";
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

interface FixedClientConfig<TStatus, TCancellation> {
  origin: string;
  definition: Readonly<BackgroundJobDefinition>;
  parsers: Readonly<BackgroundJobResponseParsers<TStatus, TCancellation>>;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

async function responseBytes(response: Response, signal: AbortSignal): Promise<Uint8Array> {
  if (!response.body) throw new Error("background job server returned no response body");
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) {
    throw new Error("background job server response is invalid");
  }
  if (response.headers.has("content-encoding")) throw new Error("background job server response is invalid");
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
        await reader.cancel();
        throw new Error("background job server response is too large");
      }
      chunks.push(next.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
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
  const fetcher = config.fetch ?? fetch;
  const post = async (path: string, maxBytes: number, body: Uint8Array, token: string): Promise<unknown> => {
    if (!(body instanceof Uint8Array) || body.byteLength < 2 || body.byteLength > maxBytes) {
      throw new TypeError("background job request body is invalid");
    }
    const expectedUrl = `${origin}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      let response: Response;
      try {
        response = await fetcher(expectedUrl, {
          method: "POST",
          redirect: "error",
          signal: controller.signal,
          headers: {
            "content-type": "application/json",
            "content-length": String(body.byteLength),
            [definition.authorityHeader]: token,
          },
          body: Buffer.from(body),
        });
      } catch {
        throw new Error("background job request failed");
      }
      if (response.url && response.url !== expectedUrl) throw new Error("background job response origin is invalid");
      if (response.status < 200 || response.status >= 300)
        throw new Error(`background job server rejected the request (${response.status})`);
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get("content-type") ?? "")) {
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
    async start(body: Uint8Array, slack: Readonly<{ messageTs: string; threadTs: string }>, idempotencyKey: string) {
      const exactBody = Uint8Array.from(body);
      const token = await signer.signStart(exactBody, slack, idempotencyKey);
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
    async cancel(receipt: Readonly<BackgroundJobReceipt>) {
      const body = controlBody(receipt);
      const token = await signer.signCancel(body, receipt);
      const cancellation = config.parsers.cancellation(
        await post(definition.cancel.path, definition.cancel.maxRequestBytes, body, token),
      );
      if (config.parsers.cancellationRunId(cancellation) !== receipt.runId)
        throw new Error("background job response binding is invalid");
      return cancellation;
    },
  });
}
