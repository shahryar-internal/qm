import type { JsonWebKey } from "node:crypto";
import type { DurableMap } from "../persistence/durable-map.ts";
import type { BackgroundJobAuthoritySigner } from "./types.ts";
import { identifier } from "./validation.ts";

export interface BackgroundJobAuthorityStageRecord {
  contract: 1;
  activeKid: string;
  nextKid?: string;
  nextPublishedAt?: number;
  previousKid?: string;
  previousRetireAt?: number;
}

interface AuthorityGeneration {
  kid: string;
  signer: BackgroundJobAuthoritySigner;
}

export function createStagedBackgroundJobAuthority(options: {
  backing: DurableMap<BackgroundJobAuthorityStageRecord>;
  recordId: string;
  durable: boolean;
  active: AuthorityGeneration;
  next?: AuthorityGeneration;
  cacheOverlapMs?: number;
  tokenLifetimeMs?: number;
  now?: () => number;
}): BackgroundJobAuthoritySigner {
  const now = options.now ?? Date.now;
  const overlap = options.cacheOverlapMs ?? 600_000;
  const lifetime = options.tokenLifetimeMs ?? 300_000;
  const recordId = identifier(options.recordId, "authority stage id");
  const activeKid = identifier(options.active.kid, "active token kid");
  const nextKid = options.next ? identifier(options.next.kid, "next token kid") : undefined;
  if (
    !options.durable ||
    typeof options.backing.update !== "function" ||
    typeof options.backing.insertIfAbsent !== "function"
  ) {
    throw new TypeError("background job authority stage store is unavailable");
  }
  if (
    !Number.isSafeInteger(overlap) ||
    overlap < 60_000 ||
    overlap > 24 * 60 * 60_000 ||
    !Number.isSafeInteger(lifetime) ||
    lifetime < 1_000 ||
    lifetime > 300_000 ||
    nextKid === activeKid
  ) {
    throw new TypeError("background job authority stage configuration is invalid");
  }
  let stage: BackgroundJobAuthorityStageRecord | undefined;
  const generations = new Map<string, AuthorityGeneration>([
    [activeKid, options.active],
    ...(options.next ? ([[nextKid!, options.next]] as Array<[string, AuthorityGeneration]>) : []),
  ]);
  const validateRecord = (value: BackgroundJobAuthorityStageRecord): BackgroundJobAuthorityStageRecord => {
    if (
      !value ||
      value.contract !== 1 ||
      !generations.has(value.activeKid) ||
      (value.nextKid !== undefined &&
        (!generations.has(value.nextKid) || !Number.isSafeInteger(value.nextPublishedAt))) ||
      (value.previousKid !== undefined &&
        (!generations.has(value.previousKid) || !Number.isSafeInteger(value.previousRetireAt)))
    ) {
      throw new Error("background job authority stage is invalid");
    }
    return value;
  };
  const refresh = async (): Promise<void> => {
    await Promise.all([...generations.values()].map((generation) => generation.signer.ready()));
    await options.backing.insertIfAbsent!(recordId, { contract: 1, activeKid });
    const at = now();
    const updated = await options.backing.update!(recordId, (current) => {
      const valid = validateRecord(current);
      let next = valid;
      if (nextKid && valid.activeKid === activeKid && valid.nextKid === undefined) {
        next = { ...valid, nextKid, nextPublishedAt: at };
      }
      if (next.nextKid && next.nextPublishedAt !== undefined && at >= next.nextPublishedAt + overlap) {
        next = {
          contract: 1,
          activeKid: next.nextKid,
          previousKid: next.activeKid,
          previousRetireAt: at + lifetime + overlap,
        };
      }
      if (next.previousKid && next.previousRetireAt !== undefined && at >= next.previousRetireAt) {
        next = { contract: 1, activeKid: next.activeKid };
      }
      return next;
    });
    if (!updated) throw new Error("background job authority stage disappeared");
    stage = validateRecord(updated);
  };
  const ready = (): Promise<void> => refresh();
  const signer = async (): Promise<BackgroundJobAuthoritySigner> => {
    await ready();
    const generation = stage ? generations.get(stage.activeKid) : undefined;
    if (!generation) throw new Error("background job active authority is unavailable");
    return generation.signer;
  };
  const keys = (): readonly Readonly<JsonWebKey>[] => {
    if (!stage) return [];
    const kids = [stage.activeKid, stage.nextKid, stage.previousKid].filter(
      (kid, index, all): kid is string => !!kid && all.indexOf(kid) === index,
    );
    return Object.freeze(
      kids.flatMap((kid) => {
        const generation = generations.get(kid);
        return generation ? generation.signer.jwks().keys.filter((jwk) => jwk.kid === kid) : [];
      }),
    );
  };
  return Object.freeze({
    ready,
    signPrepare: async (...args: Parameters<BackgroundJobAuthoritySigner["signPrepare"]>) =>
      (await signer()).signPrepare(...args),
    signStart: async (...args: Parameters<BackgroundJobAuthoritySigner["signStart"]>) =>
      (await signer()).signStart(...args),
    signStatus: async (...args: Parameters<BackgroundJobAuthoritySigner["signStatus"]>) =>
      (await signer()).signStatus(...args),
    signCancel: async (...args: Parameters<BackgroundJobAuthoritySigner["signCancel"]>) =>
      (await signer()).signCancel(...args),
    jwks: () => Object.freeze({ keys: keys() }),
  });
}
