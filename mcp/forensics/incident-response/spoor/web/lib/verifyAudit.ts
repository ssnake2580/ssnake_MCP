import { canonicalize, type Json } from "./canonicalize";
import { sha256Hex } from "./sha256";

export const GENESIS = "0".repeat(64);
const CONTENT_FIELDS = ["seq", "ts", "tool", "args", "exit_code", "stdout_sha256", "prev_hash"] as const;

export interface AuditRecord {
  seq: number;
  ts: string;
  tool: string;
  args: Json;
  exit_code: number;
  stdout_sha256: string;
  prev_hash: string;
  hash: string;
}

export interface VerifyResult {
  ok: boolean;
  brokenSeq?: number;
  reason?: string;
}

/** The single source of truth for "is the record at array index `i` shown broken?":
 *  once verification fails at `brokenSeq`, that record and everything after it is broken. */
export const isBrokenAt = (brokenSeq: number | undefined, i: number): boolean =>
  brokenSeq !== undefined && i >= brokenSeq;

/** SHA-256 over the canonical content fields (everything but `hash`). */
export async function recordHash(rec: AuditRecord): Promise<string> {
  const content: { [k: string]: Json } = {};
  for (const k of CONTENT_FIELDS) content[k] = rec[k] as Json;
  return sha256Hex(canonicalize(content));
}

/** Recompute the chain end to end; report the first break. Mirrors AuditLog.verify(). */
export async function verifyChain(records: AuditRecord[]): Promise<VerifyResult> {
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.seq !== i)
      return { ok: false, brokenSeq: i, reason: "sequence broken: record missing, duplicated, or reordered" };
    if (r.prev_hash !== prev)
      return { ok: false, brokenSeq: i, reason: "chain broken: prev_hash does not match the previous record" };
    if ((await recordHash(r)) !== r.hash)
      return { ok: false, brokenSeq: i, reason: "record tampered: stored hash does not match content" };
    prev = r.hash;
  }
  return { ok: true };
}
