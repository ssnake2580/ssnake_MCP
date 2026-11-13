import { describe, it, expect } from "vitest";
import data from "../../data/case001.json";
import { verifyChain, recordHash, type AuditRecord } from "../verifyAudit";

const records = data.audit as unknown as AuditRecord[];

describe("audit chain parity with the Python engine", () => {
  it("every record's content hashes to its stored hash", async () => {
    for (const r of records) expect(await recordHash(r)).toBe(r.hash);
  });
  it("the pristine chain verifies", async () => {
    expect(await verifyChain(records)).toEqual({ ok: true });
  });
});

describe("tamper detection (mirrors verify(): seq, prev_hash, content)", () => {
  it("mutating stdout_sha256 breaks the chain at that seq", async () => {
    const t = structuredClone(records);
    t[2].stdout_sha256 = "deadbeef" + t[2].stdout_sha256.slice(8);
    const res = await verifyChain(t);
    expect(res.ok).toBe(false);
    expect(res.brokenSeq).toBe(2);
    expect(res.reason).toMatch(/tampered/);
  });
  it("flipping exit_code breaks the chain at that seq", async () => {
    const t = structuredClone(records);
    t[0].exit_code = 1;
    expect(await verifyChain(t)).toMatchObject({ ok: false, brokenSeq: 0 });
  });
  it("reordering records breaks the sequence", async () => {
    const t = structuredClone(records);
    [t[1], t[2]] = [t[2], t[1]];
    expect((await verifyChain(t)).ok).toBe(false);
  });
  it("corrupting prev_hash breaks the chain at that record", async () => {
    const t = structuredClone(records);
    t[3] = { ...t[3], prev_hash: "dead" + t[3].prev_hash.slice(4) };
    const res = await verifyChain(t);
    expect(res).toMatchObject({ ok: false, brokenSeq: 3, reason: expect.stringMatching(/chain broken/) });
  });
});
