import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyChain, type AuditRecord } from "../lib/verifyAudit";

async function main(): Promise<void> {
  const here = dirname(fileURLToPath(import.meta.url));
  const data = JSON.parse(readFileSync(join(here, "../data/case001.json"), "utf8"));
  const records: AuditRecord[] = data.audit;

  if (!records?.length) {
    console.error("DATA GATE FAILED: audit array is empty or missing");
    process.exit(1);
  }

  // verifyChain runs exactly what the browser runs: per record it checks seq,
  // prev_hash linkage, AND recomputes the content hash against the stored hash.
  // No second pass is needed — a duplicate loop would catch nothing new.
  const res = await verifyChain(records);
  if (!res.ok) {
    console.error(`DATA GATE FAILED: chain not ok — broken at seq ${res.brokenSeq}: ${res.reason}`);
    process.exit(1);
  }
  console.log(`data gate OK — ${records.length} records verify against the TS verifier`);
}

main().catch((err) => {
  console.error("DATA GATE FAILED: unexpected error:", err);
  process.exit(1);
});
