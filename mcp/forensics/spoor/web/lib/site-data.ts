import raw from "@/data/case001.json";
import type { AuditRecord } from "@/lib/verifyAudit";

export interface Finding {
  claim: string;
  status: "confirmed" | "inferred";
  tool_call_id: string | null;
  evidence_excerpt: string | null;
}
export interface Ioc { type: string; value: string; tool_call_id: string | null }
/** A scored accuracy item — the engine's gradeable finding shape (matches scorer output). */
export interface ScoredFinding { category: string; value: string; status: "confirmed" | "inferred"; tool_call_id: string | null }

export const site = raw as unknown as {
  meta: {
    case: string;
    run_id: string;
    host: string;
    captured: string;
    lead_model: string;
    specialist_model: string;
    started_utc: string;
    finished_utc: string;
    audit_records: number;
    audit_chain_ok: boolean;
    evidence_sha256_pre: string;
    evidence_sha256_post: string;
    evidence_integrity_ok: boolean;
    scenario: string;
  };
  audit: AuditRecord[];
  verdict: {
    executive_summary: string;
    findings: Finding[];
    iocs: Ioc[];
    open_questions: string[];
    enforcement: { audit_chain_ok: boolean; confirmed: number; inferred: number; downgraded: number };
    report_audit_id: string;
  };
  accuracy: {
    precision: number; recall: number; f1: number; hallucination_rate: number;
    confirmed_total: string; ground_truth_items: number;
    pre_correction: { precision: number; recall: number; f1: number };
    true_positives: ScoredFinding[];
    false_positives: ScoredFinding[];
    false_negatives: { category: string; value: string }[];
    unscored: Ioc[];
    framing: string;
  };
};

/** Map a record hash → the human labels of findings that cite it (for the inspector). */
export function citationsByRecord(): Record<string, string[]> {
  const map: Record<string, string[]> = {};
  for (const f of site.verdict.findings) {
    if (f.status === "confirmed" && f.tool_call_id) {
      (map[f.tool_call_id] ??= []).push(f.claim);
    }
  }
  return map;
}

/** Citations are derived once at module load — the underlying data is static JSON. */
export const citations = citationsByRecord();
