import { useState } from "react";
import { AlertTriangle, Link2, X, ChevronDown, ChevronRight } from "lucide-react";
import { isBrokenAt, type AuditRecord } from "@/lib/verifyAudit";

const FIELDS: (keyof AuditRecord)[] = ["seq", "tool", "args", "ts", "exit_code", "stdout_sha256", "prev_hash", "hash"];

export function RecordInspector({
  records, selected, onSelect, citations, brokenSeq, onEdit, onTamper,
}: {
  records: AuditRecord[];
  selected: number;
  onSelect: (seq: number) => void;
  citations: Record<string, string[]>;
  brokenSeq?: number;
  onEdit: (seq: number, field: keyof AuditRecord, value: string) => void;
  onTamper: (seq: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const rec = records[selected] ?? records[0];
  const cites = citations[rec.hash] ?? [];

  return (
    <div className="mt-4">
      <button type="button" onClick={() => setOpen((v) => !v)} className="flex items-center gap-1 text-sky-400 hover:underline">
        {open
          ? <ChevronDown className="h-3.5 w-3.5" aria-hidden />
          : <ChevronRight className="h-3.5 w-3.5" aria-hidden />}
        open the full inspector — all {records.length} records, click any field to edit it
      </button>
      {open && (
        <div className="mt-3 grid gap-3 md:grid-cols-[210px_1fr]">
          <ul className="space-y-1">
            {records.map((r, i) => {
              const broken = isBrokenAt(brokenSeq, i);
              return (
                <li key={r.seq}>
                  <button
                    type="button"
                    onClick={() => onSelect(r.seq)}
                    aria-current={selected === r.seq ? "step" : undefined}
                    className={`flex w-full justify-between rounded-md border px-2 py-1 ${
                      selected === r.seq ? "border-sky-600" : "border-neutral-800"
                    } ${broken ? "text-red-400" : "text-neutral-300"}`}
                  >
                    <span>seq{r.seq} {r.tool}</span>
                    {broken
                      ? <X className="h-3.5 w-3.5 shrink-0" aria-label="broken" />
                      : <Link2 className="h-3.5 w-3.5 shrink-0" aria-label="intact" />}
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="space-y-1">
            {FIELDS.map((f) => {
              // `seq` (the array anchor) and `args` (a nested object, not a flat string)
              // are read-only; the rest are free-editable to let a visitor tamper at will.
              const isEditable = f !== "seq" && f !== "args";
              const shown = f === "args" ? JSON.stringify(rec.args) : String(rec[f]);
              return (
                <div key={f} className="flex gap-2">
                  <span className="w-28 shrink-0 text-neutral-500">{f}</span>
                  <span
                    contentEditable={isEditable}
                    suppressContentEditableWarning
                    role={isEditable ? "textbox" : undefined}
                    aria-label={f}
                    onBlur={(e) => {
                      // Only commit real edits to editable fields: skip non-editable
                      // spans (never corrupt the `args` object into a string) and skip
                      // no-op blurs so tabbing through doesn't re-hash the whole chain.
                      if (!isEditable) return;
                      const next = e.currentTarget.textContent ?? "";
                      if (next !== shown) onEdit(rec.seq, f, next);
                    }}
                    className="break-all text-neutral-200 outline-none focus:bg-neutral-900"
                  >
                    {shown}
                  </span>
                </div>
              );
            })}
            {cites.length > 0 && (
              <p className="mt-2 rounded-md border border-dashed border-emerald-800 p-2 text-xs text-emerald-400">
                A finding&apos;s tool_call_id IS this hash. Findings citing it: {cites.join("; ")}
              </p>
            )}
            <button type="button" onClick={() => onTamper(rec.seq)} className="mt-2 flex items-center gap-1 text-amber-400 hover:underline">
              <AlertTriangle className="h-3.5 w-3.5" aria-hidden /> flip a byte in this record
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
