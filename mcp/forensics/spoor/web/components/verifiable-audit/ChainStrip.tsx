import { isBrokenAt, type AuditRecord } from "@/lib/verifyAudit";

export function ChainStrip({
  records, brokenSeq, selected, onSelect,
}: {
  records: AuditRecord[];
  brokenSeq?: number;
  selected: number;
  onSelect: (seq: number) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1" aria-label="audit chain">
      {records.map((r, i) => {
        const broken = isBrokenAt(brokenSeq, i);
        const color = broken ? "border-red-600 text-red-400" : "border-emerald-700 text-emerald-400";
        return (
          <span key={r.seq} className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => onSelect(r.seq)}
              aria-current={selected === r.seq ? "step" : undefined}
              aria-label={`record ${r.seq}: ${r.tool}`}
              title={`seq ${r.seq} · ${r.tool}`}
              className={`h-7 w-7 rounded-full border ${color} ${selected === r.seq ? "ring-2 ring-sky-500" : ""}`}
            >
              {r.seq}
            </button>
            {i < records.length - 1 && <span className={`h-0.5 w-4 ${broken ? "bg-red-700" : "bg-emerald-800"}`} />}
          </span>
        );
      })}
    </div>
  );
}
