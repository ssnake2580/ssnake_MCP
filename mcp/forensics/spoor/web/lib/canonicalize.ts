export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/**
 * Deterministic JSON identical to Python's
 *   json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
 * Keys are sorted by code point (matches Python for our ASCII keys); separators are
 * bare; non-ASCII is left literal (JSON.stringify default == ensure_ascii=False).
 *
 * ASSUMPTION: audit content has no float numbers. Python json.dumps(1.0) -> "1.0"
 * but JSON.stringify(1.0) -> "1", so a float would diverge and break hash parity.
 * Real records use only integers (seq, exit_code, nested arg counts), strings, and
 * nested objects — all safe. If floats ever enter args, canonicalize must special-case them.
 */
export function canonicalize(value: Json): string {
  if (value === null) return "null";
  if (typeof value !== "object") return JSON.stringify(value); // string | number | boolean
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const obj = value as { [key: string]: Json };
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
}
