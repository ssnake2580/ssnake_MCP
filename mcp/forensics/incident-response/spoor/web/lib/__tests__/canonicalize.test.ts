import { describe, it, expect } from "vitest";
import { canonicalize } from "../canonicalize";

describe("canonicalize (mirrors Python json.dumps sort_keys, separators=(',',':'), ensure_ascii=False)", () => {
  it("sorts object keys and uses compact separators", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
  it("sorts nested objects recursively", () => {
    expect(canonicalize({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });
  it("keeps integers bare and strings quoted", () => {
    expect(canonicalize({ exit_code: 0, tool: "vol_netscan" })).toBe('{"exit_code":0,"tool":"vol_netscan"}');
  });
  it("matches a known audit content hash input", () => {
    // content fields of seq 0, in any order — canonical form must be stable
    const content = {
      seq: 0,
      ts: "2026-06-12T23:16:45.693151+00:00",
      tool: "vol_pslist",
      args: { memory_image: "/Users/rector/local-dev/spoor/evidence/case001/citadeldc01.mem" },
      exit_code: 0,
      stdout_sha256: "cb8c4b62f91fb09033e3bd3ea7b56ccba67a436688907d10f61de13cf2ca82ed",
      prev_hash: "0".repeat(64),
    };
    expect(canonicalize(content)).toBe(
      '{"args":{"memory_image":"/Users/rector/local-dev/spoor/evidence/case001/citadeldc01.mem"},' +
        '"exit_code":0,"prev_hash":"' + "0".repeat(64) + '",' +
        '"seq":0,"stdout_sha256":"cb8c4b62f91fb09033e3bd3ea7b56ccba67a436688907d10f61de13cf2ca82ed",' +
        '"tool":"vol_pslist","ts":"2026-06-12T23:16:45.693151+00:00"}',
    );
  });
});
