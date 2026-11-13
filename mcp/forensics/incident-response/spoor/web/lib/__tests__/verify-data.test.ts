import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const SCRIPT = resolve(__dirname, "../../scripts/verify-data.ts");

describe("build-time data gate", () => {
  it("exits 0 on the committed (intact) data", () => {
    const out = execFileSync("npx", ["tsx", SCRIPT], { encoding: "utf8", cwd: resolve(__dirname, "../..") });
    expect(out).toMatch(/data gate OK/);
  });
});
