// Pure-function tests for src/tools/runner.ts input guards.
// No PD binaries needed — safe to run in CI.
import { describe, expect, test } from "bun:test";
import { cleanDomain, cleanList, cleanPortSpec } from "../src/tools/runner.ts";

describe("cleanDomain", () => {
  test("accepts valid domains", () => {
    expect(cleanDomain("example.com")).toBe("example.com");
    expect(cleanDomain("WWW.Example.COM")).toBe("www.example.com");
    expect(cleanDomain("sub-domain.example.co.uk")).toBe("sub-domain.example.co.uk");
  });

  test("rejects invalid domains", () => {
    expect(() => cleanDomain("")).toThrow();
    expect(() => cleanDomain("not a domain!")).toThrow();
    expect(() => cleanDomain("evil.com\nrm -rf")).toThrow();
    expect(() => cleanDomain("a".repeat(300))).toThrow();
  });
});

describe("cleanList", () => {
  test("dedupes and strips", () => {
    expect(cleanList(["a.com", "a.com", " b.com "])).toEqual(["a.com", "b.com"]);
  });

  test("drops control chars and overlong entries", () => {
    expect(cleanList(["ok.com", "bad\n.com", "x".repeat(300)])).toEqual(["ok.com"]);
  });

  test("caps at maxItems", () => {
    const many = Array.from({ length: 2000 }, (_, i) => `h${i}.com`);
    expect(cleanList(many)).toHaveLength(1000);
  });

  test("non-array input yields empty", () => {
    expect(cleanList("nope")).toEqual([]);
    expect(cleanList(null)).toEqual([]);
  });
});

describe("cleanPortSpec", () => {
  test("accepts valid specs", () => {
    expect(cleanPortSpec("80")).toBe("80");
    expect(cleanPortSpec("80,443")).toBe("80,443");
    expect(cleanPortSpec("1-1000")).toBe("1-1000");
  });

  test("empty/null yields undefined", () => {
    expect(cleanPortSpec("")).toBeUndefined();
    expect(cleanPortSpec(null)).toBeUndefined();
    expect(cleanPortSpec(undefined)).toBeUndefined();
  });

  test("rejects injection attempts", () => {
    expect(() => cleanPortSpec("80; rm -rf /")).toThrow();
    expect(() => cleanPortSpec("80 && curl evil.com")).toThrow();
  });
});
