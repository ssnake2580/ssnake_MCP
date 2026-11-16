import { test } from "node:test";
import assert from "node:assert/strict";
import { __test__ } from "../src/ffuf.js";

const { validateWordlist, validateCodeList, validateExtensions, parseResults } = __test__;

test("validateWordlist rejects relative path", async () => {
  await assert.rejects(() => validateWordlist("wordlists/common.txt"), /absolute/);
});

test("validateWordlist rejects missing path", async () => {
  await assert.rejects(() => validateWordlist("/does/not/exist/wordlist.txt"), /not readable/);
});

test("validateWordlist accepts readable absolute path", async () => {
  const path = await validateWordlist("/etc/hosts");
  assert.equal(path, "/etc/hosts");
});

test("validateCodeList rejects shell metacharacters", () => {
  assert.throws(() => validateCodeList("200;ls", "match_codes"));
  assert.throws(() => validateCodeList("200 || curl evil", "match_codes"));
});

test("validateCodeList accepts valid input", () => {
  assert.equal(validateCodeList("200,301,401", "match_codes"), "200,301,401");
  assert.equal(validateCodeList(null, "match_codes"), null);
});

test("validateExtensions rejects bad chars", () => {
  assert.throws(() => validateExtensions(".php;cat /etc/passwd"));
});

test("validateExtensions accepts valid list", () => {
  assert.equal(validateExtensions(".php,.html,.asp"), ".php,.html,.asp");
});

test("parseResults handles empty output", () => {
  assert.deepEqual(parseResults(""), { results: [] });
  assert.deepEqual(parseResults("   "), { results: [] });
});

test("parseResults handles valid JSON", () => {
  const out = JSON.stringify({ results: [{ url: "x", status: 200 }] });
  assert.deepEqual(parseResults(out), { results: [{ url: "x", status: 200 }] });
});

test("parseResults tolerates garbage", () => {
  const r = parseResults("not json at all");
  assert.deepEqual(r.results, []);
  assert.ok(r.raw);
});
