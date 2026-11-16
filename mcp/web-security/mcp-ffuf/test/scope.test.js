import { test } from "node:test";
import assert from "node:assert/strict";
import { Scope, ScopeError } from "../src/scope.js";

test("empty scope refuses everything", () => {
  const s = new Scope([]);
  assert.equal(s.allowsUrl("https://example.com/"), false);
  assert.throws(() => s.assertAllowsUrl("https://example.com/"), ScopeError);
});

test("exact hostname match", () => {
  const s = new Scope(["api.example.com"]);
  assert.equal(s.allowsUrl("https://api.example.com/v1/"), true);
  assert.equal(s.allowsUrl("https://example.com/"), false);
});

test("wildcard hostname match", () => {
  const s = new Scope(["*.example.com"]);
  assert.equal(s.allowsUrl("https://foo.example.com/"), true);
  assert.equal(s.allowsUrl("https://a.b.example.com/"), true);
  assert.equal(s.allowsUrl("https://example.com/"), false);
  assert.equal(s.allowsUrl("https://evilexample.com/"), false);
});

test("URL with port handled", () => {
  const s = new Scope(["api.example.com"]);
  assert.equal(s.allowsUrl("https://api.example.com:8443/"), true);
});

test("case-insensitive host match", () => {
  const s = new Scope(["API.Example.COM"]);
  assert.equal(s.allowsUrl("https://api.example.com/"), true);
});

test("malformed URL refused", () => {
  const s = new Scope(["example.com"]);
  assert.equal(s.allowsUrl("not a url"), false);
});
