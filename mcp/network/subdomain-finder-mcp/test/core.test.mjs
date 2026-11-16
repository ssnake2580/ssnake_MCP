// Fixture tests. Upstream payloads in test/fixtures were saved from certspotter, crt.sh and Cloudflare DNS over
// HTTPS on 2026-11-02 (see DATA_SOURCES.md). Expected numbers were read off those payloads by hand and
// cross-checked with a separate Python script (DATA_SOURCES.md, "Cross-check").
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  InputError, PAGES, aggregateSubdomains, categorize, certspotterUrl, classifyDns, cleanName, crtshUrl, fetchCt,
  newBudget, normalizeDomain, parseCertspotter, parseCrtsh, resolveHost, surface, thirdParty, wildcardProbe,
} from '../dist/core.js';

const fx = (f) => readFileSync(new URL(`./fixtures/${f}`, import.meta.url), 'utf8');
const fxj = (f) => JSON.parse(fx(f));
const ok = (text) => ({ status: 200, text, retryAfter: null });

// Fetcher that serves saved payloads by URL substring; a function value can return any HttpResult.
const offline = (map, log = []) => async (url) => {
  log.push(url);
  for (const [k, v] of Object.entries(map)) if (url.includes(k)) return typeof v === 'function' ? v(url) : ok(fx(v));
  throw new Error(`no fixture for ${url}`);
};

test('normalizeDomain accepts URLs, wildcards, case and trailing dots; rejects IPs and junk', () => {
  assert.equal(normalizeDomain('https://Example.com/path?q=1'), 'example.com');
  assert.equal(normalizeDomain('*.HackerOne.com.'), 'hackerone.com');
  assert.equal(normalizeDomain('api.example.co.uk:8443'), 'api.example.co.uk');
  assert.throws(() => normalizeDomain('192.168.0.1'), InputError);
  assert.throws(() => normalizeDomain('localhost'), InputError);
  assert.throws(() => normalizeDomain('bad_label.example.com'), InputError);
  assert.throws(() => normalizeDomain('-x.example.com'), InputError);
});

test('cleanName drops e-mail addresses and mid-label wildcards, marks leading wildcards', () => {
  assert.deepEqual(cleanName('*.Example.com'), { name: 'example.com', wildcard: true });
  assert.deepEqual(cleanName('www.example.com.'), { name: 'www.example.com', wildcard: false });
  assert.equal(cleanName('pki_admin@sungard.com'), null);
  assert.equal(cleanName('foo.*.example.com'), null);
  assert.equal(cleanName('10.0.0.1'), null);
  assert.equal(cleanName('Issuer Not Found'), null);
});

test('upstream URLs: certspotter expands dns_names and issuer; crt.sh uses %25. and exclude=expired', () => {
  assert.equal(certspotterUrl('example.com'), 'https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&expand=issuer');
  assert.equal(certspotterUrl('example.com', '123', false), 'https://api.certspotter.com/v1/issuances?domain=example.com&match_wildcards=true&expand=dns_names&expand=issuer&after=123');
  assert.equal(crtshUrl('example.com', false), 'https://crt.sh/?q=%25.example.com&output=json&exclude=expired');
  assert.equal(crtshUrl('example.com', true), 'https://crt.sh/?q=%25.example.com&output=json');
  assert.equal(PAGES.finder, 'https://bugbountyreality.com/tools/subdomain-finder-real/?utm_source=mcp&utm_medium=subdomain-finder-mcp');
});

test('certspotter fixture (bugbountyreality.com): 11 issuances parsed with friendly issuer names', () => {
  const certs = parseCertspotter(fx('certspotter-bugbountyreality.json'));
  assert.equal(certs.length, 11);
  assert.deepEqual(certs[0], {
    id: '16380302948', source: 'certspotter', dns_names: ['*.bugbountyreality.com', 'bugbountyreality.com'], issuer: 'Sectigo',
    issuer_dn: 'C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36', not_before: '2026-08-08', not_after: '2026-11-06',
    revoked: false, sha256: 'c68c16cd9a893004161499def397b869ba601cc8a771d1e1ac43b563a26c1ec6',
  });
  assert.equal(certs.filter((c) => c.issuer === 'Google Trust Services').length, 8); // 8 GTS + 3 Sectigo;
});

test('aggregate certspotter fixture: 2 hosts, wildcard marked, first/last seen and issuers', () => {
  const { rows, wildcards, outOfScope } = aggregateSubdomains(parseCertspotter(fx('certspotter-bugbountyreality.json')), 'bugbountyreality.com');
  assert.deepEqual(wildcards, ['*.bugbountyreality.com']);
  assert.equal(outOfScope, 0);
  assert.deepEqual(rows, [
    { name: 'bugbountyreality.com', first_seen: '2026-08-08', last_seen: '2026-10-07', valid_until: '2027-01-05', cert_count: 7, issuers: ['Google Trust Services', 'Sectigo'], wildcard_cert: true },
    { name: 'www.bugbountyreality.com', first_seen: '2026-09-28', last_seen: '2026-09-28', valid_until: '2026-12-27', cert_count: 4, issuers: ['Google Trust Services'], wildcard_cert: false },
  ]);
});

test('crt.sh fixture (%.example.com): 85 rows collapse to 49 certificates (precert + cert share a serial)', () => {
  const certs = parseCrtsh(fx('crtsh-example.json'));
  assert.equal(fxj('crtsh-example.json').length, 85);
  assert.equal(certs.length, 49);
  assert.ok(certs.every((c) => c.source === 'crtsh' && /^\d{4}-\d\d-\d\d$/.test(c.not_before)));
});

test('aggregate crt.sh example.com: 7 hosts, 12 out-of-scope SANs skipped, quoted O= issuer parsed', () => {
  const { rows, wildcards, outOfScope } = aggregateSubdomains(parseCrtsh(fx('crtsh-example.json')), 'example.com');
  assert.equal(rows.length, 7);
  assert.equal(outOfScope, 12);
  assert.deepEqual(wildcards, ['*.example.com']);
  const by = Object.fromEntries(rows.map((r) => [r.name, r]));
  assert.deepEqual(by['www.example.com'], { name: 'www.example.com', first_seen: '2014-11-06', last_seen: '2025-12-02', valid_until: '2026-12-02', cert_count: 15, issuers: ['DigiCert Inc', 'Sectigo Limited', 'Symantec Corporation', 'thawte, Inc.'], wildcard_cert: false });
  assert.equal(by['example.com'].cert_count, 43);
  assert.ok(by['example.com'].issuers.includes('CLOUDFLARE, INC.'));
  assert.deepEqual(by['emudhra-lab.example.com'], { name: 'emudhra-lab.example.com', first_seen: '2026-10-20', last_seen: '2026-10-20', valid_until: '2027-08-01', cert_count: 3, issuers: ['eMudhra BV'], wildcard_cert: false });
  assert.deepEqual(rows.map((r) => r.name), ['example.com', 'dev.example.com', 'emudhra-lab.example.com', 'm.example.com', 'products.example.com', 'support.example.com', 'www.example.com']);
});

test('aggregate crt.sh abwex.com: apex 12 certs (wildcard), www 3 certs back to 2024-11-22', () => {
  const { rows } = aggregateSubdomains(parseCrtsh(fx('crtsh-abwex.json')), 'abwex.com');
  assert.deepEqual(rows.map((r) => [r.name, r.cert_count, r.first_seen, r.last_seen, r.wildcard_cert]), [
    ['abwex.com', 12, '2025-11-20', '2026-10-06', true],
    ['www.abwex.com', 3, '2024-11-22', '2025-11-20', false],
  ]);
});

test('DNS classify: direct A (live), CNAME chain (live), NXDOMAIN, NODATA (no_records)', () => {
  const live = classifyDns('www.hackerone.com', fxj('doh-www.hackerone.com_type_A.json'), null);
  assert.equal(live.status, 'live');
  assert.deepEqual(live.a, ['104.18.36.214', '172.64.151.42']);
  const chain = classifyDns('www.github.com', fxj('doh-www.github.com_type_A.json'), null);
  assert.deepEqual([chain.status, chain.cname_chain, chain.a], ['live', ['github.com'], ['140.82.121.3']]);
  assert.equal(classifyDns('zz-nx-9q.abwex.com', fxj('doh-zz-nx-9q.abwex.com_type_A.json'), null).status, 'nxdomain');
  const nodata = { Status: 0, Answer: [] };
  assert.equal(classifyDns('zz-nx-9q.hackerone.com', nodata, fxj('doh-zz-nx-9q.hackerone.com_type_AAAA.json')).status, 'no_records');
});

test('DNS classify: CNAME to a deleted S3 bucket is dangling_cname and names the service', () => {
  // Hand-built answer in the RFC 8484 JSON shape Cloudflare returns: Status 3 (NXDOMAIN) with the CNAME in Answer.
  const ans = { Status: 3, Answer: [{ name: 'assets.example.com', type: 5, TTL: 300, data: 'old-bucket.s3.amazonaws.com.' }] };
  const r = classifyDns('assets.example.com', ans, null);
  assert.equal(r.status, 'dangling_cname');
  assert.equal(r.third_party, 'AWS S3');
  assert.match(r.note, /does not exist \(NXDOMAIN\)/);
  assert.equal(thirdParty('foo.herokuapp.com.'), 'Heroku');
  assert.equal(thirdParty('bucket.s3-website-us-east-1.amazonaws.com'), 'AWS S3 website');
  assert.equal(thirdParty('github.com'), null);
});

test('wildcard DNS probe: *.github.io answers for a random label, abwex.com does not', async () => {
  const gh = await wildcardProbe(offline({ 'github.io': 'doh-zz-nx-9q.github.io_type_A.json' }), newBudget(), 'github.io', () => 0.5);
  assert.equal(gh.wildcard_dns, true);
  assert.equal(gh.answers.length, 4);
  const ab = await wildcardProbe(offline({ 'abwex.com': 'doh-zz-nx-9q.abwex.com_type_A.json' }), newBudget(), 'abwex.com', () => 0.5);
  assert.equal(ab.wildcard_dns, false);
});

test('certspotter pagination: follows after=<last id> until an empty page; max_pages truncates', async () => {
  const log = [];
  const f = offline({ 'after=17636093707': () => ok('[]'), 'certspotter': 'certspotter-bugbountyreality.json' }, log);
  const r = await fetchCt(f, newBudget(), 'bugbountyreality.com', { source: 'auto', includeExpired: false, maxPages: 3 });
  assert.deepEqual([r.source, r.certs.length, r.pages, r.truncated], ['certspotter', 11, 2, false]);
  assert.match(log[1], /after=17636093707/);
  const r1 = await fetchCt(f, newBudget(), 'bugbountyreality.com', { source: 'auto', includeExpired: false, maxPages: 1 });
  assert.deepEqual([r1.pages, r1.truncated], [1, true]);
});

test('certspotter 429 on the first page falls back to crt.sh and says so', async () => {
  const f = offline({ 'certspotter': () => ({ status: 429, text: '{"code":"rate_limited"}', retryAfter: '120' }), 'crt.sh': 'crtsh-abwex.json' });
  const r = await fetchCt(f, newBudget(), 'abwex.com', { source: 'auto', includeExpired: false, maxPages: 3 });
  assert.equal(r.source, 'crtsh');
  assert.match(r.notes[0], /certspotter failed \(certspotter \(api.certspotter.com\) is rate limiting this IP \(HTTP 429\)\. It asks to wait 120 seconds\.\); fell back to crt\.sh/);
});

test('both sources down: one throttled error that tells the caller to wait; crt.sh retried once', async () => {
  const log = [];
  const f = offline({ 'certspotter': () => ({ status: 429, text: '', retryAfter: null }), 'crt.sh': () => ({ status: 502, text: '<html>', retryAfter: null }) }, log);
  await assert.rejects(fetchCt(f, newBudget(), 'abwex.com', { source: 'auto', includeExpired: false, maxPages: 3 }),
    (e) => e.throttled === true && /Both certificate transparency sources failed/.test(e.message) && /HTTP 502 twice/.test(e.message) && /Wait a few minutes/.test(e.message));
  assert.equal(log.filter((u) => u.includes('crt.sh')).length, 2);
});

test('request budget: a host past the budget is skipped, not fetched', async () => {
  const budget = newBudget(0);
  const r = await resolveHost(async () => { throw new Error('must not fetch'); }, budget, 'www.example.com');
  assert.equal(r.status, 'skipped');
});

test('attack surface grouping: dev, mail, api, admin tokens; clusters by parent', () => {
  assert.deepEqual(categorize('dev.example.com', 'example.com'), ['dev_test']);
  assert.deepEqual(categorize('mta-sts.ave-mail.hackerone.com', 'hackerone.com'), ['mail']);
  assert.deepEqual(categorize('api2.staging.example.com', 'example.com'), ['staging', 'api']);
  assert.deepEqual(categorize('www.example.com', 'example.com'), []);
  const rows = ['admin.eu.example.com', 'api.eu.example.com', 'vpn.example.com', 'www.example.com'].map((name) => ({ name, first_seen: '2026-01-01', last_seen: '2026-01-01', valid_until: '2026-12-01', cert_count: 1, issuers: ["Let's Encrypt"], wildcard_cert: false }));
  const s = surface(rows, 'example.com');
  assert.deepEqual(s.groups.map((g) => [g.key, g.count]), [['admin_internal', 1], ['api', 1], ['remote_access', 1]]);
  assert.deepEqual(s.clusters, [{ parent: 'eu.example.com', count: 2 }]);
  assert.equal(s.uncategorized, 1);
  assert.equal(s.max_depth, 2);
});
