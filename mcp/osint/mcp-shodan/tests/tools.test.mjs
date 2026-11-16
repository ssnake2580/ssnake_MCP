// Tool tests with axios.get mocked; the real Shodan API is never contacted.
import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.SHODAN_API_KEY = 'test-key';

const { default: axios } = await import('axios');
const { registerIpLookup } = await import('../build/tools/ip-lookup.js');
const { registerShodanSearch } = await import('../build/tools/shodan-search.js');
const { registerCveLookup } = await import('../build/tools/cve-lookup.js');
const { registerDnsLookup } = await import('../build/tools/dns-lookup.js');
const { registerReverseDnsLookup } = await import('../build/tools/reverse-dns-lookup.js');
const { registerCpeLookup } = await import('../build/tools/cpe-lookup.js');
const { registerCvesByProduct } = await import('../build/tools/cves-by-product.js');
const { registerShodanCount } = await import('../build/tools/shodan-count.js');
const { registerDomainInfo } = await import('../build/tools/domain-info.js');
const { registerApiInfo } = await import('../build/tools/api-info.js');
const { registerSearchFilters } = await import('../build/tools/search-filters.js');
const { queryCVEDB, queryCPEDB, queryCVEsByProduct } = await import('../build/helpers.js');

const tools = {};
const fake = { addTool(def) { tools[def.name] = def; } };
for (const r of [registerIpLookup, registerShodanSearch, registerCveLookup, registerDnsLookup,
  registerReverseDnsLookup, registerCpeLookup, registerCvesByProduct,
  registerShodanCount, registerDomainInfo, registerApiInfo, registerSearchFilters]) r(fake);

function mockGet(t, data) {
  const calls = [];
  t.mock.method(axios, 'get', async (url, config) => {
    calls.push({ url, config });
    return { data: typeof data === 'function' ? data(url, config) : data };
  });
  return calls;
}
const run = (name, args) => tools[name].execute(tools[name].parameters.parse(args));

const match = (i) => ({
  ip_str: `1.2.3.${i}`, org: 'Org', isp: 'ISP', asn: 'AS1', timestamp: 'now',
  location: { country_name: 'US', latitude: 1, longitude: 2 },
  port: 80, transport: 'tcp', hostnames: [], domains: [],
});

test('all 11 tools are registered', () => {
  assert.deepEqual(Object.keys(tools).sort(), [
    'api_info', 'cpe_lookup', 'cve_lookup', 'cves_by_product', 'dns_lookup', 'domain_info',
    'ip_lookup', 'reverse_dns_lookup', 'search_filters', 'shodan_count', 'shodan_search']);
  for (const t of Object.values(tools)) {
    assert.equal(t.annotations.readOnlyHint, true);
    assert.equal(t.annotations.openWorldHint, true);
  }
});

test('shodan_search does not send limit, requests country facets, slices to max_results', async (t) => {
  const calls = mockGet(t, {
    total: 200,
    matches: Array.from({ length: 50 }, (_, i) => match(i)),
    facets: { country: [{ value: 'US', count: 50 }] },
  });
  const out = JSON.parse(await run('shodan_search', { query: 'apache', max_results: 5 }));
  const params = calls[0].config.params;
  assert.ok(!('limit' in params));
  assert.equal(params.facets, 'country');
  assert.equal(params.query, 'apache');
  assert.equal(out.Matches.length, 5);
  assert.equal(out['Search Summary']['Results Returned'], 5);
  assert.equal(out['Country Distribution'][0].Percentage, '25.00%');
});

test('shodan_search validates max_results as int 1..100', () => {
  const p = tools.shodan_search.parameters;
  for (const bad of [0, 101, 1.5, -1]) assert.throws(() => p.parse({ query: 'x', max_results: bad }));
  assert.equal(p.parse({ query: 'x' }).max_results, 10);
});

test('shodan_search guards percentage when total is 0', async (t) => {
  mockGet(t, { total: 0, matches: [], facets: { country: [{ value: 'US', count: 0 }] } });
  const out = JSON.parse(await run('shodan_search', { query: 'nothing' }));
  assert.equal(out['Country Distribution'][0].Percentage, '0.00%');
  assert.equal(out['Search Summary']['Results Returned'], 0);
});

test('ip_lookup tolerates missing ports/data', async (t) => {
  const calls = mockGet(t, { ip_str: '8.8.8.8', org: 'Google' });
  const out = JSON.parse(await run('ip_lookup', { ip: '8.8.8.8' }));
  assert.deepEqual(out.Services, []);
  assert.equal(out['Cloud Provider'], 'Not detected');
  assert.ok(calls[0].url.endsWith('/shodan/host/8.8.8.8'));
});

test('ip_lookup happy path with service', async (t) => {
  mockGet(t, {
    ip_str: '8.8.8.8', ports: [443],
    data: [{ port: 443, transport: 'tcp', data: ' banner ', http: { server: 'gws', title: 'T' } }],
  });
  const out = JSON.parse(await run('ip_lookup', { ip: '8.8.8.8' }));
  assert.equal(out.Services[0].Port, 443);
  assert.equal(out.Services[0].Service, 'banner');
  assert.equal(out.Services[0].HTTP.Server, 'gws');
});

test('ip_lookup validates ip (v4/v6 only)', () => {
  const p = tools.ip_lookup.parameters;
  assert.ok(p.parse({ ip: '2001:db8::1' }));
  for (const bad of ['../x', '1.2.3.4/../../account', 'example.com', '1.2.3.4?a=b']) {
    assert.throws(() => p.parse({ ip: bad }));
  }
});

test('CVEDB helpers set a 10s timeout and encode the CVE id', async (t) => {
  const calls = mockGet(t, { cpes: [], total: 0, cves: [] });
  await queryCVEDB('CVE-2021-44228/../x');
  await queryCPEDB({ product: 'p' });
  await queryCVEsByProduct({ product: 'p' });
  assert.ok(calls[0].url.endsWith('/cve/CVE-2021-44228%2F..%2Fx'));
  for (const c of calls) assert.equal(c.config?.timeout, 10000);
});

test('cpe_lookup and cves_by_product bound skip/limit', () => {
  for (const name of ['cpe_lookup', 'cves_by_product']) {
    const p = tools[name].parameters;
    const base = name === 'cpe_lookup' ? { product: 'x' } : { product: 'x' };
    for (const bad of [{ skip: -1 }, { limit: 0 }, { limit: 1001 }, { limit: 1.5 }, { skip: 0.5 }]) {
      assert.throws(() => p.parse({ ...base, ...bad }), name);
    }
    const ok = p.parse(base);
    assert.equal(ok.skip, 0);
    assert.equal(ok.limit, 1000);
  }
});

test('cpe_lookup happy path', async (t) => {
  const calls = mockGet(t, { cpes: ['cpe:2.3:a:x'], total: 1 });
  const out = JSON.parse(await run('cpe_lookup', { product: 'nginx', limit: 5 }));
  assert.deepEqual(out.cpes, ['cpe:2.3:a:x']);
  assert.equal(calls[0].config.params.limit, 5);
  const cnt = JSON.parse(await run('cpe_lookup', { product: 'nginx', count: true }));
  assert.equal(cnt.total_cpes, 1);
});

test('cve_lookup happy path', async (t) => {
  mockGet(t, {
    cve_id: 'CVE-2021-44228', published_time: '2021-12-10T00:00:00', summary: 'log4j',
    cvss_v3: 10, epss: 0.9, ranking_epss: 0.01, kev: true, cpes: [], references: [],
  });
  const out = JSON.parse(await run('cve_lookup', { cve: 'cve-2021-44228' }));
  assert.equal(out['Basic Information']['CVE ID'], 'CVE-2021-44228');
  assert.equal(out['Severity Scores']['CVSS v3'].Severity, 'Critical');
  assert.equal(out['Impact Assessment']['Known Exploited Vulnerability'], 'Yes');
});

test('cves_by_product happy path and pagination', async (t) => {
  // Like the real CVEDB: /cves returns only the list; the total needs count=true.
  const calls = mockGet(t, (url, config) => config.params.count
    ? { total: 42 }
    : { cves: [{ cve_id: 'CVE-1-1', published_time: '2020-01-01', summary: 's', cvss_v2: 5, references: [] }] });
  const out = JSON.parse(await run('cves_by_product', { product: 'nginx', skip: 20, limit: 10 }));
  assert.equal(out['Results Summary'].Page, '3');
  assert.equal(out['Results Summary']['Total CVEs Found'], 42);
  assert.equal(out.Vulnerabilities[0]['Severity Scores']['CVSS v2'].Severity, 'Medium');
  const countCall = calls.find((c) => c.config.params.count);
  assert.equal(countCall.config.params.product, 'nginx');
  assert.equal(countCall.config.params.skip, undefined);
  assert.equal(countCall.config.params.limit, undefined);
});

test('EPSS ranking is reported as a percentile', async (t) => {
  mockGet(t, (url, config) => config?.params?.count ? { total: 1 } : {
    cve_id: 'CVE-2021-44228', published_time: '2021-12-10T00:00:00', summary: 's',
    epss: 0.97, ranking_epss: 0.9995, cpes: [], references: [],
    cves: [{ cve_id: 'CVE-2021-44228', published_time: '2021-12-10', summary: 's', epss: 0.97, ranking_epss: 0.9995, references: [] }],
  });
  const expected = { Score: '97.00%', Percentile: '99.95 (higher than 99.95% of scored CVEs)' };
  const one = JSON.parse(await run('cve_lookup', { cve: 'CVE-2021-44228' }));
  assert.deepEqual(one['Severity Scores'].EPSS, expected);
  const many = JSON.parse(await run('cves_by_product', { product: 'log4j', limit: 1 }));
  assert.deepEqual(many.Vulnerabilities[0]['Severity Scores'].EPSS, expected);
});

test('cve_lookup caps affected products at 50 and reports the total', async (t) => {
  const cpes = Array.from({ length: 120 }, (_, i) => `cpe:2.3:a:apache:log4j:2.${i}`);
  mockGet(t, { cve_id: 'CVE-2021-44228', published_time: '2021-12-10', summary: 's', cpes, references: [] });
  const out = JSON.parse(await run('cve_lookup', { cve: 'CVE-2021-44228' }));
  const ap = out['Affected Products'];
  assert.equal(ap.Total, 120);
  assert.equal(ap.Shown, 50);
  assert.deepEqual(ap.CPEs, cpes.slice(0, 50));
  assert.match(ap.Note, /50 of 120/);
});

test('cve_lookup lists all affected products when there are few', async (t) => {
  mockGet(t, { cve_id: 'CVE-2020-0001', published_time: '2021-12-10', summary: 's', cpes: ['cpe:2.3:a:x:y:1'], references: [] });
  const out = JSON.parse(await run('cve_lookup', { cve: 'CVE-2020-0001' }));
  assert.deepEqual(out['Affected Products'], { Total: 1, Shown: 1, CPEs: ['cpe:2.3:a:x:y:1'] });
});

test('cves_by_product mutual-exclusion errors', async () => {
  await assert.rejects(run('cves_by_product', { product: 'a', cpe23: 'cpe:2.3:a:b:c' }), /both/);
  await assert.rejects(run('cves_by_product', {}), /either/);
});

test('dns_lookup happy path', async (t) => {
  const calls = mockGet(t, { 'a.com': '1.1.1.1', 'b.com': '2.2.2.2' });
  const out = JSON.parse(await run('dns_lookup', { hostnames: ['a.com', 'b.com'] }));
  assert.equal(calls[0].config.params.hostnames, 'a.com,b.com');
  assert.equal(out.Summary['Total Lookups'], 2);
  assert.equal(out['DNS Resolutions'][0]['IP Address'], '1.1.1.1');
});

test('reverse_dns_lookup handles null PTR', async (t) => {
  mockGet(t, { '1.1.1.1': ['one.one.one.one'], '9.9.9.9': null });
  const out = JSON.parse(await run('reverse_dns_lookup', { ips: ['1.1.1.1', '9.9.9.9'] }));
  assert.deepEqual(out['Reverse DNS Resolutions'][1].Hostnames, ['No hostnames found']);
  assert.equal(out.Summary['IPs with Results'], 1);
});

// ---- API coverage additions ----

test('shodan_search sends page only when > 1, custom facets, and rejects bad input', async (t) => {
  const calls = mockGet(t, { total: 10, matches: [], facets: {} });
  await run('shodan_search', { query: 'x' });
  assert.ok(!('page' in calls[0].config.params));
  assert.equal(calls[0].config.params.facets, 'country');
  const out = JSON.parse(await run('shodan_search', { query: 'x', page: 3, facets: 'org:5,port' }));
  assert.equal(calls[1].config.params.page, 3);
  assert.equal(calls[1].config.params.facets, 'org:5,port');
  assert.equal(out['Search Summary'].Page, 3);
  assert.ok(!('Country Distribution' in out));
  const p = tools.shodan_search.parameters;
  assert.throws(() => p.parse({ query: 'x', page: 0 }));
  for (const bad of ['', 'country,', 'a b', 'country:12345', 'a;b', ',a'])
    assert.throws(() => p.parse({ query: 'x', facets: bad }), bad);
  assert.ok(p.parse({ query: 'x', facets: 'Country:10,org,http.title' }));
  assert.match(tools.shodan_search.description, /when the query uses filters, plus 1 per page beyond the first/);
});

test('shodan_search Facets output, OS and vulnerabilities', async (t) => {
  mockGet(t, {
    total: 200,
    matches: [{ ...match(1), os: 'Linux', vulns: { 'CVE-2020-2': {}, 'CVE-2019-1': {} } }, match(2)],
    facets: { country: [{ value: 'US', count: 50 }], port: [{ value: 80, count: 100 }] },
  });
  const out = JSON.parse(await run('shodan_search', { query: 'x', facets: 'country,port' }));
  assert.deepEqual(out.Facets.country[0], { Value: 'US', Count: 50, Percentage: '25.00%' });
  assert.equal(out.Facets.port[0].Percentage, '50.00%');
  assert.equal(out['Country Distribution'][0].Percentage, '25.00%');
  assert.equal(out.Matches[0].OS, 'Linux');
  assert.deepEqual(out.Matches[0].Vulnerabilities, ['CVE-2019-1', 'CVE-2020-2']);
  assert.ok(!('Vulnerabilities' in out.Matches[1]));
  assert.equal(out.Matches[1].OS, 'Unknown');
});

test('shodan_count sends query/facets, guards total 0, validates facets', async (t) => {
  const calls = mockGet(t, { total: 0, facets: { org: [{ value: 'A', count: 0 }] } });
  const out = JSON.parse(await run('shodan_count', { query: 'apache', facets: 'org' }));
  assert.ok(calls[0].url.endsWith('/shodan/host/count'));
  assert.equal(calls[0].config.params.query, 'apache');
  assert.equal(calls[0].config.params.facets, 'org');
  assert.deepEqual(out['Search Summary'], { Query: 'apache', 'Total Results': 0 });
  assert.equal(out.Facets.org[0].Percentage, '0.00%');
  await run('shodan_count', { query: 'apache' });
  assert.ok(!('facets' in calls[1].config.params));
  assert.throws(() => tools.shodan_count.parameters.parse({ query: 'x', facets: 'bad facet' }));
  assert.match(tools.shodan_count.description, /does not consume query credits/);
});

test('domain_info request params, output and validation', async (t) => {
  const calls = mockGet(t, {
    domain: 'example.com', tags: ['cdn'], subdomains: ['www', 'mail'], more: true,
    data: [{ subdomain: '', type: 'MX', value: 'mx.example.com', last_seen: '2024-01-01' },
      { subdomain: 'www', type: 'A', value: '1.2.3.4', last_seen: '2024-01-02' }],
  });
  const out = JSON.parse(await run('domain_info', { domain: 'example.com' }));
  assert.ok(calls[0].url.endsWith('/dns/domain/example.com'));
  for (const k of ['history', 'type', 'page']) assert.ok(!(k in calls[0].config.params), k);
  assert.equal(out.Domain, 'example.com');
  assert.deepEqual(out.Subdomains, { Count: 2, Names: ['www', 'mail'] });
  assert.equal(out['DNS Records'][0].Subdomain, '@');
  assert.equal(out['DNS Records'][0]['Last Seen'], '2024-01-01');
  assert.equal(out['More Results'], 'Yes — request page 2');
  await run('domain_info', { domain: 'example.com', history: true, type: 'A', page: 2 });
  assert.deepEqual(
    { h: calls[1].config.params.history, t: calls[1].config.params.type, p: calls[1].config.params.page },
    { h: true, t: 'A', p: 2 });
  const p = tools.domain_info.parameters;
  for (const bad of ['../x', 'example', 'a b.com', 'x.com/../y', '-a.com', 'a.com?x=1'])
    assert.throws(() => p.parse({ domain: bad }), bad);
  for (const good of ['example.com', 'Sub.Example.CO.uk', 'xn--e1afmkfd.xn--p1ai'])
    assert.equal(p.parse({ domain: good }).domain, good);
  assert.throws(() => p.parse({ domain: 'a.com', page: 0 }));
  assert.throws(() => p.parse({ domain: 'a.com', type: 'SRV' }));
  assert.match(tools.domain_info.description, /1 query credit/);
});

test('domain_info tolerates empty response', async (t) => {
  mockGet(t, {});
  const out = JSON.parse(await run('domain_info', { domain: 'a.com' }));
  assert.equal(out.Domain, 'a.com');
  assert.deepEqual(out['DNS Records'], []);
  assert.equal(out['More Results'], 'No');
});

test('api_info output', async (t) => {
  const calls = mockGet(t, {
    plan: 'dev', query_credits: 100, scan_credits: 5, monitored_ips: 2,
    usage_limits: { query_credits: 100, scan_credits: 5, monitored_ips: 16 },
    unlocked: true, unlocked_left: 99, https: false, telnet: false,
  });
  const out = JSON.parse(await run('api_info', {}));
  assert.ok(calls[0].url.endsWith('/api-info'));
  assert.equal(out.Plan, 'dev');
  assert.equal(out['Query Credits'], 100);
  assert.equal(out['Usage Limits'].monitored_ips, 16);
  assert.equal(out['Unlocked Left'], 99);
  assert.equal(out.HTTPS, false);
});

test('search_filters calls both endpoints and sorts', async (t) => {
  const calls = mockGet(t, (url) =>
    url.endsWith('/filters') ? ['port', 'country', 'asn'] : ['org', 'country']);
  const out = JSON.parse(await run('search_filters', {}));
  assert.deepEqual(calls.map((c) => c.url.split('.io')[1]).sort(),
    ['/shodan/host/search/facets', '/shodan/host/search/filters']);
  assert.deepEqual(out.Filters, { Count: 3, Names: ['asn', 'country', 'port'] });
  assert.deepEqual(out.Facets, { Count: 2, Names: ['country', 'org'] });
});

test('ip_lookup sends history/minify only when true', async (t) => {
  const calls = mockGet(t, { ip_str: '8.8.8.8' });
  await run('ip_lookup', { ip: '8.8.8.8' });
  assert.deepEqual(Object.keys(calls[0].config.params), ['key']);
  await run('ip_lookup', { ip: '8.8.8.8', history: true, minify: true });
  assert.equal(calls[1].config.params.history, true);
  assert.equal(calls[1].config.params.minify, true);
});

test('ip_lookup enrichment: OS, product, CPE, vulns, latest banner, history', async (t) => {
  mockGet(t, {
    ip_str: '1.1.1.1', os: 'Linux', ports: [80, 22], vulns: ['CVE-2021-2', 'CVE-2020-1'],
    data: [
      { port: 80, transport: 'tcp', timestamp: '2023-01-01T00:00:00', data: 'old', product: 'nginx', version: '1.0' },
      { port: 80, transport: 'tcp', timestamp: '2024-06-01T00:00:00', data: 'new', product: 'nginx', version: '1.2',
        cpe: ['cpe:/a:nginx:nginx:1.2'], cpe23: ['cpe:2.3:a:nginx:nginx:1.2'], vulns: { 'CVE-9-2': {}, 'CVE-9-1': {} } },
      { port: 22, transport: 'tcp', timestamp: '2024-01-01T00:00:00', data: 'ssh', product: 'OpenSSH' },
    ],
  });
  const out = JSON.parse(await run('ip_lookup', { ip: '1.1.1.1', history: true }));
  assert.equal(out['IP Information'].OS, 'Linux');
  assert.deepEqual(out.Vulnerabilities, { Count: 2, CVEs: ['CVE-2020-1', 'CVE-2021-2'] });
  const s80 = out.Services[0];
  assert.equal(s80.Service, 'new');
  assert.equal(s80.Product, 'nginx');
  assert.equal(s80.Version, '1.2');
  assert.deepEqual(s80.CPE, ['cpe:2.3:a:nginx:nginx:1.2']);
  assert.deepEqual(s80.Vulnerabilities, ['CVE-9-1', 'CVE-9-2']);
  assert.ok(!('Vulnerabilities' in out.Services[1]));
  // One row per port/transport/product/version, ports ascending, newest version first.
  assert.deepEqual(out['Banner History'], [
    { Port: 22, Transport: 'tcp', Product: 'OpenSSH', Version: 'Unknown',
      'First Seen': '2024-01-01T00:00:00', 'Last Seen': '2024-01-01T00:00:00', Observations: 1 },
    { Port: 80, Transport: 'tcp', Product: 'nginx', Version: '1.2',
      'First Seen': '2024-06-01T00:00:00', 'Last Seen': '2024-06-01T00:00:00', Observations: 1 },
    { Port: 80, Transport: 'tcp', Product: 'nginx', Version: '1.0',
      'First Seen': '2023-01-01T00:00:00', 'Last Seen': '2023-01-01T00:00:00', Observations: 1 },
  ]);
});

test('ip_lookup history merges repeated banners into first/last seen ranges', async (t) => {
  const banner = (ts, version) => ({ port: 22, transport: 'tcp', timestamp: ts, product: 'OpenSSH', version });
  mockGet(t, {
    ip_str: '1.1.1.1', ports: [22],
    data: [
      banner('2024-03-01T00:00:00', '8.0'), banner('2024-01-01T00:00:00', '7.4'),
      banner('2024-05-01T00:00:00', '8.0'), banner('2023-06-01T00:00:00', '7.4'),
      banner('2024-02-01T00:00:00', '7.4'),
    ],
  });
  const out = JSON.parse(await run('ip_lookup', { ip: '1.1.1.1', history: true }));
  assert.deepEqual(out['Banner History'], [
    { Port: 22, Transport: 'tcp', Product: 'OpenSSH', Version: '8.0',
      'First Seen': '2024-03-01T00:00:00', 'Last Seen': '2024-05-01T00:00:00', Observations: 2 },
    { Port: 22, Transport: 'tcp', Product: 'OpenSSH', Version: '7.4',
      'First Seen': '2023-06-01T00:00:00', 'Last Seen': '2024-02-01T00:00:00', Observations: 3 },
  ]);
});

test('ip_lookup defaults: no history key, OS Unknown, no vulns, minify without banners', async (t) => {
  mockGet(t, { ip_str: '1.1.1.1', ports: [80, 443] });
  const out = JSON.parse(await run('ip_lookup', { ip: '1.1.1.1', minify: true }));
  assert.equal(out['IP Information'].OS, 'Unknown');
  assert.equal(out.Vulnerabilities, 'None reported');
  assert.ok(!('Banner History' in out));
  assert.deepEqual(out.Services.map((s) => s.Port), [80, 443]);
  assert.equal(out.Services[0].Service, 'No banner');
});

test('CVSS v4 is shown when CVEDB has it, before v3 and v2', async (t) => {
  const cve = { cve_id: 'CVE-2026-3497', published_time: '2026-01-01', summary: 's', cpes: [], references: [],
    cvss_v4: 6.9, cvss_v3: 7.5, cvss_v2: null };
  mockGet(t, (url, config) => config?.params?.count ? { total: 1 } : { ...cve, cves: [cve] });
  for (const out of [
    JSON.parse(await run('cve_lookup', { cve: 'CVE-2026-3497' }))['Severity Scores'],
    JSON.parse(await run('cves_by_product', { product: 'openssh', limit: 1 })).Vulnerabilities[0]['Severity Scores'],
  ]) {
    assert.deepEqual(Object.keys(out), ['CVSS v4', 'CVSS v3', 'CVSS v2', 'EPSS']);
    assert.deepEqual(out['CVSS v4'], { Score: 6.9, Severity: 'Medium' });
    assert.deepEqual(out['CVSS v3'], { Score: 7.5, Severity: 'High' });
  }
});

test('CVSS v4 reads "Not available" when absent', async (t) => {
  mockGet(t, { cve_id: 'CVE-2021-44228', published_time: '2021-12-10', summary: 's', cpes: [], references: [], cvss_v3: 10 });
  const out = JSON.parse(await run('cve_lookup', { cve: 'CVE-2021-44228' }));
  assert.equal(out['Severity Scores']['CVSS v4'], 'Not available');
});
