// Tool registry shared by the stdio and Worker entries.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { DOH, InputError, MAX_LIMIT, MAX_PAGES, MAX_RESOLVE, PAGES, REPO, SITE, UpstreamError, aggregateSubdomains, cleanName, fetchCt, inScope, mapLimit, newBudget, normalizeDomain, plural, recentRows, resolveHost, surface, tallyDns, wildcardProbe, } from './core.js';
export const VERSION = '1.0.0';
export const TOOL_INFO = [
    { name: 'find_subdomains', blurb: 'Passive subdomain list for a domain from certificate transparency logs (certspotter, crt.sh fallback): deduplicated, wildcards marked, first and last seen, issuers. Optional DNS check.' },
    { name: 'resolve_subdomains', blurb: 'DNS over HTTPS (Cloudflare) A, AAAA and CNAME for up to 40 hosts. Marks live, NXDOMAIN and dangling CNAMEs to cloud services. Detects wildcard DNS.' },
    { name: 'get_certificate_history', blurb: 'Certificates logged for one host: issuer, validity dates, SANs, revocation, SHA-256, with first and last issuance.' },
    { name: 'summarize_attack_surface', blurb: 'Groups a domain\'s CT subdomains into dev/test, staging, admin, API, auth, mail, VPN, storage and legacy, with clusters, issuer mix and the newest names.' },
];
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
function ok(data) {
    return { content: [{ type: 'text', text: `${data.summary}\n\n${JSON.stringify(data, null, 2)}` }], structuredContent: data };
}
function fail(e) {
    const msg = e instanceof Error ? e.message : String(e);
    const prefix = e instanceof InputError ? 'Error' : e instanceof UpstreamError && e.throttled ? 'Upstream rate limit' : 'Upstream error';
    return { isError: true, content: [{ type: 'text', text: `${prefix}: ${msg} The web version is at ${PAGES.finder}` }] };
}
const domainArg = z.string().min(3).max(253).describe('Registered domain, for example "example.com". A URL is accepted and reduced to its host.');
const sourceArg = z.enum(['auto', 'certspotter', 'crtsh']).default('auto')
    .describe('auto = certspotter first (fast, unexpired certificates), crt.sh if it fails or throttles. crtsh = crt.sh only (includes expired with include_expired).');
const expiredArg = z.boolean().default(false).describe('Also include names from expired certificates (uses crt.sh). Finds retired hosts; slower.');
const AUTH = 'Passive lookup of public certificate transparency logs; nothing is sent to the target. Use it on assets you own or are authorised to test.';
export function createServer(fetcher) {
    const server = new McpServer({ name: REPO, version: VERSION, websiteUrl: SITE }, {
        instructions: 'Live, passive subdomain discovery from certificate transparency logs (certspotter, crt.sh) plus DNS over HTTPS via Cloudflare. ' +
            'No port scans and no requests to the target. A model cannot know a domain\'s current subdomains from training data; call find_subdomains, then resolve_subdomains for the hosts that matter. ' +
            'For authorised recon only (bug bounty scope, your own assets).',
    });
    server.registerTool('find_subdomains', {
        title: 'Find subdomains (certificate transparency)',
        description: 'Passive subdomain enumeration for a domain from live certificate transparency logs: certspotter (unexpired certificates) with crt.sh as fallback or for expired history. ' +
            'Returns deduplicated hostnames with first seen and last seen issuance dates, certificate count, issuers and whether a wildcard certificate covers the name, plus the list of wildcard entries. ' +
            'Set resolve=true to also check the first 40 names with DNS over HTTPS and mark live hosts. ' + AUTH,
        inputSchema: {
            domain: domainArg,
            source: sourceArg,
            include_expired: expiredArg,
            limit: z.number().int().min(1).max(MAX_LIMIT).default(200).describe(`Max hostnames returned (1-${MAX_LIMIT}). Totals are always reported.`),
            resolve: z.boolean().default(false).describe(`Also resolve up to ${MAX_RESOLVE} of the returned names over DNS (newest first).`),
            max_pages: z.number().int().min(1).max(MAX_PAGES).default(3).describe(`certspotter pages to read (1-${MAX_PAGES}). Each page is one request against its keyless rate limit.`),
        },
        annotations: { title: 'Find subdomains', ...RO },
    }, async ({ domain, source, include_expired, limit, resolve, max_pages }) => {
        try {
            const d = normalizeDomain(domain);
            const budget = newBudget();
            const ct = await fetchCt(fetcher, budget, d, { source: source ?? 'auto', includeExpired: include_expired ?? false, maxPages: max_pages ?? 3 });
            const { rows, wildcards, outOfScope } = aggregateSubdomains(ct.certs, d);
            const lim = limit ?? 200;
            const shown = rows.slice(0, lim);
            let dns = null;
            if (resolve && shown.length) {
                const pick = recentRows(shown, MAX_RESOLVE).map((r) => r.name);
                const probe = await wildcardProbe(fetcher, budget, d);
                const res = await mapLimit(pick, 8, (h) => resolveHost(fetcher, budget, h));
                const byHost = new Map(res.map((r) => [r.host, r]));
                for (const r of shown) {
                    const x = byHost.get(r.name);
                    if (x)
                        r.dns = { status: x.status, a: x.a, aaaa: x.aaaa, cname_chain: x.cname_chain, third_party: x.third_party };
                }
                dns = { checked: res.length, tally: tallyDns(res), wildcard_dns: probe?.wildcard_dns ?? null, resolver: DOH,
                    dangling: res.filter((r) => r.status === 'dangling_cname').map((r) => ({ host: r.host, cname: r.cname_chain.at(-1), third_party: r.third_party })) };
            }
            const t = dns?.tally;
            const summary = `${plural(rows.length, 'unique hostname')} under ${d} in ${plural(ct.certs.length, 'certificate')} from ${ct.source === 'certspotter' ? 'certspotter' : 'crt.sh'}` +
                `${ct.truncated ? ` (first ${plural(ct.pages, 'page')} only; raise max_pages for more)` : ''}. ` +
                (wildcards.length ? `${plural(wildcards.length, 'wildcard entry', 'wildcard entries')} (${wildcards.slice(0, 3).join(', ')}${wildcards.length > 3 ? ', ...' : ''}), so some hosts will never appear in CT. ` : '') +
                (rows.length ? `Newest: ${recentRows(rows, 5).map((r) => `${r.name} (${r.first_seen})`).join(', ')}. ` : 'No names found; the domain may use only wildcard or no public certificates, or CT data may be lagging. ') +
                (dns ? `DNS: ${t.live} live, ${t.nxdomain} NXDOMAIN, ${t.no_records} with no records, ${t.dangling_cname} dangling CNAME${dns.wildcard_dns ? '; the zone has wildcard DNS so "live" is not conclusive' : ''}. ` : '') +
                (rows.length > lim ? `Showing ${lim} of ${rows.length}. ` : '') + ct.notes.join(' ');
            return ok({
                domain: d, source: ct.source_url, ct_source: ct.source, certificates: ct.certs.length, pages_read: ct.pages, truncated: ct.truncated,
                total: rows.length, returned: shown.length, wildcards, out_of_scope_names_skipped: outOfScope, subdomains: shown, dns,
                notes: ct.notes, as_of: new Date().toISOString(), more: PAGES.finder, summary,
            });
        }
        catch (e) {
            return fail(e);
        }
    });
    server.registerTool('resolve_subdomains', {
        title: 'Resolve subdomains (DNS over HTTPS)',
        description: `Resolve up to ${MAX_RESOLVE} hostnames now through Cloudflare DNS over HTTPS (A, AAAA and the CNAME chain). ` +
            'Each host is marked live, nxdomain, no_records or dangling_cname (a CNAME whose target does not exist, a subdomain takeover lead), and CNAME targets on cloud platforms (S3, Azure, Heroku, GitHub Pages, Netlify, Vercel and others) are named. ' +
            'Also probes a random label per parent domain to detect wildcard DNS. DNS lookups only; no connection is made to the hosts.',
        inputSchema: {
            hosts: z.array(z.string().min(3).max(253)).min(1).max(MAX_RESOLVE).describe(`Hostnames, for example ["www.example.com", "api.example.com"]. Max ${MAX_RESOLVE}.`),
            check_wildcard: z.boolean().default(true).describe('Probe one random label under each parent domain (max 3) to detect wildcard DNS.'),
        },
        annotations: { title: 'Resolve subdomains', ...RO },
    }, async ({ hosts, check_wildcard }) => {
        try {
            const clean = [];
            const rejected = [];
            for (const h of hosts) {
                let n = null;
                try {
                    n = cleanName(normalizeDomain(h));
                }
                catch {
                    n = null;
                }
                if (n && !clean.includes(n.name))
                    clean.push(n.name);
                else if (!n)
                    rejected.push(h);
            }
            if (!clean.length)
                throw new InputError(`No valid hostnames in ${JSON.stringify(hosts.slice(0, 5))}.`);
            const budget = newBudget();
            const parents = [...new Set(clean.map((h) => h.split('.').slice(-2).join('.')))].slice(0, 3);
            const probes = check_wildcard ?? true ? await Promise.all(parents.map((p) => wildcardProbe(fetcher, budget, p))) : [];
            const rows = await mapLimit(clean, 8, (h) => resolveHost(fetcher, budget, h));
            const t = tallyDns(rows);
            const wild = probes.filter((p) => p?.wildcard_dns).map((p) => p.probe.split('.').slice(1).join('.'));
            const dangling = rows.filter((r) => r.status === 'dangling_cname');
            const summary = `${plural(rows.length, 'host')} checked over DNS: ${t.live} live, ${t.nxdomain} NXDOMAIN, ${t.no_records} with no address records, ${t.dangling_cname} dangling CNAME${t.error ? `, ${t.error} errors` : ''}${t.skipped ? `, ${t.skipped} skipped` : ''}. ` +
                (dangling.length ? `Takeover leads: ${dangling.map((r) => `${r.host} -> ${r.cname_chain.at(-1)}${r.third_party ? ` (${r.third_party})` : ''}`).join('; ')}. Verify only inside an authorised scope. ` : '') +
                (wild.length ? `Wildcard DNS on ${wild.join(', ')}: any name there resolves, so "live" is not proof the host exists. ` : '') +
                (rejected.length ? `Skipped invalid input: ${rejected.join(', ')}.` : '');
            return ok({
                results: rows, tally: t, wildcard_dns: probes.filter(Boolean), rejected, resolver: DOH,
                source: DOH, as_of: new Date().toISOString(), more: dangling.length ? PAGES.takeover : PAGES.dns, summary,
            });
        }
        catch (e) {
            return fail(e);
        }
    });
    server.registerTool('get_certificate_history', {
        title: 'Get certificate history for a host',
        description: 'Certificates logged in certificate transparency for one hostname (or a whole domain with include_subdomains): issuer organisation and DN, not_before and not_after dates, every SAN on the certificate, revocation status and SHA-256 where certspotter has them. ' +
            'Summarises first and last issuance and the issuers used, which shows CA changes and renewal cadence. Default source certspotter (unexpired); include_expired uses crt.sh for the full history.',
        inputSchema: {
            host: domainArg.describe('Hostname, for example "api.example.com" or "example.com".'),
            include_subdomains: z.boolean().default(false).describe('Also include certificates for names under the host.'),
            source: sourceArg,
            include_expired: expiredArg,
            limit: z.number().int().min(1).max(100).default(25).describe('Max certificates returned, newest first (1-100).'),
        },
        annotations: { title: 'Certificate history', ...RO },
    }, async ({ host, include_subdomains, source, include_expired, limit }) => {
        try {
            const h = normalizeDomain(host);
            const sub = include_subdomains ?? false;
            const ct = await fetchCt(fetcher, newBudget(), h, { source: source ?? 'auto', includeExpired: include_expired ?? false, maxPages: 2, includeSubdomains: sub });
            const match = (c) => c.dns_names.some((n) => { const x = cleanName(n); return !!x && (sub ? inScope(x.name, h) : x.name === h || (x.wildcard && h.endsWith(`.${x.name}`) && h.split('.').length === x.name.split('.').length + 1)); });
            const certs = ct.certs.filter(match).sort((a, b) => b.not_before.localeCompare(a.not_before));
            const shown = certs.slice(0, limit ?? 25);
            const issuers = new Map();
            for (const c of certs)
                issuers.set(c.issuer, (issuers.get(c.issuer) ?? 0) + 1);
            const first = certs.at(-1)?.not_before ?? null;
            const last = certs[0]?.not_before ?? null;
            const today = new Date().toISOString().slice(0, 10);
            const valid = certs.filter((c) => c.not_after >= today && c.not_before <= today && c.revoked !== true);
            const summary = certs.length
                ? `${plural(certs.length, 'certificate')} for ${h}${sub ? ' and its subdomains' : ''} from ${ct.source === 'certspotter' ? 'certspotter' : 'crt.sh'}: first issued ${first}, latest ${last}, ${valid.length} valid today. ` +
                    `Issuers: ${[...issuers.entries()].map(([k, v]) => `${k} (${v})`).join(', ')}. ${ct.notes.join(' ')}`
                : `No certificates logged for ${h}${ct.source === 'certspotter' ? ' among unexpired certificates' : ''}. It may be covered only by a wildcard on its parent, or use no public certificate. ${ct.notes.join(' ')}`;
            return ok({
                host: h, include_subdomains: sub, ct_source: ct.source, total: certs.length, returned: shown.length, first_issued: first, last_issued: last,
                valid_today: valid.length, issuers: [...issuers.entries()].map(([issuer, count]) => ({ issuer, count })), certificates: shown,
                notes: ct.notes, source: ct.source_url, as_of: new Date().toISOString(), more: PAGES.ct, summary,
            });
        }
        catch (e) {
            return fail(e);
        }
    });
    server.registerTool('summarize_attack_surface', {
        title: 'Summarize attack surface from CT',
        description: 'Reads a domain\'s subdomains from live certificate transparency and groups them for recon triage: development and test, staging, admin and internal tools, APIs, authentication, mail, remote access (VPN), storage and CDN, legacy and backup. ' +
            'Each group has a count, examples and why it matters. Also returns naming clusters (for example *.eu.example.com), certificate issuers in use, wildcard entries and the 10 newest names. Passive only.',
        inputSchema: { domain: domainArg, source: sourceArg, include_expired: expiredArg },
        annotations: { title: 'Attack surface summary', ...RO },
    }, async ({ domain, source, include_expired }) => {
        try {
            const d = normalizeDomain(domain);
            const ct = await fetchCt(fetcher, newBudget(), d, { source: source ?? 'auto', includeExpired: include_expired ?? false, maxPages: 3 });
            const { rows, wildcards } = aggregateSubdomains(ct.certs, d);
            const s = surface(rows, d);
            const newest = recentRows(rows, 10).map((r) => ({ name: r.name, first_seen: r.first_seen }));
            const summary = rows.length
                ? `${plural(rows.length, 'hostname')} under ${d} from ${ct.source === 'certspotter' ? 'certspotter' : 'crt.sh'}. ` +
                    (s.groups.length ? `Groups: ${s.groups.map((g) => `${g.label.toLowerCase()} ${g.count}`).join(', ')}; ${s.uncategorized} uncategorised. ` : `No names match the dev, admin, API or other groups; ${s.uncategorized} uncategorised. `) +
                    (wildcards.length ? `${plural(wildcards.length, 'wildcard entry', 'wildcard entries')} hide further hosts from CT. ` : '') +
                    `Issuers: ${s.issuers.slice(0, 4).map((i) => i.issuer).join(', ')}. Newest: ${newest.slice(0, 4).map((n) => n.name).join(', ')}. ${ct.notes.join(' ')}`
                : `No subdomains found in certificate transparency for ${d}. ${ct.notes.join(' ')}`;
            return ok({
                domain: d, ct_source: ct.source, total: rows.length, ...s, wildcards, newest, truncated: ct.truncated,
                notes: ct.notes, source: ct.source_url, as_of: new Date().toISOString(), more: PAGES.checklist, summary,
            });
        }
        catch (e) {
            return fail(e);
        }
    });
    return server;
}
