export const REPO = 'subdomain-finder-mcp';
export const SITE = 'https://bugbountyreality.com';
export const UTM = `utm_source=mcp&utm_medium=${REPO}`;
export const more = (path) => `${SITE}${path}?${UTM}`;
export const PAGES = {
    finder: more('/tools/subdomain-finder-real/'),
    ct: more('/tools/certificate-transparency-lookup/'),
    takeover: more('/tools/subdomain-takeover-checker/'),
    dns: more('/tools/dns-lookup-tool/'),
    checklist: more('/tools/subdomain-enumeration-checklist-manual-recon-guide'),
};
export const CERTSPOTTER = 'https://api.certspotter.com/v1/issuances';
export const CRTSH = 'https://crt.sh/';
export const DOH = 'https://cloudflare-dns.com/dns-query';
export const MAX_LIMIT = 1000;
export const MAX_RESOLVE = 40;
export const MAX_PAGES = 5;
/** Upstream requests one tool call may make. Cloudflare's free Workers plan allows 50 subrequests. */
export const REQUEST_BUDGET = 46;
export class InputError extends Error {
}
export class UpstreamError extends Error {
    throttled;
    retryAfter;
    constructor(message, throttled = false, retryAfter = null) {
        super(message);
        this.throttled = throttled;
        this.retryAfter = retryAfter;
    }
}
// ---------------------------------------------------------------- names
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
/** Accepts "example.com", "https://Example.com/path", "*.example.com." and returns "example.com". */
export function normalizeDomain(input) {
    let s = String(input ?? '').trim().toLowerCase();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
    s = s.replace(/^\*\./, '').replace(/^%\./, '');
    if (!s)
        throw new InputError('Give a domain name such as example.com.');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(':'))
        throw new InputError(`"${input}" is an IP address. Certificate transparency is searched by domain name.`);
    const labels = s.split('.');
    if (labels.length < 2)
        throw new InputError(`"${input}" is not a domain name. Use a registered domain such as example.com.`);
    if (s.length > 253 || !labels.every((l) => LABEL.test(l)))
        throw new InputError(`"${input}" is not a valid domain name.`);
    if (/^\d+$/.test(labels.at(-1)))
        throw new InputError(`"${input}" has a numeric top-level label.`);
    return s;
}
/** Cleans one CT name. Returns null for e-mail addresses, IPs and junk. */
export function cleanName(raw) {
    let s = raw.trim().toLowerCase().replace(/\.$/, '');
    if (!s || s.includes('@') || s.includes(' '))
        return null;
    let wildcard = false;
    if (s.startsWith('*.')) {
        wildcard = true;
        s = s.slice(2);
    }
    if (s.includes('*'))
        return null;
    const labels = s.split('.');
    if (labels.length < 2 || !labels.every((l) => LABEL.test(l)))
        return null;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s))
        return null;
    return { name: s, wildcard };
}
export const inScope = (name, domain) => name === domain || name.endsWith(`.${domain}`);
const day = (s) => (s ? String(s).slice(0, 10) : '');
// ---------------------------------------------------------------- upstream parsers
export function certspotterUrl(domain, after, includeSubdomains = true) {
    const q = new URLSearchParams({ domain });
    if (includeSubdomains)
        q.set('include_subdomains', 'true');
    else
        q.set('match_wildcards', 'true');
    q.append('expand', 'dns_names');
    q.append('expand', 'issuer');
    if (after)
        q.set('after', after);
    return `${CERTSPOTTER}?${q.toString()}`;
}
export function crtshUrl(domain, includeExpired, includeSubdomains = true) {
    const q = `${includeSubdomains ? '%25.' : ''}${domain}`;
    return `${CRTSH}?q=${q}&output=json${includeExpired ? '' : '&exclude=expired'}`;
}
function issuerOrg(dn) {
    const m = /(?:^|,\s*)O=("([^"]+)"|[^,]+)/.exec(dn);
    const org = m ? (m[2] ?? m[1]).trim() : '';
    if (org)
        return org;
    const cn = /(?:^|,\s*)CN=([^,]+)/.exec(dn);
    return cn ? cn[1].trim() : dn || 'unknown';
}
export function parseCertspotter(text) {
    const rows = JSON.parse(text);
    if (!Array.isArray(rows))
        throw new UpstreamError(`certspotter answered with ${String(rows?.code ?? 'an unexpected body')}: ${String(rows?.message ?? '').slice(0, 160)}`);
    return rows.map((r) => ({
        id: String(r.id),
        source: 'certspotter',
        dns_names: Array.isArray(r.dns_names) ? r.dns_names.map(String) : [],
        issuer: String(r.issuer?.friendly_name || issuerOrg(String(r.issuer?.name ?? ''))),
        issuer_dn: String(r.issuer?.name ?? ''),
        not_before: day(r.not_before),
        not_after: day(r.not_after),
        revoked: typeof r.revoked === 'boolean' ? r.revoked : null,
        sha256: r.cert_sha256 ? String(r.cert_sha256) : null,
    }));
}
/** crt.sh lists the precertificate and the certificate as two rows; they share a serial and issuer. */
export function parseCrtsh(text) {
    const rows = JSON.parse(text);
    if (!Array.isArray(rows))
        throw new UpstreamError('crt.sh returned an unexpected body.');
    const byKey = new Map();
    for (const r of rows) {
        const key = `${r.issuer_ca_id}|${r.serial_number ?? r.id}`;
        const names = String(r.name_value ?? '').split('\n').concat(r.common_name ? [String(r.common_name)] : []);
        const prev = byKey.get(key);
        if (prev) {
            for (const n of names)
                if (!prev.dns_names.includes(n))
                    prev.dns_names.push(n);
            continue;
        }
        const dn = String(r.issuer_name ?? '');
        byKey.set(key, {
            id: String(r.id),
            source: 'crtsh',
            dns_names: [...new Set(names)],
            issuer: issuerOrg(dn),
            issuer_dn: dn,
            not_before: day(r.not_before),
            not_after: day(r.not_after),
            revoked: null,
            sha256: null,
        });
    }
    return [...byKey.values()];
}
export const newBudget = (n = REQUEST_BUDGET) => ({ left: n });
async function get(fetcher, budget, url, timeoutMs, cacheTtl, accept = 'application/json') {
    if (budget.left <= 0)
        throw new UpstreamError('request budget for this call is used up');
    budget.left--;
    return fetcher(url, { timeoutMs, cacheTtl, accept });
}
function throttleMessage(host, r) {
    const wait = r.retryAfter ? ` It asks to wait ${r.retryAfter} seconds.` : '';
    return `${host} is rate limiting this IP (HTTP ${r.status}).${wait}`;
}
export async function fetchCertspotter(fetcher, budget, domain, maxPages, includeSubdomains = true) {
    const certs = [];
    let after;
    let pages = 0;
    let truncated = false;
    const first = certspotterUrl(domain, undefined, includeSubdomains);
    for (;;) {
        const url = certspotterUrl(domain, after, includeSubdomains);
        const r = await get(fetcher, budget, url, 12000, 3600);
        if (r.status === 429) {
            if (pages === 0)
                throw new UpstreamError(throttleMessage('certspotter (api.certspotter.com)', r), true, r.retryAfter);
            truncated = true;
            break;
        }
        if (r.status >= 400) {
            let msg = `HTTP ${r.status}`;
            try {
                const j = JSON.parse(r.text);
                if (j?.message)
                    msg += `: ${j.message}`;
            }
            catch { /* not JSON */ }
            if (r.status === 400)
                throw new InputError(`certspotter rejected "${domain}" (${msg}). Use a registered domain such as example.com.`);
            throw new UpstreamError(`certspotter answered ${msg}`);
        }
        const page = parseCertspotter(r.text);
        pages++;
        if (!page.length)
            break;
        certs.push(...page);
        after = page.at(-1).id;
        if (pages >= maxPages) {
            truncated = true;
            break;
        }
    }
    return {
        certs, source: 'certspotter', source_url: first, pages, truncated,
        notes: ['certspotter lists unexpired certificates only. Use source "crtsh" with include_expired for older names.'],
    };
}
export async function fetchCrtsh(fetcher, budget, domain, includeExpired, includeSubdomains = true) {
    const url = crtshUrl(domain, includeExpired, includeSubdomains);
    let r = null;
    for (let attempt = 0; attempt < 2; attempt++) {
        r = await get(fetcher, budget, url, 25000, 3600);
        if (r.status === 200 || r.status === 429 || (r.status >= 400 && r.status < 500 && r.status !== 404))
            break;
        if (attempt === 0)
            await new Promise((res) => setTimeout(res, 1200));
    }
    if (!r)
        throw new UpstreamError('crt.sh did not answer');
    if (r.status === 429)
        throw new UpstreamError(throttleMessage('crt.sh', r), true, r.retryAfter);
    if (r.status !== 200)
        throw new UpstreamError(`crt.sh answered HTTP ${r.status} twice (it is often overloaded; try again in a minute)`);
    if (/^\s*</.test(r.text))
        throw new UpstreamError('crt.sh returned an HTML error page instead of JSON');
    return {
        certs: parseCrtsh(r.text), source: 'crtsh', source_url: url, pages: 1, truncated: false,
        notes: includeExpired ? ['crt.sh results include expired certificates, so some names may be retired.'] : ['crt.sh results exclude expired certificates.'],
    };
}
/** auto: certspotter first (fast, reliable from Cloudflare); crt.sh when certspotter fails or throttles. */
export async function fetchCt(fetcher, budget, domain, o) {
    const sub = o.includeSubdomains ?? true;
    const wantCrtsh = o.source === 'crtsh' || (o.source === 'auto' && o.includeExpired);
    if (wantCrtsh) {
        try {
            return await fetchCrtsh(fetcher, budget, domain, o.includeExpired, sub);
        }
        catch (e) {
            if (o.source === 'crtsh' || e instanceof InputError)
                throw e;
            const r = await fetchCertspotter(fetcher, budget, domain, o.maxPages, sub);
            r.notes.unshift(`crt.sh failed (${e.message}); fell back to certspotter, which has unexpired certificates only.`);
            return r;
        }
    }
    try {
        return await fetchCertspotter(fetcher, budget, domain, o.maxPages, sub);
    }
    catch (e) {
        if (o.source === 'certspotter' || e instanceof InputError)
            throw e;
        try {
            const r = await fetchCrtsh(fetcher, budget, domain, false, sub);
            r.notes.unshift(`certspotter failed (${e.message}); fell back to crt.sh.`);
            return r;
        }
        catch (e2) {
            const throttled = e.throttled || e2.throttled;
            throw new UpstreamError(`Both certificate transparency sources failed. certspotter: ${e.message} crt.sh: ${e2.message}` +
                (throttled ? ' Wait a few minutes before asking again; the results are cached for an hour once fetched.' : ''), throttled);
        }
    }
}
// ---------------------------------------------------------------- aggregation
export function aggregateSubdomains(certs, domain) {
    const map = new Map();
    const wild = new Set();
    let outOfScope = 0;
    for (const c of certs) {
        const counted = new Set();
        for (const raw of c.dns_names) {
            const n = cleanName(raw);
            if (!n)
                continue;
            if (!inScope(n.name, domain)) {
                outOfScope++;
                continue;
            }
            if (n.wildcard)
                wild.add(`*.${n.name}`);
            const key = n.name;
            let row = map.get(key);
            if (!row) {
                row = { name: key, first_seen: c.not_before, last_seen: c.not_before, valid_until: c.not_after, cert_count: 0, issuers: [], wildcard_cert: false, _issuers: new Set() };
                map.set(key, row);
            }
            if (!counted.has(key)) {
                counted.add(key);
                row.cert_count++;
                if (c.not_before && (!row.first_seen || c.not_before < row.first_seen))
                    row.first_seen = c.not_before;
                if (c.not_before > row.last_seen)
                    row.last_seen = c.not_before;
                if (c.not_after > row.valid_until)
                    row.valid_until = c.not_after;
                row._issuers.add(c.issuer);
            }
            if (n.wildcard)
                row.wildcard_cert = true;
        }
    }
    const rows = [...map.values()].map(({ _issuers, ...r }) => ({ ...r, issuers: [..._issuers].sort() }));
    rows.sort((a, b) => sortKey(a.name).localeCompare(sortKey(b.name)));
    return { rows, wildcards: [...wild].sort(), outOfScope };
}
/** Sort by reversed labels so siblings group together: api.eu.x.com next to web.eu.x.com. */
const sortKey = (n) => n.split('.').reverse().join('.');
// ---------------------------------------------------------------- DNS over HTTPS
/** CNAME targets on hosted platforms. A dangling CNAME to one of these is a classic takeover lead. */
export const THIRD_PARTY = [
    ['s3.amazonaws.com', 'AWS S3'], ['s3-website', 'AWS S3 website'], ['elasticbeanstalk.com', 'AWS Elastic Beanstalk'],
    ['cloudfront.net', 'AWS CloudFront'], ['amazonaws.com', 'AWS'], ['herokuapp.com', 'Heroku'], ['herokudns.com', 'Heroku'],
    ['github.io', 'GitHub Pages'], ['azurewebsites.net', 'Azure App Service'], ['cloudapp.net', 'Azure Cloud Services'],
    ['cloudapp.azure.com', 'Azure VM'], ['trafficmanager.net', 'Azure Traffic Manager'], ['blob.core.windows.net', 'Azure Blob Storage'],
    ['azureedge.net', 'Azure CDN'], ['azurefd.net', 'Azure Front Door'], ['netlify.app', 'Netlify'], ['netlify.com', 'Netlify'],
    ['vercel.app', 'Vercel'], ['vercel-dns.com', 'Vercel'], ['pages.dev', 'Cloudflare Pages'], ['workers.dev', 'Cloudflare Workers'],
    ['fastly.net', 'Fastly'], ['myshopify.com', 'Shopify'], ['ghost.io', 'Ghost'], ['helpscoutdocs.com', 'Help Scout'],
    ['readme.io', 'ReadMe'], ['surge.sh', 'Surge'], ['bitbucket.io', 'Bitbucket'], ['wordpress.com', 'WordPress.com'],
    ['pantheonsite.io', 'Pantheon'], ['zendesk.com', 'Zendesk'], ['statuspage.io', 'Statuspage'], ['unbouncepages.com', 'Unbounce'],
    ['fly.dev', 'Fly.io'], ['onrender.com', 'Render'], ['firebaseapp.com', 'Firebase'], ['web.app', 'Firebase'], ['appspot.com', 'Google App Engine'],
];
export function thirdParty(target) {
    const t = target.toLowerCase().replace(/\.$/, '');
    for (const [suffix, name] of THIRD_PARTY)
        if (t === suffix || t.endsWith(`.${suffix}`) || (suffix.startsWith('s3-') && t.includes(suffix)))
            return name;
    return null;
}
export const dohUrl = (name, type) => `${DOH}?name=${encodeURIComponent(name)}&type=${type}`;
/** Builds one DnsRow from the A answer and an optional AAAA answer. */
export function classifyDns(host, a, aaaa) {
    const ans = [...(a.Answer ?? []), ...(aaaa?.Answer ?? [])];
    const cname = [];
    for (const x of ans)
        if (x.type === 5) {
            const d = x.data.replace(/\.$/, '').toLowerCase();
            if (!cname.includes(d))
                cname.push(d);
        }
    const v4 = [...new Set((a.Answer ?? []).filter((x) => x.type === 1).map((x) => x.data))];
    const v6 = [...new Set((aaaa?.Answer ?? []).filter((x) => x.type === 28).map((x) => x.data))];
    const tp = cname.length ? thirdParty(cname.at(-1)) : null;
    const row = { host, status: 'no_records', a: v4, aaaa: v6, cname_chain: cname, third_party: tp, note: null };
    if (v4.length || v6.length)
        row.status = 'live';
    else if (a.Status === 3 && cname.length) {
        row.status = 'dangling_cname';
        row.note = `CNAME to ${cname.at(-1)}${tp ? ` (${tp})` : ''}, which does not exist (NXDOMAIN). If the service account was deleted, this host may be claimable; check it only within an authorised program scope.`;
    }
    else if (a.Status === 3)
        row.status = 'nxdomain';
    else if (a.Status !== 0) {
        row.status = 'error';
        row.note = `resolver status ${a.Status} (${a.Status === 2 ? 'SERVFAIL' : a.Status === 5 ? 'REFUSED' : 'see RFC 6895'})`;
    }
    else if (cname.length)
        row.note = `CNAME to ${cname.at(-1)} with no address records.`;
    return row;
}
async function doh(fetcher, budget, name, type) {
    const r = await get(fetcher, budget, dohUrl(name, type), 6000, 300, 'application/dns-json');
    if (r.status !== 200)
        throw new UpstreamError(`DNS over HTTPS answered HTTP ${r.status}`, r.status === 429, r.retryAfter);
    return JSON.parse(r.text);
}
export async function resolveHost(fetcher, budget, host) {
    if (budget.left <= 0)
        return { host, status: 'skipped', a: [], aaaa: [], cname_chain: [], third_party: null, note: 'request budget for this call used up; ask again for the remaining hosts' };
    try {
        const a = await doh(fetcher, budget, host, 'A');
        let aaaa = null;
        const hasA = (a.Answer ?? []).some((x) => x.type === 1);
        if (a.Status === 0 && !hasA && budget.left > 0)
            aaaa = await doh(fetcher, budget, host, 'AAAA');
        return classifyDns(host, a, aaaa);
    }
    catch (e) {
        return { host, status: 'error', a: [], aaaa: [], cname_chain: [], third_party: null, note: e.message };
    }
}
export async function mapLimit(items, n, fn) {
    const out = new Array(items.length);
    let i = 0;
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
        while (i < items.length) {
            const k = i++;
            out[k] = await fn(items[k]);
        }
    }));
    return out;
}
/** One lookup of a random label: if it resolves, the zone has wildcard DNS and "live" means little. */
export async function wildcardProbe(fetcher, budget, domain, rand = Math.random) {
    const probe = `zz-${Math.floor(rand() * 1e12).toString(36)}-nx.${domain}`;
    if (budget.left <= 0)
        return null;
    try {
        const a = await doh(fetcher, budget, probe, 'A');
        const answers = (a.Answer ?? []).filter((x) => x.type === 1 || x.type === 5).map((x) => x.data);
        return { wildcard_dns: answers.length > 0, probe, answers };
    }
    catch {
        return null;
    }
}
export function tallyDns(rows) {
    const t = { live: 0, no_records: 0, nxdomain: 0, dangling_cname: 0, error: 0, skipped: 0 };
    for (const r of rows)
        t[r.status]++;
    return t;
}
// ---------------------------------------------------------------- attack surface grouping
export const CATEGORIES = [
    { key: 'dev_test', label: 'Development and test', why: 'Pre-production hosts often run debug builds, default credentials or older code.', words: ['dev', 'develop', 'development', 'test', 'testing', 'tst', 'qa', 'uat', 'sandbox', 'sbx', 'demo', 'preview', 'preprod', 'beta', 'alpha', 'canary', 'lab', 'labs', 'poc', 'sit', 'int', 'nonprod'] },
    { key: 'staging', label: 'Staging', why: 'Staging mirrors production with weaker controls.', words: ['stage', 'staging', 'stg', 'stag'] },
    { key: 'admin_internal', label: 'Admin and internal tools', why: 'Consoles and internal apps exposed by name; confirm they are in scope before touching them.', words: ['admin', 'administrator', 'internal', 'intranet', 'corp', 'manage', 'management', 'console', 'dashboard', 'cpanel', 'panel', 'backoffice', 'ops', 'jenkins', 'grafana', 'kibana', 'prometheus', 'git', 'gitlab', 'jira', 'confluence', 'vault', 'argocd', 'sonar', 'nexus', 'portainer', 'phpmyadmin'] },
    { key: 'api', label: 'APIs', why: 'API hosts are where most access-control and IDOR findings live.', words: ['api', 'apis', 'graphql', 'gateway', 'gw', 'rest', 'ws', 'websocket', 'webhook', 'webhooks', 'rpc', 'grpc', 'backend'] },
    { key: 'auth', label: 'Authentication', why: 'Login, SSO and identity hosts; check redirect and token handling.', words: ['auth', 'sso', 'login', 'signin', 'oauth', 'id', 'identity', 'accounts', 'account', 'okta', 'adfs', 'idp', 'iam', 'passport', 'cas'] },
    { key: 'mail', label: 'Mail', why: 'Mail and autodiscover hosts reveal the mail stack.', words: ['mail', 'smtp', 'imap', 'pop', 'pop3', 'mx', 'webmail', 'autodiscover', 'email', 'owa', 'exchange'] },
    { key: 'remote_access', label: 'Remote access', why: 'VPN and remote gateways are high-value perimeter devices with public CVE history.', words: ['vpn', 'remote', 'citrix', 'rdp', 'ssh', 'bastion', 'jump', 'sslvpn', 'fortinet', 'pulse', 'globalprotect', 'anyconnect'] },
    { key: 'storage_cdn', label: 'Storage and CDN', why: 'Asset and upload hosts often CNAME to cloud storage; check for dangling records.', words: ['cdn', 'static', 'assets', 'media', 'img', 'images', 'files', 'file', 's3', 'storage', 'upload', 'uploads', 'download', 'downloads', 'content', 'blob'] },
    { key: 'legacy', label: 'Legacy and backup', why: 'Old and backup hosts are often unpatched or forgotten.', words: ['old', 'legacy', 'archive', 'backup', 'bak', 'deprecated', 'v1', 'classic', 'temp', 'tmp'] },
];
export function categorize(name, domain) {
    const rel = name === domain ? '' : name.slice(0, -(domain.length + 1));
    if (!rel)
        return [];
    const tokens = new Set(rel.split(/[.\-_]/).flatMap((t) => [t, t.replace(/\d+$/, '')]).filter(Boolean));
    return CATEGORIES.filter((c) => c.words.some((w) => tokens.has(w))).map((c) => c.key);
}
export function surface(rows, domain, examples = 15) {
    const groups = CATEGORIES.map((c) => ({ key: c.key, label: c.label, why: c.why, count: 0, examples: [] }));
    const byKey = new Map(groups.map((g) => [g.key, g]));
    const parents = new Map();
    let maxDepth = 0;
    let uncategorized = 0;
    for (const r of rows) {
        const cats = categorize(r.name, domain);
        if (!cats.length && r.name !== domain)
            uncategorized++;
        for (const k of cats) {
            const g = byKey.get(k);
            g.count++;
            if (g.examples.length < examples)
                g.examples.push(r.name);
        }
        const depth = r.name === domain ? 0 : r.name.slice(0, -(domain.length + 1)).split('.').length;
        maxDepth = Math.max(maxDepth, depth);
        if (depth >= 2) {
            const p = r.name.split('.').slice(1).join('.');
            parents.set(p, (parents.get(p) ?? 0) + 1);
        }
    }
    const issuers = new Map();
    for (const r of rows)
        for (const i of r.issuers)
            issuers.set(i, (issuers.get(i) ?? 0) + 1);
    return {
        groups: groups.filter((g) => g.count > 0).sort((a, b) => b.count - a.count),
        uncategorized,
        max_depth: maxDepth,
        clusters: [...parents.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([parent, count]) => ({ parent, count })),
        issuers: [...issuers.entries()].sort((a, b) => b[1] - a[1]).map(([issuer, names]) => ({ issuer, names })),
    };
}
export function recentRows(rows, n = 10) {
    return [...rows].sort((a, b) => b.first_seen.localeCompare(a.first_seen)).slice(0, n);
}
export const plural = (n, w, p = `${w}s`) => `${n} ${n === 1 ? w : p}`;
