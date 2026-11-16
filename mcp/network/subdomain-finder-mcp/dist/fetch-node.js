const UA = 'subdomain-finder-mcp/1.0 (+https://github.com/theluckystrike/subdomain-finder-mcp)';
const cache = new Map();
const MAX_ENTRIES = 300;
export async function fetchRaw(url, opts, init = {}) {
    const ac = new AbortController();
    const ms = opts.timeoutMs ?? 12000;
    const timer = setTimeout(() => ac.abort(), ms);
    try {
        const res = await fetch(url, {
            ...init,
            redirect: 'follow',
            signal: ac.signal,
            headers: { 'User-Agent': UA, Accept: opts.accept ?? 'application/json' },
        });
        const text = await res.text();
        return { status: res.status, text, retryAfter: res.headers.get('retry-after') };
    }
    catch (e) {
        if (e.name === 'AbortError')
            throw new Error(`${new URL(url).host} gave no answer within ${Math.round(ms / 1000)} s`);
        throw new Error(`${new URL(url).host} unreachable: ${e.message}`);
    }
    finally {
        clearTimeout(timer);
    }
}
export const fetchNode = async (url, opts = {}) => {
    const hit = cache.get(url);
    if (hit && Date.now() - hit.at < hit.ttl * 1000)
        return hit.res;
    const res = await fetchRaw(url, opts);
    if (res.status >= 200 && res.status < 300 && opts.cacheTtl) {
        if (cache.size >= MAX_ENTRIES)
            cache.delete(cache.keys().next().value);
        cache.set(url, { at: Date.now(), ttl: opts.cacheTtl, res });
    }
    return res;
};
