// Cloudflare Worker entry: stateless Streamable HTTP at /mcp, no auth, no KV, no Durable Objects.
// CT answers are cached at the edge for an hour (2xx only) so repeat calls do not spend the keyless rate limits.
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { createServer, TOOL_INFO, VERSION } from './tools.js';
import { fetchRaw } from './fetch-node.js';
import { PAGES, REPO, SITE, UTM } from './core.js';
import type { Fetcher } from './types.js';

const fetchEdge: Fetcher = (url, opts = {}) =>
  fetchRaw(url, opts, { cf: { cacheTtlByStatus: { '200-299': opts.cacheTtl ?? 300, '300-599': 0 }, cacheEverything: true } } as RequestInit);

const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID',
  'Access-Control-Expose-Headers': 'Mcp-Session-Id, Mcp-Protocol-Version',
};

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));

function home(origin: string): Response {
  const url = `${origin}/mcp`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${REPO}</title><meta name="description" content="MCP server for passive subdomain enumeration from certificate transparency logs (certspotter, crt.sh) with DNS over HTTPS checks.">
<style>body{font:16px/1.55 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1d2731;background:#fff}code,pre{background:#f1f4f7;border-radius:4px}pre{padding:.7rem;overflow-x:auto}code{padding:0 .25rem}td{padding:.3rem .5rem;vertical-align:top;border-bottom:1px solid #e3e8ee}a{color:#0b5cad}</style></head><body>
<h1>${REPO}</h1>
<p>Live, passive subdomain discovery for AI assistants. Names come from public certificate transparency logs (certspotter, with crt.sh as fallback); optional DNS checks go through Cloudflare DNS over HTTPS. No port scans and no requests to the target. Use it on assets you own or are authorised to test. Version ${VERSION}.</p>
<h2>Tools</h2><table>${TOOL_INFO.map((t) => `<tr><td><code>${t.name}</code></td><td>${esc(t.blurb)}</td></tr>`).join('')}</table>
<h2>Connect</h2>
<p>Hosted endpoint (Streamable HTTP, no token, no sign-up). Paste it into a Claude.ai custom connector or ChatGPT developer mode:</p>
<pre>${url}</pre>
<p>Claude Code:</p><pre>claude mcp add --transport http subdomain-finder ${url}</pre>
<p>Local stdio (Node 20+):</p><pre>npx -y github:theluckystrike/${REPO}</pre>
<p>Source and install notes for Cursor and VS Code: <a href="https://github.com/theluckystrike/${REPO}">github.com/theluckystrike/${REPO}</a></p>
<p>Recon checklists, the subdomain takeover checker and more bug bounty tools are on <a href="${SITE}/?${UTM}">bugbountyreality.com</a> (<a href="${PAGES.finder}">web subdomain finder</a>).</p>
<p>Part of the Zovo MCP collection: <a href="https://mcp.zovo.one">https://mcp.zovo.one</a></p>
</body></html>`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=3600' } });
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (url.pathname === '/' && request.method === 'GET') return home(url.origin);
    if (url.pathname === '/health') return Response.json({ ok: true, name: REPO, version: VERSION });
    if (url.pathname !== '/mcp' && url.pathname !== '/mcp/') return new Response('Not found. The MCP endpoint is /mcp', { status: 404 });
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed. This stateless server accepts POST only.' }, id: null }), {
        status: 405, headers: { 'content-type': 'application/json', Allow: 'POST, OPTIONS', ...CORS },
      });
    }
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    const server = createServer(fetchEdge);
    await server.connect(transport);
    const res = await transport.handleRequest(request);
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(CORS)) headers.set(k, v);
    return new Response(res.body, { status: res.status, headers });
  },
};
