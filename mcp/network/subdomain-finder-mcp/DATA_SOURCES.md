# Data sources

Every hostname and certificate this server returns is read at call time from the public services below.
Nothing is stored. Fetch dates are the dates each source was fetched and checked for this build.

## Live sources (keyless, public)

| Service | Endpoint | Used for | Fetched |
| --- | --- | --- | --- |
| SSLMate certspotter CT Search API v1 | https://api.certspotter.com/v1/issuances?domain=bugbountyreality.com&include_subdomains=true&expand=dns_names&expand=issuer | Primary source. Unexpired certificate issuances for a domain and its subdomains: SANs, issuer, not_before, not_after, revocation, SHA-256. Paged with `after=<last id>`. Keyless; the response carried `x-ratelimit-limit: 10`. | 2026-11-02 |
| certspotter API reference | https://sslmate.com/help/reference/ct_search_api_v1 | Field meanings; "list all unexpired certificate issuances"; `match_wildcards`; paging until an empty page | 2026-11-02 |
| crt.sh (Sectigo) | https://crt.sh/?q=%25.abwex.com&output=json (and `&exclude=expired`) | Fallback, and the source for expired certificates (`include_expired`). One row per log entry; the precertificate and certificate rows are merged by issuer and serial. It answered 502 and 404 to some queries on 2026-11-02, so the server retries once and then falls back. | 2026-11-02 |
| Cloudflare DNS over HTTPS (JSON) | https://cloudflare-dns.com/dns-query?name=www.hackerone.com&type=A | A, AAAA and CNAME lookups, NXDOMAIN (Status 3) detection, wildcard DNS probe | 2026-11-02 |
| Cloudflare DoH JSON format | https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/ | Response shape (`Status`, `Answer[].type` 1 = A, 5 = CNAME, 28 = AAAA) | 2026-11-02 |

## Reference lists

- Cloud services whose dangling CNAMEs are known takeover leads: https://github.com/EdOverflow/can-i-take-over-xyz
  (README fetched 2026-11-02). The server only names the service behind a CNAME target; it does not claim a host is
  vulnerable. Many listed services are no longer exploitable; check the list before reporting.
- The attack-surface groups (dev, staging, admin, API, auth, mail, VPN, storage, legacy) are keyword lists in
  `src/core.ts`, the same groups as the bugbountyreality.com subdomain enumeration checklist:
  https://bugbountyreality.com/tools/subdomain-enumeration-checklist-manual-recon-guide

## Test fixtures

Saved in `test/fixtures/` on 2026-11-02 from the endpoints above:

- `certspotter-bugbountyreality.json`: first page for bugbountyreality.com (11 issuances).
- `crtsh-example.json`: crt.sh `%.example.com`, all certificates (85 rows, 49 certificates).
- `crtsh-abwex.json`: crt.sh `%.abwex.com` (25 rows, 15 certificates).
- `doh-*.json`: Cloudflare DoH answers for a live host, a CNAME chain (www.github.com), an NXDOMAIN, a NODATA
  answer and a wildcard zone (github.io).

The dangling-CNAME case uses a hand-built answer in the same JSON shape, because no real dangling record was
used for testing.

## Cross-check

The expected host counts, first and last seen dates, certificate counts and issuers in `test/core.test.mjs`
were computed a second time by `scripts/xcheck_ct.py`, a separate Python script that shares no code with
`src/core.ts` (run: `python3 scripts/xcheck_ct.py test/fixtures/crtsh-example.json example.com`). Both agree: example.com 7 hosts, 12 out-of-scope SANs, www.example.com 15 certificates
from 2014-11-06 to 2025-12-02; abwex.com 12 certificates, www.abwex.com 3.
