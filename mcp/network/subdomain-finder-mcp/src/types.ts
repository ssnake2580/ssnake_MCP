export interface FetchOpts {
  accept?: string;
  timeoutMs?: number;
  /** Seconds the edge or memory cache may reuse a 2xx answer. */
  cacheTtl?: number;
}

/** Raw HTTP answer. Fetchers throw only on network failure or timeout, never on a status code. */
export interface HttpResult {
  status: number;
  text: string;
  retryAfter: string | null;
}

export type Fetcher = (url: string, opts?: FetchOpts) => Promise<HttpResult>;

/** One certificate issuance, normalised from certspotter or crt.sh. */
export interface Cert {
  id: string;
  source: 'certspotter' | 'crtsh';
  dns_names: string[];
  issuer: string;
  issuer_dn: string;
  not_before: string; // YYYY-MM-DD
  not_after: string; // YYYY-MM-DD
  revoked: boolean | null;
  sha256: string | null;
}

export interface SubdomainRow {
  name: string;
  first_seen: string;
  last_seen: string;
  valid_until: string;
  cert_count: number;
  issuers: string[];
  wildcard_cert: boolean;
}

export interface DnsRow {
  host: string;
  status: 'live' | 'no_records' | 'nxdomain' | 'dangling_cname' | 'error' | 'skipped';
  a: string[];
  aaaa: string[];
  cname_chain: string[];
  third_party: string | null;
  note: string | null;
}
