import axios from "axios";
import { UserError } from "fastmcp";
import { z } from "zod";
import type { ShodanSsl } from "./types.js";

export const API_BASE_URL = "https://api.shodan.io";
export const CVEDB_API_URL = "https://cvedb.shodan.io";
export const SHODAN_API_KEY = process.env.SHODAN_API_KEY!;

export async function queryShodan(endpoint: string, params: Record<string, any>) {
  try {
    const response = await axios.get(`${API_BASE_URL}${endpoint}`, {
      params: { ...params, key: SHODAN_API_KEY },
      timeout: 10000,
    });
    return response.data;
  } catch (error: any) {
    const errorMessage = error.response?.data?.error || error.message;
    console.error(`Shodan API error: ${errorMessage}`);
    throw new UserError(`Shodan API error: ${errorMessage}`);
  }
}

export async function queryCVEDB(cveId: string) {
  try {
    const response = await axios.get(`${CVEDB_API_URL}/cve/${encodeURIComponent(cveId)}`, {
      timeout: 10000,
    });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new UserError(`Invalid CVE ID format: ${cveId}`);
    }
    if (error.response?.status === 404) {
      throw new UserError(`CVE not found: ${cveId}`);
    }
    throw new UserError(`CVEDB API error: ${error.message}`);
  }
}

export async function queryCPEDB(params: {
  product: string;
  count?: boolean;
  skip?: number;
  limit?: number;
}) {
  try {
    const response = await axios.get(`${CVEDB_API_URL}/cpes`, { params, timeout: 10000 });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new UserError(`Invalid parameters: ${error.response.data?.detail || error.message}`);
    }
    throw new UserError(`CVEDB API error: ${error.message}`);
  }
}

export async function queryCVEsByProduct(params: {
  cpe23?: string;
  product?: string;
  count?: boolean;
  is_kev?: boolean;
  sort_by_epss?: boolean;
  skip?: number;
  limit?: number;
  start_date?: string;
  end_date?: string;
}) {
  try {
    const response = await axios.get(`${CVEDB_API_URL}/cves`, { params, timeout: 10000 });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new UserError(`Invalid parameters: ${error.response.data?.detail || error.message}`);
    }
    throw new UserError(`CVEDB API error: ${error.message}`);
  }
}

// CVEDB's ranking_epss is a percentile (1.0 = highest EPSS of all scored CVEs).
export function formatEpss(epss: number | null | undefined, rankingEpss: number | null | undefined) {
  if (!epss) return "Not available";
  const percentile = ((rankingEpss ?? 0) * 100).toFixed(2);
  return {
    Score: `${(epss * 100).toFixed(2)}%`,
    Percentile: `${percentile} (higher than ${percentile}% of scored CVEs)`,
  };
}

export const MAX_CVE_CPES = 50;

export function getCvssSeverity(score: number): string {
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score >= 0.1) return "Low";
  return "None";
}

function formatCertSerial(serial: number | string | undefined): string {
  if (serial == null) return "Unknown";
  if (typeof serial === "string") return serial;
  // Shodan sends large serials as integers; by the time they arrive through
  // JSON parsing the low-order digits may already be lost. Render as a plain
  // decimal string (no scientific notation); use the SHA-256 fingerprint for
  // exact matching.
  try {
    return BigInt(serial).toString();
  } catch {
    return String(serial);
  }
}

export function formatSslSummary(ssl: ShodanSsl) {
  const cert = ssl.cert || {};
  return {
    "Subject CN": cert.subject?.CN || "Unknown",
    "Issuer CN": cert.issuer?.CN || "Unknown",
    Serial: formatCertSerial(cert.serial),
    "SHA-256 Fingerprint":
      cert.fingerprint?.sha256 || ssl.chain_sha256?.[0] || "Unknown",
    "Signature Algorithm": cert.sig_alg || "Unknown",
    "Public Key": cert.pubkey?.type
      ? `${cert.pubkey.type} ${cert.pubkey.bits || "?"}-bit`
      : "Unknown",
    Issued: cert.issued || "Unknown",
    Expires: cert.expires || "Unknown",
    Expired:
      cert.expired == null ? "Unknown" : cert.expired ? "Yes" : "No",
    "TLS Versions": (ssl.versions || []).filter(
      (version) => !version.startsWith("-")
    ),
    Cipher: ssl.cipher?.name
      ? `${ssl.cipher.name} (${ssl.cipher.bits || "?"}-bit)`
      : "Unknown",
    JARM: ssl.jarm || "Not available",
    JA3S: ssl.ja3s || "Not available",
  };
}

export const FACETS_REGEX = /^[a-z0-9_.]+(:\d{1,4})?(,[a-z0-9_.]+(:\d{1,4})?)*$/i;

export const facetsSchema = z
  .string()
  .regex(FACETS_REGEX, "Invalid facets format. Use e.g. 'country:10,org,port'.");

export function formatFacets(
  facets: Record<string, Array<{ value?: string | number; count?: number }>> | undefined,
  total: number | undefined
) {
  const out: Record<string, Array<{ Value: string | number; Count: number; Percentage: string }>> = {};
  for (const [name, entries] of Object.entries(facets || {})) {
    out[name] = (Array.isArray(entries) ? entries : []).map((e) => {
      const count = e.count ?? 0;
      const pct = total && total > 0 ? (count / total) * 100 : 0;
      return { Value: e.value ?? "Unknown", Count: count, Percentage: `${pct.toFixed(2)}%` };
    });
  }
  return out;
}

export function sortedCveIds(vulns: unknown): string[] {
  if (Array.isArray(vulns)) return vulns.map(String).sort();
  if (vulns && typeof vulns === "object") return Object.keys(vulns).sort();
  return [];
}
