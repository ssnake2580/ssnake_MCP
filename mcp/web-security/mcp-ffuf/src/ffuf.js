import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { access } from "node:fs/promises";
import { constants as FS } from "node:fs";

const execFileP = promisify(execFile);

const CODE_LIST = /^[\d,]+$/;

async function validateWordlist(path) {
  if (!path || typeof path !== "string") throw new Error("wordlist path required");
  if (!path.startsWith("/")) throw new Error("wordlist path must be absolute");
  try {
    await access(path, FS.R_OK);
  } catch {
    throw new Error(`wordlist not readable: ${path}`);
  }
  return path;
}

function validateCodeList(v, field) {
  if (v == null) return null;
  if (!CODE_LIST.test(v)) throw new Error(`${field} must be comma-separated HTTP codes, e.g. '200,301,401'`);
  return v;
}

function validateExtensions(v) {
  if (v == null) return null;
  if (!/^[\w.,-]+$/.test(v)) throw new Error("extensions must be comma-separated, e.g. '.php,.asp,.html'");
  return v;
}

async function runFfuf(args, { timeoutMs }) {
  args.push("-of", "json", "-o", "-", "-s");
  const { stdout } = await execFileP("ffuf", args, {
    timeout: timeoutMs,
    maxBuffer: 32 * 1024 * 1024,
  });
  return parseResults(stdout);
}

function parseResults(out) {
  const trimmed = out.trim();
  if (!trimmed) return { results: [] };
  try {
    return JSON.parse(trimmed);
  } catch {
    return { results: [], raw: trimmed.slice(0, 4000) };
  }
}

function assertFuzz(url) {
  if (!url.includes("FUZZ")) throw new Error("URL must contain the literal token FUZZ");
}

const POLITE = ["-t", "10", "-rate", "20", "-timeout", "10", "-maxtime", "60"];

export async function fuzzPath({ url, wordlist, extensions, match_codes, filter_codes, timeoutMs = 75_000 }) {
  assertFuzz(url);
  const wl = await validateWordlist(wordlist);
  const mc = validateCodeList(match_codes, "match_codes");
  const fc = validateCodeList(filter_codes, "filter_codes");
  const exts = validateExtensions(extensions);

  const args = ["-u", url, "-w", wl, ...POLITE];
  if (exts) args.push("-e", exts);
  if (mc) args.push("-mc", mc);
  if (fc) args.push("-fc", fc);
  return runFfuf(args, { timeoutMs });
}

export async function fuzzParameter({ url, wordlist, match_codes, filter_codes, timeoutMs = 75_000 }) {
  assertFuzz(url);
  const wl = await validateWordlist(wordlist);
  const mc = validateCodeList(match_codes, "match_codes");
  const fc = validateCodeList(filter_codes, "filter_codes");

  const args = ["-u", url, "-w", wl, ...POLITE];
  if (mc) args.push("-mc", mc);
  if (fc) args.push("-fc", fc);
  return runFfuf(args, { timeoutMs });
}

export async function fuzzVhost({ url, wordlist, match_codes, filter_codes, timeoutMs = 75_000 }) {
  const wl = await validateWordlist(wordlist);
  const mc = validateCodeList(match_codes, "match_codes");
  const fc = validateCodeList(filter_codes, "filter_codes");
  const host = new URL(url).hostname;

  const args = ["-u", url, "-H", `Host: FUZZ.${host}`, "-w", wl, ...POLITE];
  if (mc) args.push("-mc", mc);
  if (fc) args.push("-fc", fc);
  return runFfuf(args, { timeoutMs });
}

export const __test__ = { validateWordlist, validateCodeList, validateExtensions, parseResults };
