export class ScopeError extends Error {
  constructor(msg) {
    super(msg);
    this.name = "ScopeError";
  }
}

export class Scope {
  constructor(rules) {
    this.rules = rules.map(parseRule);
  }

  static fromEnv(varName) {
    const raw = process.env[varName];
    if (!raw || !raw.trim()) return new Scope([]);
    return new Scope(raw.split(",").map((s) => s.trim()).filter(Boolean));
  }

  isEmpty() {
    return this.rules.length === 0;
  }

  allowsUrl(url) {
    if (this.isEmpty()) return false;
    let host;
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      return false;
    }
    return this.rules.some((r) => ruleMatches(r, host));
  }

  assertAllowsUrl(url) {
    if (this.isEmpty()) {
      throw new ScopeError("MCP_FFUF_SCOPE is empty — refusing all runs");
    }
    if (!this.allowsUrl(url)) {
      throw new ScopeError(`URL host not in scope: ${url}`);
    }
  }

  describe() {
    return this.rules.map((r) => r.raw);
  }
}

function parseRule(raw) {
  if (raw.startsWith("*.")) {
    return { raw, kind: "wildcard", suffix: raw.slice(1).toLowerCase() };
  }
  return { raw, kind: "host", host: raw.toLowerCase() };
}

function ruleMatches(rule, host) {
  if (rule.kind === "host") return host === rule.host;
  if (rule.kind === "wildcard") return host.endsWith(rule.suffix);
  return false;
}
