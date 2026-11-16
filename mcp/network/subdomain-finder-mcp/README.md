# subdomain-finder-mcp

Passive subdomain finder for AI assistants: live certificate transparency lookups (certspotter, crt.sh) with DNS checks over Cloudflare DNS over HTTPS.

This is a Model Context Protocol (MCP) server for subdomain enumeration in bug bounty and security recon. It reads public certificate transparency (CT) logs, deduplicates the names, handles wildcard certificates, and reports first seen, last seen and issuer for each host. It can then resolve the hosts to mark which are live and which have dangling CNAMEs. It needs no API key.

## Passive and read-only

- It only reads public CT logs and public DNS. It sends nothing to the target's servers.
- No port scanning, no HTTP probing, no brute-force wordlists.
- Use it on domains you own or are authorised to test, for example inside a bug bounty program's scope.

## Tools

| Tool | What it returns |
| --- | --- |
| `find_subdomains` | Deduplicated hostnames for a domain from CT logs, with first seen, last seen, valid until, certificate count, issuers and a wildcard flag. Optional DNS check of up to 40 names. |
| `resolve_subdomains` | A, AAAA and CNAME chain for up to 40 hosts. Marks live, NXDOMAIN, no records and dangling CNAMEs, names cloud services behind CNAMEs, and detects wildcard DNS. |
| `get_certificate_history` | Certificates for one host: issuer, validity dates, every SAN, revocation status and SHA-256, plus first and latest issuance and the issuers used. |
| `summarize_attack_surface` | The domain's CT hostnames grouped into development and test, staging, admin, API, auth, mail, remote access, storage and legacy, with naming clusters, issuers and the newest names. |

Every result has structured JSON, a one-paragraph summary, `as_of`, `source` (the CT or DNS query URL) and `more` (the matching tool on [bugbountyreality.com](https://bugbountyreality.com/?utm_source=mcp&utm_medium=subdomain-finder-mcp)).

## What it knows that your model does not

- A domain's current subdomains. New hosts appear in CT logs within minutes of getting a certificate; a model's training data is months old and never had most of them.
- Which hosts resolve right now, which CNAMEs point at a deleted cloud resource, and whether the zone has wildcard DNS.
- Certificate history: when each name first got a certificate, which CAs issued it, and when the current one expires.
- How to read CT data cleanly: precertificate and certificate rows merged, e-mail SANs and out-of-scope names dropped, `*.` entries reported as wildcards instead of hosts.

## Install

### Hosted (Claude.ai custom connector, ChatGPT developer mode)

Paste this URL. No token, no sign-up.

```
https://subdomain-finder-mcp.lipmichal.workers.dev/mcp
```

### Claude Code

```
claude mcp add --transport http subdomain-finder https://subdomain-finder-mcp.lipmichal.workers.dev/mcp
```

Or run it locally over stdio:

```
claude mcp add subdomain-finder -- npx -y github:theluckystrike/subdomain-finder-mcp
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "subdomain-finder": { "command": "npx", "args": ["-y", "github:theluckystrike/subdomain-finder-mcp"] }
  }
}
```

### Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "subdomain-finder": { "url": "https://subdomain-finder-mcp.lipmichal.workers.dev/mcp" }
  }
}
```

### VS Code

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "subdomain-finder": { "type": "http", "url": "https://subdomain-finder-mcp.lipmichal.workers.dev/mcp" }
  }
}
```

Node 20 or newer is needed for the local stdio version. The local version uses your own IP for the CT and DNS lookups, so it has its own rate-limit allowance.

## Example prompts

- "Find subdomains of hackerone.com from certificate transparency and tell me which are live."
- "Which of these hosts have dangling CNAMEs: assets.example.com, docs.example.com, status.example.com?"
- "Show the certificate history for api.example.com. Did they change CA this year?"
- "Summarise the attack surface of example.com. Any staging, admin or VPN hosts?"
- "Include expired certificates and list hosts under example.com that first appeared before 2020."

## Data sources

All public and keyless. Full list with fetch dates in [DATA_SOURCES.md](DATA_SOURCES.md).

- SSLMate certspotter CT Search API (api.certspotter.com), unexpired certificates. Primary.
- crt.sh, including expired certificates. Fallback, and used when `include_expired` is true.
- Cloudflare DNS over HTTPS (cloudflare-dns.com/dns-query).

## Limitations

- Certificate transparency only shows names that got a publicly trusted certificate. Hosts behind a wildcard certificate (`*.example.com`) or with no TLS never appear by name. Pair it with other passive sources for full coverage.
- certspotter's keyless tier is rate limited per IP (`x-ratelimit-limit: 10` observed). Results are cached for an hour, the tool reads at most 5 pages per call, and it falls back to crt.sh when certspotter throttles. If both throttle, the error says to wait a few minutes.
- crt.sh is often slow or overloaded, and two calls minutes apart can return different rows (its database replicas lag). Calls time out after 25 seconds, retry once, then fail with a clear message.
- Very large domains return the first pages only; the result says when it was truncated.
- DNS checks are capped at 40 hosts per call. A "dangling CNAME" is a lead to verify inside an authorised scope, not proof of a vulnerability.

## More

The web versions of these tools, a subdomain takeover checker and a manual recon checklist are on [bugbountyreality.com](https://bugbountyreality.com/tools/subdomain-finder-real/?utm_source=mcp&utm_medium=subdomain-finder-mcp). See also the [certificate transparency lookup](https://bugbountyreality.com/tools/certificate-transparency-lookup/?utm_source=mcp&utm_medium=subdomain-finder-mcp) and the [subdomain enumeration checklist](https://bugbountyreality.com/tools/subdomain-enumeration-checklist-manual-recon-guide?utm_source=mcp&utm_medium=subdomain-finder-mcp).

Part of the Zovo MCP collection: https://mcp.zovo.one

## Development

```
npm install
npm test            # builds, then runs the fixture tests against saved CT and DNS payloads
node scripts/smoke-stdio.mjs   # live stdio check, one real call per tool
npx wrangler deploy            # Cloudflare Worker, Streamable HTTP at /mcp
```

## License

MIT

<!-- data-servers:start -->
## More data servers from the same author

Each one is free, needs no API key and has a hosted URL you can paste into Claude or ChatGPT.

| server | tools | hosted URL |
|---|---|---|
| [cups-to-grams-mcp](https://github.com/theluckystrike/cups-to-grams-mcp) | convert_ingredient, search_ingredients, scale_recipe, convert_oven_temperature | `https://cups-to-grams-mcp.lipmichal.workers.dev/mcp` |
| [dscr-loan-calculator-mcp](https://github.com/theluckystrike/dscr-loan-calculator-mcp) | calculate_dscr, max_loan_for_target_dscr, rent_needed_for_target_dscr, compare_scenarios, amortization_summary | `https://dscr-loan-calculator-mcp.lipmichal.workers.dev/mcp` |
| [gold-price-per-gram-mcp](https://github.com/theluckystrike/gold-price-per-gram-mcp) | get_gold_price_per_gram, get_metal_prices, calculate_jewelry_value, convert_gold_units | `https://gold-price-per-gram-mcp.lipmichal.workers.dev/mcp` |
| [lake-level-mcp](https://github.com/theluckystrike/lake-level-mcp) | search_lakes, get_lake_level, get_lake_history, compare_lakes | `https://lake-level-mcp.lipmichal.workers.dev/mcp` |
| [minimum-wage-mcp](https://github.com/theluckystrike/minimum-wage-mcp) | get_minimum_wage, list_upcoming_increases, compare_states, annual_income_at_minimum_wage | `https://minimum-wage-mcp.lipmichal.workers.dev/mcp` |
| [no-tax-on-overtime-mcp](https://github.com/theluckystrike/no-tax-on-overtime-mcp) | calculate_overtime_deduction, calculate_tips_deduction, calculate_senior_deduction, estimate_tax_savings, explain_eligibility | `https://no-tax-on-overtime-mcp.lipmichal.workers.dev/mcp` |
| [paycheck-calculator-mcp](https://github.com/theluckystrike/paycheck-calculator-mcp) | calculate_take_home_pay, compare_states_take_home, salary_to_hourly, hourly_to_salary, get_federal_tax_brackets | `https://paycheck-calculator-mcp.lipmichal.workers.dev/mcp` |
| [uk-income-tax-salary-mcp](https://github.com/theluckystrike/uk-income-tax-salary-mcp) | calculate_uk_take_home, get_uk_tax_bands, compare_salaries, marginal_rate_at_income | `https://uk-income-tax-salary-mcp.lipmichal.workers.dev/mcp` |
| [us-federal-holidays-business-days-mcp](https://github.com/theluckystrike/us-federal-holidays-business-days-mcp) | list_federal_holidays, is_business_day, add_business_days, count_business_days, invoice_due_date | `https://us-federal-holidays-business-days-mcp.lipmichal.workers.dev/mcp` |
| [ab-test-sample-size-calculator-mcp](https://github.com/theluckystrike/ab-test-sample-size-calculator-mcp) | calculate_sample_size, estimate_test_duration, test_ab_significance, fisher_exact_test, check_peeking_risk | `https://ab-test-sample-size-calculator-mcp.lipmichal.workers.dev/mcp` |
| [aca-premium-tax-credit-calculator-mcp](https://github.com/theluckystrike/aca-premium-tax-credit-calculator-mcp) | get_federal_poverty_level, calculate_premium_tax_credit, check_subsidy_cliff, get_aptc_repayment_cap | `https://aca-premium-tax-credit-calculator-mcp.lipmichal.workers.dev/mcp` |
| [ap-score-distributions-mcp](https://github.com/theluckystrike/ap-score-distributions-mcp) | get_ap_score_distribution, estimate_ap_percentile, compare_ap_exams, list_ap_exams, estimate_ap_score_from_composite | `https://ap-score-distributions-mcp.lipmichal.workers.dev/mcp` |
| [car-loan-interest-deduction-calculator-mcp](https://github.com/theluckystrike/car-loan-interest-deduction-calculator-mcp) | calculate_car_loan_interest_deduction, calculate_salt_deduction, get_tax_brackets_and_standard_deduction, calculate_child_tax_credit | `https://car-loan-interest-deduction-calculator-mcp.lipmichal.workers.dev/mcp` |
| [estate-gift-tax-exemption-calculator-mcp](https://github.com/theluckystrike/estate-gift-tax-exemption-calculator-mcp) | get_exemption_amounts, calculate_estate_tax, check_gift, compare_years | `https://estate-gift-tax-exemption-calculator-mcp.lipmichal.workers.dev/mcp` |
| [recipe-nutrition-calculator-mcp](https://github.com/theluckystrike/recipe-nutrition-calculator-mcp) | lookup_ingredient_nutrition, calculate_recipe_nutrition, round_nutrition_label, scale_recipe_nutrition | `https://recipe-nutrition-calculator-mcp.lipmichal.workers.dev/mcp` |
| [retirement-contribution-limits-2027-mcp](https://github.com/theluckystrike/retirement-contribution-limits-2027-mcp) | get_contribution_limits, calculate_max_contribution, get_social_security_cola, compare_years | `https://retirement-contribution-limits-2027-mcp.lipmichal.workers.dev/mcp` |
| [section-179-deduction-calculator-mcp](https://github.com/theluckystrike/section-179-deduction-calculator-mcp) | calculate_section_179, calculate_bonus_depreciation, get_vehicle_depreciation_limits, calculate_asset_loan_payment | `https://section-179-deduction-calculator-mcp.lipmichal.workers.dev/mcp` |
| [student-loan-repayment-assistance-plan-calculator-mcp](https://github.com/theluckystrike/student-loan-repayment-assistance-plan-calculator-mcp) | calculate_rap_payment, compare_rap_vs_standard, get_federal_loan_limits, get_plan_transition_dates | `https://student-loan-repayment-assistance-plan-calculator-mcp.lipmichal.workers.dev/mcp` |
| [uk-statutory-sick-pay-maternity-pay-calculator-mcp](https://github.com/theluckystrike/uk-statutory-sick-pay-maternity-pay-calculator-mcp) | calculate_statutory_sick_pay, calculate_statutory_maternity_pay, get_minimum_wage_rates, check_eligibility | `https://uk-statutory-sick-pay-maternity-pay-calculator-mcp.lipmichal.workers.dev/mcp` |

The paid back-office collection (invoices, VAT, PDFs, spreadsheets) is at https://mcp.zovo.one
<!-- data-servers:end -->

## More from zovo

- [All free zovo VS Code extensions](https://marketplace.visualstudio.com/publishers/zovo) - file viewers, database clients, formatters. Offline, no telemetry, no sign-up.
- [Full MCP server catalogue](https://theluckystrike.github.io/mcp/) - local-first MCP servers for back-office work: invoices, VAT, PDFs, spreadsheets, payroll.
- [Hosted no-install MCP endpoints](https://mcp.zovo.one) - paste a URL in Claude / Cursor, nothing to install.
