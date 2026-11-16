# Tool reference

Eleven tools in three groups. Every tool is read-only and returns pretty-printed JSON text.

Each tool has a sample of real output, captured on 2026-10-12 against public targets such as [scanme.nmap.org](http://scanme.nmap.org/). Long lists are cut to a few entries and marked `… N more`, and long strings end in `…`. The real output is complete.

| Tool | Backend | Spends Shodan query credits? |
|---|---|---|
| `ip_lookup` | Shodan REST API | No |
| `shodan_search` | Shodan REST API | Yes: 1 if the query uses filters, plus 1 per page after the first |
| `shodan_count` | Shodan REST API | No |
| `domain_info` | Shodan REST API | Yes: 1 per call |
| `dns_lookup` | Shodan REST API | No |
| `reverse_dns_lookup` | Shodan REST API | No |
| `cve_lookup` | Shodan CVEDB | No (CVEDB is free and keyless) |
| `cpe_lookup` | Shodan CVEDB | No |
| `cves_by_product` | Shodan CVEDB | No |
| `search_filters` | Shodan REST API | No |
| `api_info` | Shodan REST API | No |

## Network reconnaissance

### `ip_lookup`

Everything Shodan has seen on one host: owner, location, open ports with banners, HTTP and TLS details, cloud provider, hostnames and tags.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `ip` | string | yes | | IPv4 or IPv6 address. Anything else is rejected before a request is made. |
| `history` | boolean | no | `false` | Include every banner Shodan has recorded for the host, not only the latest. |
| `minify` | boolean | no | `false` | Ports and host details only, no banners. Smaller and faster. |

Returns:

- **IP Information:** address, organization, ISP, ASN, OS, last update.
- **Location:** country, city, region, coordinates.
- **Vulnerabilities:** CVE IDs Shodan associates with the host, with a count. Look them up with `cve_lookup`.
- **Services:** one entry per open port (the latest banner) with transport, product, version, CPEs, banner, per-service CVEs, HTTP server and title, and a TLS summary (subject and issuer CN, serial, SHA-256 fingerprint, signature algorithm, key, validity, TLS versions, cipher, JARM, JA3S).
- **Banner History** (with `history: true`): one row per port, transport, product and version, with first seen, last seen and the number of observations. Version changes on a port show up as separate rows, newest first.
- **Cloud Provider**, **Hostnames**, **Domains**, **Tags**. Certificate SAN names show up in Hostnames and Domains.

<details markdown="1">
<summary>Sample output: <code>{"ip": "45.33.32.156"}</code></summary>

```json
{
  "IP Information": {
    "IP Address": "45.33.32.156",
    "Organization": "Linode",
    "ISP": "Akamai Connected Cloud",
    "ASN": "AS63949",
    "Last Update": "2026-10-11T17:13:50.085877",
    "OS": "Linux"
  },
  "Location": {
    "Country": "United States",
    "City": "Fremont",
    "Coordinates": "37.54827, -121.98857",
    "Region": "CA"
  },
  "Services": [
    {
      "Port": 80,
      "Protocol": "tcp",
      "Service": "HTTP/1.1 200 OK\r\nDate: Sat, 10 Oct 2026 04:21:34 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nAccept-Ranges: bytes\r\nVary: Acce…",
      "Product": "Apache httpd",
      "Version": "2.4.7",
      "CPE": [
        "cpe:2.3:a:apache:http_server:2.4.7",
        "cpe:2.3:o:canonical:ubuntu_linux"
      ],
      "Vulnerabilities": [
        "CVE-2006-20001",
        "CVE-2007-4723",
        "CVE-2009-0796",
        "… 134 more"
      ],
      "HTTP": {
        "Server": "Apache/2.4.7 (Ubuntu)",
        "Title": "Go ahead and ScanMe!"
      }
    },
    {
      "Port": 31337,
      "Protocol": "tcp",
      "Service": "No banner",
      "Product": "Unknown",
      "Version": "Unknown",
      "CPE": [],
      "SSL": {
        "Subject CN": "localhost",
        "Issuer CN": "localhost",
        "Serial": "1141171337",
        "SHA-256 Fingerprint": "66a104a97c7caadcd85f81e43e1ea172f57a27bdd382fb2d6a3fe0cc1a72b190",
        "Signature Algorithm": "sha256WithRSAEncryption",
        "Public Key": "rsa 2048-bit",
        "Issued": "20260928154722Z",
        "Expires": "20270928154722Z",
        "Expired": "No",
        "TLS Versions": [],
        "Cipher": "AES256-GCM-SHA384 (256-bit)",
        "JARM": "04d10d00004d04d04c04d10d04d04d9674c6b4e623ae36cc2d998e99e2262e",
        "JA3S": "7c02dbae662670040c7af9bd15fb7e2f"
      }
    }
  ],
  "Vulnerabilities": {
    "Count": 137,
    "CVEs": [
      "CVE-2006-20001",
      "CVE-2007-4723",
      "CVE-2009-0796",
      "… 134 more"
    ]
  },
  "Cloud Provider": {
    "Provider": "Linode",
    "Service": null,
    "Region": "us-ca"
  },
  "Hostnames": [
    "scanme.nmap.org"
  ],
  "Domains": [
    "nmap.org"
  ],
  "Tags": [
    "self-signed",
    "cloud"
  ]
}
```

</details>

<details markdown="1">
<summary>With history: <code>{"ip": "45.33.32.156", "history": true}</code></summary>

```json
{
  "Banner History": [
    {
      "Port": 22,
      "Transport": "tcp",
      "Product": "OpenSSH",
      "Version": "6.6.1p1 Ubuntu 2ubuntu2.13",
      "First Seen": "2026-07-15T14:35:23.112073",
      "Last Seen": "2026-10-12T14:43:14.154740",
      "Observations": 75
    },
    {
      "Port": 22,
      "Transport": "tcp",
      "Product": "OpenSSH",
      "Version": "6.6.1p1 Ubuntu 2ubuntu2.13\\r\\n",
      "First Seen": "2026-10-04T18:23:15.825876",
      "Last Seen": "2026-10-04T18:23:15.825876",
      "Observations": 1
    },
    {
      "Port": 80,
      "Transport": "tcp",
      "Product": "Apache httpd",
      "Version": "2.4.7",
      "First Seen": "2026-07-15T21:39:03.534632",
      "Last Seen": "2026-10-10T04:21:34.049621",
      "Observations": 73
    },
    {
      "Port": 123,
      "Transport": "udp",
      "Product": "ntpd",
      "Version": "3",
      "First Seen": "2026-07-28T03:18:39.112684",
      "Last Seen": "2026-10-11T07:52:08.903449",
      "Observations": 70
    },
    "… 2 more"
  ]
}
```

</details>

### `shodan_search`

Search Shodan's index of internet-connected devices using [Shodan query syntax](https://www.shodan.io/search/filters), for example `product:nginx country:DE port:443`.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `query` | string | yes | | Shodan search query. |
| `max_results` | integer | no | `10` | 1-100. Shodan returns pages of up to 100 matches; the tool trims each page to this many. |
| `page` | integer | no | `1` | Results page, 100 matches per page. |
| `facets` | string | no | `country` | Comma-separated facets, each optionally with a count: `country:10,org,port`. `search_filters` lists valid names. |

Returns a search summary (total matches, results returned, page), facet breakdowns across all matches, and for each match: IP, organization, ISP, ASN, OS, location, port, transport, product, version, CPEs, CVEs, HTTP details, hostnames and domains.

!!! note
    Queries with filters cost one query credit and need a membership or paid API plan. Each page after the first costs one more credit. On a free account, use plain keywords or the other tools. To see only totals and breakdowns, use `shodan_count`, which is free.

<details markdown="1">
<summary>Sample output: <code>{"query": "hostname:scanme.nmap.org", "max_results": 1, "facets": "port:5"}</code></summary>

```json
{
  "Search Summary": {
    "Query": "hostname:scanme.nmap.org",
    "Total Results": 8,
    "Results Returned": 1,
    "Page": 1
  },
  "Facets": {
    "port": [
      {
        "Value": 22,
        "Count": 2,
        "Percentage": "25.00%"
      },
      {
        "Value": 80,
        "Count": 2,
        "Percentage": "25.00%"
      },
      {
        "Value": 123,
        "Count": 2,
        "Percentage": "25.00%"
      },
      "… 1 more"
    ]
  },
  "Matches": [
    {
      "Basic Information": {
        "IP Address": "2600:3c01::f03c:91ff:fe18:bb2f",
        "Organization": "Linode",
        "ISP": "Akamai Connected Cloud",
        "ASN": "AS63949",
        "Last Update": "2026-10-12T01:41:36.584171"
      },
      "Location": {
        "Country": "United States",
        "City": "Fremont",
        "Region": "CA",
        "Coordinates": "37.54827, -121.98857"
      },
      "Service Details": {
        "Port": 22,
        "Transport": "tcp",
        "Product": "OpenSSH",
        "Version": "6.6.1p1 Ubuntu 2ubuntu2.13",
        "CPE": [
          "cpe:/a:openbsd:openssh:6.6.1p1",
          "cpe:/o:canonical:ubuntu_linux"
        ]
      },
      "Web Information": "No HTTP information",
      "OS": "Linux",
      "Hostnames": [
        "scanme.nmap.org"
      ],
      "Domains": [
        "nmap.org"
      ]
    }
  ]
}
```

</details>

### `shodan_count`

The total number of matches and facet breakdowns for a query, without fetching results. It costs no query credits, so use it to size a query before running `shodan_search`.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `query` | string | yes | | Shodan search query. |
| `facets` | string | no | | Same format as `shodan_search`, for example `country:5,port:10,vuln`. |

Returns the query, total matches and the requested facet breakdowns.

<details markdown="1">
<summary>Sample output: <code>{"query": "product:nginx", "facets": "country:3,port:3"}</code></summary>

```json
{
  "Search Summary": {
    "Query": "product:nginx",
    "Total Results": 52128079
  },
  "Facets": {
    "country": [
      {
        "Value": "US",
        "Count": 13835326,
        "Percentage": "26.54%"
      },
      {
        "Value": "CN",
        "Count": 8759895,
        "Percentage": "16.80%"
      },
      {
        "Value": "HK",
        "Count": 3627262,
        "Percentage": "6.96%"
      }
    ],
    "port": [
      {
        "Value": 80,
        "Count": 10768170,
        "Percentage": "20.66%"
      },
      {
        "Value": 443,
        "Count": 8796296,
        "Percentage": "16.87%"
      },
      {
        "Value": 888,
        "Count": 480640,
        "Percentage": "0.92%"
      }
    ]
  }
}
```

</details>

### `domain_info`

Subdomains and DNS records Shodan has observed for a domain.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `domain` | string | yes | | A domain name such as `example.com`. |
| `history` | boolean | no | `false` | Include records that are no longer live. |
| `type` | string | no | | Only one record type: `A`, `AAAA`, `CNAME`, `NS`, `SOA`, `MX` or `TXT`. |
| `page` | integer | no | `1` | Results page, for large domains. |

Returns tags, the list of subdomains, DNS records (subdomain, type, value, last seen; `@` is the domain itself), and whether more pages exist.

!!! note
    Each call costs one query credit.

<details markdown="1">
<summary>Sample output: <code>{"domain": "nmap.org", "type": "MX"}</code></summary>

```json
{
  "Domain": "nmap.org",
  "Tags": [],
  "Subdomains": {
    "Count": 0,
    "Names": []
  },
  "DNS Records": [
    {
      "Subdomain": "@",
      "Type": "MX",
      "Value": "alt1.aspmx.l.google.com",
      "Last Seen": "2026-10-08T16:02:16.288000"
    },
    {
      "Subdomain": "@",
      "Type": "MX",
      "Value": "alt2.aspmx.l.google.com",
      "Last Seen": "2026-10-08T16:02:16.288000"
    },
    {
      "Subdomain": "@",
      "Type": "MX",
      "Value": "aspmx.l.google.com",
      "Last Seen": "2026-10-08T16:02:16.288000"
    },
    "… 2 more"
  ],
  "More Results": "No"
}
```

</details>

### `dns_lookup`

Resolve hostnames to IP addresses in one batch.

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `hostnames` | string[] | yes | For example `["example.com", "shodan.io"]`. |

Returns a hostname-to-IP list and a summary.

<details markdown="1">
<summary>Sample output: <code>{"hostnames": ["scanme.nmap.org", "shodan.io"]}</code></summary>

```json
{
  "DNS Resolutions": [
    {
      "Hostname": "shodan.io",
      "IP Address": "216.117.2.180"
    },
    {
      "Hostname": "scanme.nmap.org",
      "IP Address": "45.33.32.156"
    }
  ],
  "Summary": {
    "Total Lookups": 2,
    "Queried Hostnames": [
      "scanme.nmap.org",
      "shodan.io"
    ]
  }
}
```

</details>

### `reverse_dns_lookup`

Find the hostnames that point back to IP addresses, in one batch.

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `ips` | string[] | yes | For example `["8.8.8.8", "1.1.1.1"]`. |

Returns hostnames per IP (`"No hostnames found"` when there is no PTR record) and a count of IPs with results.

<details markdown="1">
<summary>Sample output: <code>{"ips": ["8.8.8.8", "1.1.1.1"]}</code></summary>

```json
{
  "Reverse DNS Resolutions": [
    {
      "IP Address": "8.8.8.8",
      "Hostnames": [
        "dns.google"
      ]
    },
    {
      "IP Address": "1.1.1.1",
      "Hostnames": [
        "one.one.one.one"
      ]
    }
  ],
  "Summary": {
    "Total IPs Queried": 2,
    "IPs with Results": 2,
    "Queried IP Addresses": [
      "8.8.8.8",
      "1.1.1.1"
    ]
  }
}
```

</details>

## Vulnerability intelligence

These tools query [CVEDB](https://cvedb.shodan.io), Shodan's free vulnerability database. They don't use your API key.

### `cve_lookup`

Full details for one CVE.

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `cve` | string | yes | `CVE-YYYY-NNNN…`, case-insensitive. For example `CVE-2021-44228`. |

Returns the summary and publish date; CVSS v4, v3 and v2 scores with severity (v4 where the CVE has one); EPSS probability and its percentile among all scored CVEs; whether it is in CISA's Known Exploited Vulnerabilities (KEV) catalog, with the proposed action and ransomware use; affected CPEs (the first 50, with the total, since popular software can list over a thousand); and references.

<details markdown="1">
<summary>Sample output: <code>{"cve": "CVE-2021-44228"}</code></summary>

```json
{
  "Basic Information": {
    "CVE ID": "CVE-2021-44228",
    "Published": "12/10/2021, 10:15:09 AM",
    "Summary": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in …"
  },
  "Severity Scores": {
    "CVSS v4": "Not available",
    "CVSS v3": {
      "Score": 10,
      "Severity": "Critical"
    },
    "CVSS v2": {
      "Score": 9.3,
      "Severity": "Critical"
    },
    "EPSS": {
      "Score": "100.00%",
      "Percentile": "100.00 (higher than 100.00% of scored CVEs)"
    }
  },
  "Impact Assessment": {
    "Known Exploited Vulnerability": "Yes",
    "Proposed Action": "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related en…",
    "Ransomware Campaign": "Known"
  },
  "Affected Products": {
    "Total": 1593,
    "Shown": 50,
    "CPEs": [
      "cpe:2.3:a:apache:log4j:2.0",
      "cpe:2.3:a:apache:log4j:2.0.1",
      "cpe:2.3:a:apache:log4j:2.0.2",
      "… 47 more"
    ],
    "Note": "Showing the first 50 of 1593 affected CPEs. Use cves_by_product with a cpe23 value to check a specific version."
  },
  "Additional Information": {
    "References": [
      "http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html",
      "http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html",
      "http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html",
      "… 100 more"
    ]
  }
}
```

</details>

### `cpe_lookup`

Find CPE 2.3 identifiers for a product name. Use the result as the `cpe23` input to `cves_by_product`.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `product` | string | yes | | For example `apache`, `nginx`. |
| `count` | boolean | no | `false` | Return only the number of matching CPEs. |
| `skip` | integer | no | `0` | Pagination offset, 0 or more. |
| `limit` | integer | no | `1000` | 1-1000. |

<details markdown="1">
<summary>Sample output: <code>{"product": "log4j", "limit": 5}</code></summary>

```json
{
  "cpes": [
    "cpe:2.3:a:apache:log4j:1.0.4",
    "cpe:2.3:a:apache:log4j:1.1.3",
    "cpe:2.3:a:apache:log4j:1.2",
    "cpe:2.3:a:apache:log4j:1.2.1",
    "cpe:2.3:a:apache:log4j:1.2.10"
  ],
  "skip": 0,
  "limit": 5,
  "total_returned": 5
}
```

</details>

### `cves_by_product`

List CVEs that affect a product or a specific CPE, with filters for KEV, EPSS ordering and publish date.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `product` | string | one of these two | | Product name, for example `log4j`. |
| `cpe23` | string | one of these two | | For example `cpe:2.3:a:apache:log4j:2.14.1`. |
| `count` | boolean | no | `false` | Return only the number of matching CVEs. |
| `is_kev` | boolean | no | `false` | Only CVEs in the KEV catalog. |
| `sort_by_epss` | boolean | no | `false` | Highest EPSS score first. |
| `skip` | integer | no | `0` | Pagination offset, 0 or more. |
| `limit` | integer | no | `1000` | 1-1000. |
| `start_date` | string | no | | Published on or after, `YYYY-MM-DDTHH:MM:SS`. |
| `end_date` | string | no | | Published on or before, `YYYY-MM-DDTHH:MM:SS`. |

Pass exactly one of `product` and `cpe23`. Returns the query, a results summary with the total number of matching CVEs and the page number, and per-CVE details in the same shape as `cve_lookup` (without the CPE list).

!!! tip
    The default `limit` of 1000 can return a very large response for popular products. Ask for `count: true` first, or set `limit` to 10-50 with `sort_by_epss: true` to get the most likely exploited issues.

<details markdown="1">
<summary>Sample output: <code>{"product": "log4j", "sort_by_epss": true, "limit": 2}</code></summary>

```json
{
  "Query Information": {
    "Product": "log4j",
    "CPE 2.3": "N/A",
    "KEV Only": "No",
    "Sort by EPSS": "Yes",
    "Date Range": "All dates"
  },
  "Results Summary": {
    "Total CVEs Found": 20,
    "CVEs Returned": 2,
    "Page": "1",
    "CVEs per Page": 2
  },
  "Vulnerabilities": [
    {
      "Basic Information": {
        "CVE ID": "CVE-2021-44228",
        "Published": "12/10/2021, 10:15:09 AM",
        "Summary": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in …"
      },
      "Severity Scores": {
        "CVSS v4": "Not available",
        "CVSS v3": {
          "Score": 10,
          "Severity": "Critical"
        },
        "CVSS v2": {
          "Score": 9.3,
          "Severity": "Critical"
        },
        "EPSS": {
          "Score": "100.00%",
          "Percentile": "100.00 (higher than 100.00% of scored CVEs)"
        }
      },
      "Impact Assessment": {
        "Known Exploited Vulnerability": "Yes",
        "Proposed Action": "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related en…",
        "Ransomware Campaign": "Known"
      },
      "References": [
        "http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html",
        "http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html",
        "… 101 more"
      ]
    },
    {
      "Basic Information": {
        "CVE ID": "CVE-2021-45105",
        "Published": "12/18/2021, 12:15:07 PM",
        "Summary": "Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recur…"
      },
      "Severity Scores": {
        "CVSS v4": "Not available",
        "CVSS v3": {
          "Score": 5.9,
          "Severity": "Medium"
        },
        "CVSS v2": {
          "Score": 4.3,
          "Severity": "Medium"
        },
        "EPSS": {
          "Score": "100.00%",
          "Percentile": "99.99 (higher than 99.99% of scored CVEs)"
        }
      },
      "Impact Assessment": {
        "Known Exploited Vulnerability": "No",
        "Proposed Action": "No specific action proposed",
        "Ransomware Campaign": "No known ransomware campaigns"
      },
      "References": [
        "http://www.openwall.com/lists/oss-security/2021/12/19/1",
        "https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf",
        "… 24 more"
      ]
    }
  ]
}
```

</details>

## Query helpers and account

### `search_filters`

Every search filter and facet name Shodan supports. Use it to build valid `shodan_search` and `shodan_count` queries. No parameters, no credits.

<details markdown="1">
<summary>Sample output: <code>{}</code></summary>

```json
{
  "Filters": {
    "Count": 94,
    "Names": [
      "all",
      "asn",
      "asset",
      "bitcoin.ip",
      "bitcoin.ip_count",
      "bitcoin.port",
      "… 88 more"
    ]
  },
  "Facets": {
    "Count": 90,
    "Names": [
      "asn",
      "bitcoin.ip",
      "bitcoin.ip_count",
      "bitcoin.port",
      "bitcoin.user_agent",
      "bitcoin.version",
      "… 84 more"
    ]
  }
}
```

</details>

### `api_info`

Your Shodan plan and what's left on it: query credits, scan credits, monitored IPs and usage limits. No parameters, no credits. Ask the agent to check this before a run of credit-spending searches.

<details markdown="1">
<summary>Sample output: <code>{}</code></summary>

```json
{
  "Plan": "dev",
  "Query Credits": 95,
  "Scan Credits": 100,
  "Monitored IPs": 5,
  "Usage Limits": {
    "scan_credits": 100,
    "query_credits": 100,
    "monitored_ips": 16
  },
  "Unlocked": true,
  "Unlocked Left": 95,
  "HTTPS": true,
  "Telnet": true
}
```

</details>
