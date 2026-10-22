---
organization: Huntbase
category: ["security"]
icon_url: "/images/plugins/huntbase-io/criminalip.svg"
brand_color: "#E5302F"
display_name: "Criminal IP"
short_name: "criminalip"
description: "Steampipe plugin to query IP, domain, banner and exploit threat intelligence from Criminal IP."
og_description: "Query Criminal IP threat intelligence with SQL! Open source CLI. No DB required."
og_image: "/images/plugins/huntbase-io/criminalip-social-graphic.png"
engines: ["steampipe", "sqlite", "postgres", "export"]
---

# Criminal IP + Steampipe

[Criminal IP](https://www.criminalip.io) is a cyber threat intelligence search engine. It scans the internet and scores IP addresses, domains, exposed services and vulnerabilities.

[Steampipe](https://steampipe.io) is an open-source zero-ETL engine to instantly query cloud APIs using SQL.

Check whether an IP is malicious:

```sql
select
  ip,
  score_inbound,
  is_malicious,
  is_tor,
  abuse_record_count,
  hostname
from
  criminalip_ip
where
  ip = '185.220.101.1';
```

```
+---------------+---------------+--------------+--------+--------------------+---------------------------------+
| ip            | score_inbound | is_malicious | is_tor | abuse_record_count | hostname                        |
+---------------+---------------+--------------+--------+--------------------+---------------------------------+
| 185.220.101.1 | Critical      | true         | true   | 37                 | berlin01.tor-exit.artikel10.org |
+---------------+---------------+--------------+--------+--------------------+---------------------------------+
```

## Documentation

- **[Table definitions & examples →](/plugins/huntbase-io/criminalip/tables)**

## Get started

### Install

Download and install the latest Criminal IP plugin:

```bash
steampipe plugin install huntbase-io/criminalip
```

### Credentials

| Item        | Description |
| :---------- | :---------- |
| Credentials | Criminal IP requires an [API key](https://www.criminalip.io/mypage/information) for every request. |
| Permissions | Which endpoints a key can call, and how many credits each call costs, depends on your Criminal IP plan. |
| Radius      | Each connection represents a single Criminal IP API key. |
| Resolution  | 1. `api_key` in the Steampipe connection config.<br />2. The `CRIMINALIP_API_KEY` environment variable. |

### Configuration

Installing the latest criminalip plugin creates a config file (`~/.steampipe/config/criminalip.spc`) with a single connection named `criminalip`:

```hcl
connection "criminalip" {
  plugin = "huntbase-io/criminalip"

  # Your Criminal IP API key. If not set here, CRIMINALIP_API_KEY is used.
  # api_key = "YOUR_CRIMINALIP_API_KEY"

  # Maximum number of records a search table fetches per query. A SQL LIMIT
  # can lower this but never raise it. Defaults to 100.
  # max_search_results = 100

  # Override the API endpoint (for proxies or testing).
  # base_url = "https://api.criminalip.io"
}
```

- `api_key` - Your Criminal IP API key. Prefer the `CRIMINALIP_API_KEY` environment variable so the key does not live in a file.
- `max_search_results` - The most records `criminalip_banner_search`, `criminalip_asset_search`, `criminalip_exploit_search` and `criminalip_domain_report_list` fetch for one query. Every page of search results costs API credits, so the default is a cautious 100. The API never returns more than 10,000 records per query.
- `base_url` - The API base URL. Defaults to `https://api.criminalip.io`.

Alternatively, set the key in the environment:

```bash
export CRIMINALIP_API_KEY=your_api_key
```

## Tables

| Table | What it returns | Required qual |
| :---- | :-------------- | :------------ |
| `criminalip_account` | The account behind the API key | none |
| `criminalip_ip` | Verdict, scores, geolocation and detection flags for an IP | `ip` |
| `criminalip_ip_report` | The full IP report, each section as JSON | `ip` (optional `full_report`) |
| `criminalip_ip_port` | One row per open port observation | `ip` (optional `full_report`) |
| `criminalip_ip_vulnerability` | One row per CVE found on an IP | `ip` (optional `full_report`) |
| `criminalip_ip_malicious` | Actors, scanning records, IDS hits and categories | `ip` |
| `criminalip_ip_suspicious` | Compact risk profile, good for bulk enrichment | `ip` |
| `criminalip_ip_privacy_threat` | Exposed webcams, IoT, admin pages and NAS | `ip` |
| `criminalip_ip_vpn` | VPN, anonymous VPN, Tor and proxy flags | `ip` |
| `criminalip_ip_hosting` | Hosting and cloud provider detection | `ip` |
| `criminalip_dns_server_safety` | Whether an IP is a safe DNS resolver | `ip` |
| `criminalip_banner_search` | Service banners matching a search query | `query` |
| `criminalip_asset_search` | The same records in pages of 100 | `query` |
| `criminalip_banner_stats` | Aggregations (country, AS, port, product) for a query | `query` |
| `criminalip_exploit_search` | Exploit-DB entries matching a query | `query` |
| `criminalip_domain_quick` | Fast domain verdict and malicious/trusted list lookups | `domain` |
| `criminalip_domain_report_list` | Existing domain scan reports for a domain | `query` |
| `criminalip_domain_report` | A full domain scan report | `scan_id` |
| `criminalip_domain_scan_status` | Progress of a domain scan | `scan_id` |

## Things to know

- **Every call can cost credits.** Steampipe caches query results for 5 minutes by default. The IP report is also shared: `criminalip_ip_report`, `criminalip_ip_port` and `criminalip_ip_vulnerability` make one API call between them for the same IP.
- **Searches are bounded.** Search tables stop at the SQL `limit`, at `max_search_results` (100 by default), or at the end of the results, whichever comes first.
- **Read-only.** No table starts a domain scan or changes anything. To scan a new domain, use the Criminal IP web site or API, then query `criminalip_domain_report_list` and `criminalip_domain_report`.
- **IPv4 only.** IPv6 addresses are skipped without an API call and return no rows.
- **One call at a time.** The API rejects concurrent calls with the same key, so the plugin sends at most one request at a time per API key (across all connections that share the key), and its default rate limiter (`criminalip_api`) paces calls at up to 2 per second. You can tune the pacing with a [`limiter`](https://steampipe.io/docs/guides/limiter) block. If another program uses the same key at the same time, the plugin retries the API's "unable to call api at the same time" error with backoff.
- **Timestamps** from the API have no timezone, and not all endpoints use the same one. The plugin returns every timestamp in UTC. Checked against live responses: banner and asset search `scan_dtime` is sent in Korea Standard Time (UTC+9) and converted; the IP tables, `criminalip_domain_report_list.reg_dtime` and `criminalip_domain_report.report_time` are sent in UTC. The remaining timestamps (account dates, exploit dates, domain quick `reg_dtime`, `criminalip_ip_malicious.hostname_time`) could not be verified and are read as UTC.
- **Full IP reports** (`full_report`, default true) are complete but can be large: about 2.3 MB for 8.8.8.8. Set `full_report = false` for a faster report capped at 20 items per section.

## Example queries

Enrich a list of IPs with a compact risk profile:

```sql
select
  ip,
  score_inbound,
  abuse_record_count,
  is_tor,
  is_vpn,
  is_scanner
from
  criminalip_ip_suspicious
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1');
```

List the latest observation of each open port on an IP:

```sql
select distinct on (port)
  port,
  protocol,
  software,
  confirmed_time
from
  criminalip_ip_port
where
  ip = '8.8.8.8'
order by
  port,
  confirmed_time desc;
```

Find exposed OpenSSH services in a country (one API call per 10 rows):

```sql
select
  ip_address,
  open_port_no,
  software,
  scan_dtime
from
  criminalip_banner_search
where
  query = 'product: OpenSSH country: KR'
limit 10;
```

Get a quick verdict for a domain:

```sql
select
  domain,
  result,
  type,
  is_malicious_listed,
  is_trusted_listed
from
  criminalip_domain_quick
where
  domain = 'google.com';
```
