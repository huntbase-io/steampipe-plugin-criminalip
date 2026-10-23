## v0.1.0 [2026-10-23]

First release.

_What's new?_

- New tables added
  - [criminalip_account](docs/tables/criminalip_account.md)
  - [criminalip_asset_search](docs/tables/criminalip_asset_search.md)
  - [criminalip_banner_search](docs/tables/criminalip_banner_search.md)
  - [criminalip_banner_stats](docs/tables/criminalip_banner_stats.md)
  - [criminalip_dns_server_safety](docs/tables/criminalip_dns_server_safety.md)
  - [criminalip_domain_quick](docs/tables/criminalip_domain_quick.md)
  - [criminalip_domain_report](docs/tables/criminalip_domain_report.md)
  - [criminalip_domain_report_list](docs/tables/criminalip_domain_report_list.md)
  - [criminalip_domain_scan_status](docs/tables/criminalip_domain_scan_status.md)
  - [criminalip_exploit_search](docs/tables/criminalip_exploit_search.md)
  - [criminalip_ip](docs/tables/criminalip_ip.md)
  - [criminalip_ip_hosting](docs/tables/criminalip_ip_hosting.md)
  - [criminalip_ip_malicious](docs/tables/criminalip_ip_malicious.md)
  - [criminalip_ip_port](docs/tables/criminalip_ip_port.md)
  - [criminalip_ip_privacy_threat](docs/tables/criminalip_ip_privacy_threat.md)
  - [criminalip_ip_report](docs/tables/criminalip_ip_report.md)
  - [criminalip_ip_suspicious](docs/tables/criminalip_ip_suspicious.md)
  - [criminalip_ip_vpn](docs/tables/criminalip_ip_vpn.md)
  - [criminalip_ip_vulnerability](docs/tables/criminalip_ip_vulnerability.md)

_Enhancements_

- API requests are serialised per API key (Criminal IP rejects concurrent calls with the same key), retried with backoff on HTTP 429/5xx and on the API's "unable to call api at the same time" response, and redirects to other hosts are refused.
- Search tables stop at `min(limit, max_search_results)` (100 by default), because every page of results costs API credits.
- `criminalip_ip_report`, `criminalip_ip_port` and `criminalip_ip_vulnerability` share one cached report call per IP. `full_report` defaults to `true`, because the API otherwise caps each section at 20 items.

_Bug fixes_

- `scan_dtime` in `criminalip_banner_search` and `criminalip_asset_search` is converted from KST to UTC.
- Missing location fields in `criminalip_ip` are returned as null instead of empty strings.
