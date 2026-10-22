---
title: "Steampipe Table: criminalip_banner_search - Query Criminal IP Banner Search Results using SQL"
description: "Allows users to search Criminal IP's internet-wide index of service banners (one row per IP address and port) using the Criminal IP query language."
---

# Table: criminalip_banner_search - Query Criminal IP Banner Search Results using SQL

Criminal IP continuously scans the internet and stores the banner of every service it finds. The banner search endpoint (`/v2/banner/search`) lets you query that index by port, service, product, country, certificate fields, CVE and more.

## Table Usage Guide

The `criminalip_banner_search` table returns one row per IP address and port that matches a Criminal IP search query. Use it to find exposed services, map an organization's attack surface, or check which hosts in a network range run a given product.

**Important Notes**
- You must specify the `query` column in the `where` clause.
- Each API call returns 10 records and costs credits. The table stops paging as soon as Steampipe has the rows it needs, so **always use `limit`**. The plugin also never fetches more than the connection's `max_search_results` setting (100 records by default), even when the `limit` is larger. Raise that setting to pull more. At most 10,000 records are reachable per query.
- Steampipe only passes the `limit` to the plugin when it can apply it directly. With `order by`, a `where` condition on a column other than `query`, or a join, the plugin cannot see the `limit` and fetches up to `max_search_results` records. Put filters such as country or port inside `query` instead (for example `query = 'product: OpenSSH country: KR port: 22'`): that is cheaper and lets the `limit` through.
- `scan_dtime` is sent by the API in Korea Standard Time (UTC+9) without a timezone. The plugin converts it to UTC.
- `total_count` is the total number of matches, which can be far larger than the rows returned.
- Query syntax:
  - Filters are `name: value`, and terms are ANDed. `OR` splits the query into AND-groups (lowest precedence), and `NOT` negates a term. Keywords must come before filters.
  - **Filter values cannot contain spaces.** A quoted value such as `title: "Plesk Obsidian"` returns 0 results. Quoted *keywords* such as `"default password"` do work.
  - Use `service:` (for example `service: ssh`), not `service_name:`.
  - **An unknown filter name is silently treated as keywords** and usually returns 0 rows without an error. Check the `groups` column to see how the server parsed your query.
  - `before: YYYY-MM-DD` works, but `after:` currently returns 0 results. Filter on `scan_dtime` in SQL instead.
  - `ip:` accepts a single IP address or a CIDR range such as `ip: 8.8.8.0/24`.
- For bulk pulls, `criminalip_asset_search` takes the same query and returns 100 records per call.

## Examples

### List the services exposed in a network range
Find every service Criminal IP has seen in a /24, with the HTTP status and certificate name.

```sql+postgres
select
  ip_address,
  open_port_no,
  service_name,
  status_code,
  ssl_subject_common_name,
  scan_dtime
from
  criminalip_banner_search
where
  query = 'ip: 8.8.8.0/24'
limit 50;
```

```sql+sqlite
select
  ip_address,
  open_port_no,
  service_name,
  status_code,
  ssl_subject_common_name,
  scan_dtime
from
  criminalip_banner_search
where
  query = 'ip: 8.8.8.0/24'
limit 50;
```

### Find HTTPS services in a country and show their page titles
Review web applications exposed in South Korea, for example to spot admin consoles.

```sql+postgres
select
  ip_address,
  open_port_no,
  title,
  as_name
from
  criminalip_banner_search
where
  query = 'service: https country: KR'
limit 20;
```

```sql+sqlite
select
  ip_address,
  open_port_no,
  title,
  as_name
from
  criminalip_banner_search
where
  query = 'service: https country: KR'
limit 20;
```

### Find hosts running a vulnerable product version
Combine filters to find OpenSSH hosts with known CVEs, and expand the detected software versions.

```sql+postgres
select
  ip_address,
  open_port_no,
  s ->> 'product' as product,
  s ->> 'version' as version,
  has_cve
from
  criminalip_banner_search,
  jsonb_array_elements(software) as s
where
  query = 'product: OpenSSH country: KR'
  and has_cve
limit 20;
```

```sql+sqlite
select
  ip_address,
  open_port_no,
  json_extract(s.value, '$.product') as product,
  json_extract(s.value, '$.version') as version,
  has_cve
from
  criminalip_banner_search,
  json_each(software) as s
where
  query = 'product: OpenSSH country: KR'
  and has_cve
limit 20;
```

### Check how the server parsed a query
If a query returns nothing, check whether each filter was recognised. Here `service_name` is not a real filter, so it ends up under `keywords`.

```sql+postgres
select distinct
  total_count,
  jsonb_pretty(groups) as parsed_query
from
  criminalip_banner_search
where
  query = 'service_name: SSH country: KR'
limit 1;
```

```sql+sqlite
select distinct
  total_count,
  groups as parsed_query
from
  criminalip_banner_search
where
  query = 'service_name: SSH country: KR'
limit 1;
```

### Find expired TLS certificates seen in the last week
Use SQL for the date bound, because the `after:` filter is unreliable.

```sql+postgres
select
  ip_address,
  open_port_no,
  ssl_subject_common_name,
  ssl_issuer_organization,
  scan_dtime
from
  criminalip_banner_search
where
  query = 'ssl_expired: true country: US'
  and scan_dtime > now() - interval '7 days'
limit 20;
```

```sql+sqlite
select
  ip_address,
  open_port_no,
  ssl_subject_common_name,
  ssl_issuer_organization,
  scan_dtime
from
  criminalip_banner_search
where
  query = 'ssl_expired: true country: US'
  and scan_dtime > datetime('now', '-7 days')
limit 20;
```
