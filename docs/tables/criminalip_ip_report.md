---
title: "Steampipe Table: criminalip_ip_report - Query Criminal IP Full IP Reports using SQL"
description: "Allows users to query the full Criminal IP report for an IPv4 address, with every section as JSON."
---

# Table: criminalip_ip_report - Query Criminal IP Full IP Reports using SQL

The `criminalip_ip_report` table returns the full Criminal IP report for an IPv4 address (`/v2/asset/ip/report`) as one row. The issue flags and scores are columns, and each report section (WHOIS, hostnames, domains, IDS hits, honeypot hits, threat categories, ports, vulnerabilities and more) is a JSON column with a matching `_count` column.

## Table Usage Guide

Use this table for ad-hoc investigation of a single IP, where you want everything Criminal IP knows in one place. For one row per port or per CVE, use `criminalip_ip_port` or `criminalip_ip_vulnerability`.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- `full_report` (optional) defaults to `true`, which requests the complete report (`full=true`). Without it the API caps every section at 20 items and reports `count` as the number returned, so ports and CVEs would be silently truncated. Set `full_report = false` for a faster, smaller response.
- `criminalip_ip_report`, `criminalip_ip_port` and `criminalip_ip_vulnerability` share one cached `/v2/asset/ip/report` call per (`ip`, `full_report`), so querying all three for the same IP costs one API call.
- Full reports for popular IPs are large. For 8.8.8.8 the full report is about 2.3 MB and takes about 5 seconds, with more than 10,000 entries in `domain`.
- With `full_report = true`, the `ports` section includes historical sightings, so a port can appear more than once with different `confirmed_time` values.

## Examples

### Get the headline facts of a report
See the scores, flags and section sizes for an IP.

```sql+postgres
select
  ip,
  score_inbound,
  score_outbound,
  is_tor,
  is_snort,
  ids_count,
  honeypot_count,
  ip_category_count,
  ports_count,
  vulnerabilities_count
from
  criminalip_ip_report
where
  ip = '185.220.101.1';
```

```sql+sqlite
select
  ip,
  score_inbound,
  score_outbound,
  is_tor,
  is_snort,
  ids_count,
  honeypot_count,
  ip_category_count,
  ports_count,
  vulnerabilities_count
from
  criminalip_ip_report
where
  ip = '185.220.101.1';
```

### List IDS detections for an IP
Expand the `ids` section to see which Snort rules fired.

```sql+postgres
select
  i ->> 'classification' as classification,
  i ->> 'message' as message,
  i ->> 'confirmed_time' as confirmed_time
from
  criminalip_ip_report,
  jsonb_array_elements(ids) as i
where
  ip = '185.220.101.1'
order by
  confirmed_time desc;
```

```sql+sqlite
select
  json_extract(i.value, '$.classification') as classification,
  json_extract(i.value, '$.message') as message,
  json_extract(i.value, '$.confirmed_time') as confirmed_time
from
  criminalip_ip_report,
  json_each(ids) as i
where
  ip = '185.220.101.1'
order by
  confirmed_time desc;
```

### Summarise threat categories
Count the categories Criminal IP has assigned to an IP, using the faster capped report.

```sql+postgres
select
  c ->> 'type' as category,
  count(*) as entries
from
  criminalip_ip_report,
  jsonb_array_elements(ip_category) as c
where
  ip = '185.220.101.1'
  and full_report = false
group by
  category
order by
  entries desc;
```

```sql+sqlite
select
  json_extract(c.value, '$.type') as category,
  count(*) as entries
from
  criminalip_ip_report,
  json_each(ip_category) as c
where
  ip = '185.220.101.1'
  and full_report = 0
group by
  category
order by
  entries desc;
```

### Show the hostnames and WHOIS owner of an IP
Pull the first WHOIS record and all hostnames.

```sql+postgres
select
  ip,
  whois -> 0 ->> 'as_name' as as_name,
  whois -> 0 ->> 'org_country_code' as country,
  jsonb_path_query_array(hostname, '$[*].domain_name_full') as hostnames
from
  criminalip_ip_report
where
  ip = '185.220.101.1';
```

```sql+sqlite
select
  ip,
  json_extract(whois, '$[0].as_name') as as_name,
  json_extract(whois, '$[0].org_country_code') as country,
  (select json_group_array(json_extract(h.value, '$.domain_name_full')) from json_each(hostname) as h) as hostnames
from
  criminalip_ip_report
where
  ip = '185.220.101.1';
```
