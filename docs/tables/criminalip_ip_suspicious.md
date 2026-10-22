---
title: "Steampipe Table: criminalip_ip_suspicious - Query Criminal IP Suspicious IP Profiles using SQL"
description: "Allows users to query a compact risk profile for an IPv4 address: scores, issue flags, abuse record count, WHOIS, IDS hits and open ports."
---

# Table: criminalip_ip_suspicious - Query Criminal IP Suspicious IP Profiles using SQL

The `criminalip_ip_suspicious` table returns the compact Criminal IP risk profile for an IPv4 address (`/v3/feature/ip/suspicious-info`). The response is small (2–3 KB), which makes it a good choice for enriching many rows, for example every source IP in a log table.

## Table Usage Guide

Use this table to enrich IPs at scale, where `criminalip_ip_report` would be too large and `criminalip_ip` would need two calls per IP.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- Each IP looked up costs one API call. Steampipe caches results (5 minutes by default), so repeating a query is free.

## Examples

### Get the risk profile of an IP
See the scores, issue flags and abuse count.

```sql+postgres
select
  ip,
  score_inbound,
  score_outbound,
  abuse_record_count,
  is_tor,
  is_vpn,
  is_proxy,
  is_scanner,
  is_cloud
from
  criminalip_ip_suspicious
where
  ip = '8.8.8.8';
```

```sql+sqlite
select
  ip,
  score_inbound,
  score_outbound,
  abuse_record_count,
  is_tor,
  is_vpn,
  is_proxy,
  is_scanner,
  is_cloud
from
  criminalip_ip_suspicious
where
  ip = '8.8.8.8';
```

### Rank several IPs by abuse records
Prioritise a list of IPs for investigation.

```sql+postgres
select
  ip,
  score_inbound,
  abuse_record_count,
  ids_count,
  current_opened_port_count
from
  criminalip_ip_suspicious
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1')
order by
  abuse_record_count desc;
```

```sql+sqlite
select
  ip,
  score_inbound,
  abuse_record_count,
  ids_count,
  current_opened_port_count
from
  criminalip_ip_suspicious
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1')
order by
  abuse_record_count desc;
```

### Enrich IPs from another table
Join source IPs from another table, here a literal list, to their risk scores. Each distinct IP costs one call.

```sql+postgres
with seen as (
  select
    unnest(array['8.8.8.8', '185.220.101.1'])::inet as src_ip
)
select
  s.src_ip,
  c.score_inbound,
  c.is_tor,
  c.abuse_record_count
from
  seen as s
  join criminalip_ip_suspicious as c on c.ip = s.src_ip;
```

```sql+sqlite
select
  c.ip,
  c.score_inbound,
  c.is_tor,
  c.abuse_record_count
from
  criminalip_ip_suspicious as c
where
  c.ip in ('8.8.8.8', '185.220.101.1');
```
