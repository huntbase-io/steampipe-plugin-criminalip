---
title: "Steampipe Table: criminalip_ip - Query Criminal IP IP Verdicts using SQL"
description: "Allows users to query the Criminal IP verdict, geolocation, ownership and detection flags for an IPv4 address."
---

# Table: criminalip_ip - Query Criminal IP IP Verdicts using SQL

The `criminalip_ip` table gives a one-row verdict for an IPv4 address: inbound and outbound risk scores, whether it is malicious, geolocation and ownership, detection flags (Tor, VPN, proxy, hosting, scanner, CDN, mobile) and counts of abuse records, open ports and vulnerabilities.

## Table Usage Guide

This is the best single table for asking whether an IP is bad. Use it to enrich IPs from logs, alerts or firewall data. The geolocation and score columns come from `/v1/asset/ip/summary`. The verdict, flags and counts come from `/v1/asset/ip/report/summary`, which is called only when you select one of those columns.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- Selecting only `ip`, the score columns and geolocation columns costs one API call per IP. Selecting any detection or count column costs one more.
- Score values are `Safe`, `Low`, `Moderate`, `Dangerous` and `Critical`.
- Each IP looked up costs one API call. Steampipe caches results (5 minutes by default), so repeating a query is free.

## Examples

### Get the verdict for an IP
See the scores, malicious flag and main detections for a single address.

```sql+postgres
select
  ip,
  score_inbound,
  score_outbound,
  is_malicious,
  is_tor,
  is_vpn,
  is_proxy,
  abuse_record_count
from
  criminalip_ip
where
  ip = '185.220.101.1';
```

```sql+sqlite
select
  ip,
  score_inbound,
  score_outbound,
  is_malicious,
  is_tor,
  is_vpn,
  is_proxy,
  abuse_record_count
from
  criminalip_ip
where
  ip = '185.220.101.1';
```

### Locate and attribute several IPs
Find the country, network owner and ASN for a list of addresses. Only the summary endpoint is called.

```sql+postgres
select
  ip,
  country_code,
  city,
  org_name,
  as_no,
  score_inbound
from
  criminalip_ip
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1');
```

```sql+sqlite
select
  ip,
  country_code,
  city,
  org_name,
  as_no,
  score_inbound
from
  criminalip_ip
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1');
```

### Find anonymising infrastructure among IPs
Flag addresses that are Tor nodes, VPNs, proxies or scanners.

```sql+postgres
select
  ip,
  hostname,
  is_tor,
  is_vpn,
  is_anonymous_vpn,
  is_proxy,
  is_scanner,
  issues
from
  criminalip_ip
where
  ip in ('8.8.8.8', '185.220.101.1')
  and (is_tor or is_vpn or is_anonymous_vpn or is_proxy or is_scanner);
```

```sql+sqlite
select
  ip,
  hostname,
  is_tor,
  is_vpn,
  is_anonymous_vpn,
  is_proxy,
  is_scanner,
  issues
from
  criminalip_ip
where
  ip in ('8.8.8.8', '185.220.101.1')
  and (is_tor or is_vpn or is_anonymous_vpn or is_proxy or is_scanner);
```

### List open ports with known vulnerabilities
Expand the `open_ports` JSON to see which TCP ports have vulnerable services.

```sql+postgres
select
  ip,
  (p ->> 'port')::int as port,
  (p ->> 'has_vulnerability')::bool as has_vulnerability
from
  criminalip_ip,
  jsonb_array_elements(open_ports -> 'TCP') as p
where
  ip = '185.220.101.1';
```

```sql+sqlite
select
  ip,
  json_extract(p.value, '$.port') as port,
  json_extract(p.value, '$.has_vulnerability') as has_vulnerability
from
  criminalip_ip,
  json_each(json_extract(open_ports, '$.TCP')) as p
where
  ip = '185.220.101.1';
```
