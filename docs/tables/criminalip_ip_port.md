---
title: "Steampipe Table: criminalip_ip_port - Query Criminal IP Open Ports using SQL"
description: "Allows users to query the open ports, banners, software, operating systems and TLS details Criminal IP has seen on an IPv4 address."
---

# Table: criminalip_ip_port - Query Criminal IP Open Ports using SQL

The `criminalip_ip_port` table returns one row per port observation from the Criminal IP report for an IPv4 address: the port, transport, protocol, banner, detected software and operating systems, web technologies, TLS certificate fields and when the port was confirmed open.

## Table Usage Guide

Use this table to see what an IP exposes: attack surface reviews, finding outdated software, or pivoting on JARM hashes and certificate names.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- `full_report` (optional) defaults to `true`, which requests the complete report (`full=true`). Without it the API caps every section at 20 items and reports `count` as the number returned, so ports and CVEs would be silently truncated. Set `full_report = false` for a faster, smaller response.
- `criminalip_ip_report`, `criminalip_ip_port` and `criminalip_ip_vulnerability` share one cached `/v2/asset/ip/report` call per (`ip`, `full_report`), so querying all three for the same IP costs one API call.
- With `full_report = true` the API returns historical observations, so the same port can appear several times with different `confirmed_time` values. Use `distinct on (port, socket)` with `order by confirmed_time desc` to get the latest observation per port, as in the examples. For 185.220.101.1, 45 observations covered 5 ports.
- `software` and `operating_systems` are arrays of `{product, version}`. Values can be the literal string `Unknown`.

## Examples

### Latest observation for each open port
Show each port once, using its most recent observation.

```sql+postgres
select distinct on (port, socket)
  port,
  socket,
  protocol,
  confirmed_time,
  is_vulnerability
from
  criminalip_ip_port
where
  ip = '185.220.101.1'
order by
  port,
  socket,
  confirmed_time desc;
```

```sql+sqlite
select
  port,
  socket,
  protocol,
  max(confirmed_time) as confirmed_time,
  max(is_vulnerability) as is_vulnerability
from
  criminalip_ip_port
where
  ip = '185.220.101.1'
group by
  port,
  socket,
  protocol
order by
  port;
```

### List detected software by port
Expand `software` to one row per product and version.

```sql+postgres
select distinct
  port,
  s ->> 'product' as product,
  s ->> 'version' as version
from
  criminalip_ip_port,
  jsonb_array_elements(software) as s
where
  ip = '8.8.8.8'
order by
  port;
```

```sql+sqlite
select distinct
  port,
  json_extract(s.value, '$.product') as product,
  json_extract(s.value, '$.version') as version
from
  criminalip_ip_port,
  json_each(software) as s
where
  ip = '8.8.8.8'
order by
  port;
```

### Find TLS services and their certificates
List ports that present a certificate, with its common name and JARM fingerprint.

```sql+postgres
select distinct
  port,
  sdn_common_name,
  dns_names,
  jarm_hash
from
  criminalip_ip_port
where
  ip = '185.220.101.1'
  and sdn_common_name is not null;
```

```sql+sqlite
select distinct
  port,
  sdn_common_name,
  dns_names,
  jarm_hash
from
  criminalip_ip_port
where
  ip = '185.220.101.1'
  and sdn_common_name is not null;
```

### Count observations per port
See how often, and how recently, each port was seen open.

```sql+postgres
select
  port,
  count(*) as observations,
  min(confirmed_time) as first_seen,
  max(confirmed_time) as last_seen
from
  criminalip_ip_port
where
  ip = '185.220.101.1'
group by
  port
order by
  port;
```

```sql+sqlite
select
  port,
  count(*) as observations,
  min(confirmed_time) as first_seen,
  max(confirmed_time) as last_seen
from
  criminalip_ip_port
where
  ip = '185.220.101.1'
group by
  port
order by
  port;
```
