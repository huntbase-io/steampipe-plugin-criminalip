---
title: "Steampipe Table: criminalip_ip_malicious - Query Criminal IP Malicious Activity using SQL"
description: "Allows users to query malicious-activity details for an IPv4 address: threat actors, scanning records, IDS hits, remote-access ports and threat categories."
---

# Table: criminalip_ip_malicious - Query Criminal IP Malicious Activity using SQL

The `criminalip_ip_malicious` table returns the Criminal IP malicious-activity profile of an IPv4 address (`/v3/feature/ip/malicious-info`). It covers whether the IP is malicious or linked to a threat actor, scanning activity seen by honeypots, IDS detections, exposed remote-access ports and the threat categories assigned to the IP.

## Table Usage Guide

Use this table when triaging an alert about an IP: to see what it has been seen doing (scanning, attacks), and whether it is tied to a known actor.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- Each IP looked up costs one API call. Steampipe caches results (5 minutes by default), so repeating a query is free.
- `ip_category` can hold thousands of entries for popular IPs (2,689 for 8.8.8.8). The API returns it either way; select the column only when you need it, and use `ip_category_count` for a quick size check.
- The API names one field `hostname_dtime ` with a trailing space. It is exposed here as `hostname_time`.

## Examples

### Check whether an IP is malicious
See the headline flags for an IP.

```sql+postgres
select
  ip,
  is_malicious,
  is_actor,
  can_remote_access,
  hostname,
  as_name,
  country
from
  criminalip_ip_malicious
where
  ip = '185.220.101.1';
```

```sql+sqlite
select
  ip,
  is_malicious,
  is_actor,
  can_remote_access,
  hostname,
  as_name,
  country
from
  criminalip_ip_malicious
where
  ip = '185.220.101.1';
```

### List scanning activity seen from an IP
Expand `scanning_record` to see what the IP sent to honeypots.

```sql+postgres
select
  r ->> 'confirmed_time' as seen,
  (r ->> 'dst_port')::int as dst_port,
  r ->> 'protocol_type' as protocol,
  r ->> 'user_agent' as user_agent,
  r ->> 'message' as request
from
  criminalip_ip_malicious,
  jsonb_array_elements(scanning_record) as r
where
  ip = '185.220.101.1'
order by
  seen desc;
```

```sql+sqlite
select
  json_extract(r.value, '$.confirmed_time') as seen,
  json_extract(r.value, '$.dst_port') as dst_port,
  json_extract(r.value, '$.protocol_type') as protocol,
  json_extract(r.value, '$.user_agent') as user_agent,
  json_extract(r.value, '$.message') as request
from
  criminalip_ip_malicious,
  json_each(scanning_record) as r
where
  ip = '185.220.101.1'
order by
  seen desc;
```

### Find IPs linked to threat actors
List actors associated with a set of IPs.

```sql+postgres
select
  ip,
  a ->> 'name' as actor,
  a ->> 'url' as reference
from
  criminalip_ip_malicious,
  jsonb_array_elements(actor) as a
where
  ip in ('8.8.8.8', '185.220.101.1');
```

```sql+sqlite
select
  ip,
  json_extract(a.value, '$.name') as actor,
  json_extract(a.value, '$.url') as reference
from
  criminalip_ip_malicious,
  json_each(actor) as a
where
  ip in ('8.8.8.8', '185.220.101.1');
```

### Compare activity counts across IPs
Use the `_count` columns to rank IPs by how much malicious activity was recorded.

```sql+postgres
select
  ip,
  is_malicious,
  ids_count,
  scanning_record_count,
  remote_port_count,
  ip_category_count
from
  criminalip_ip_malicious
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1')
order by
  scanning_record_count desc;
```

```sql+sqlite
select
  ip,
  is_malicious,
  ids_count,
  scanning_record_count,
  remote_port_count,
  ip_category_count
from
  criminalip_ip_malicious
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1')
order by
  scanning_record_count desc;
```
