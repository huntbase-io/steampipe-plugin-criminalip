---
title: "Steampipe Table: criminalip_ip_privacy_threat - Query Criminal IP Privacy Threats using SQL"
description: "Allows users to query devices and services exposed on an IPv4 address that threaten privacy: webcams, IoT devices, admin pages, NAS devices and other ports."
---

# Table: criminalip_ip_privacy_threat - Query Criminal IP Privacy Threats using SQL

The `criminalip_ip_privacy_threat` table returns the exposed devices and services Criminal IP found on an IPv4 address (`/v2/feature/ip/privacy-threat`), grouped as webcams, IoT devices, admin pages, NAS devices and other ports.

## Table Usage Guide

Use this table to check your own address ranges for devices that should not be on the internet, such as cameras, NAS boxes or admin consoles.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- Each IP looked up costs one API call. Steampipe caches results (5 minutes by default), so repeating a query is free.
- Each section entry is `{socket_type, port, protocol, has_vulnerability, confirmed_time, software, operating_systems}`.

## Examples

### Check an IP for exposed devices
See how many devices of each kind are exposed.

```sql+postgres
select
  ip,
  webcam_count,
  iot_count,
  admin_page_count,
  nas_count,
  other_ports_count
from
  criminalip_ip_privacy_threat
where
  ip = '8.8.8.8';
```

```sql+sqlite
select
  ip,
  webcam_count,
  iot_count,
  admin_page_count,
  nas_count,
  other_ports_count
from
  criminalip_ip_privacy_threat
where
  ip = '8.8.8.8';
```

### Find exposed admin pages or webcams
Flag IPs that expose high-risk devices.

```sql+postgres
select
  ip,
  admin_page_count,
  webcam_count
from
  criminalip_ip_privacy_threat
where
  ip in ('8.8.8.8', '1.1.1.1')
  and (admin_page_count > 0 or webcam_count > 0);
```

```sql+sqlite
select
  ip,
  admin_page_count,
  webcam_count
from
  criminalip_ip_privacy_threat
where
  ip in ('8.8.8.8', '1.1.1.1')
  and (admin_page_count > 0 or webcam_count > 0);
```

### List other exposed ports
Expand `other_ports` to one row per exposed port.

```sql+postgres
select
  ip,
  (p ->> 'port')::int as port,
  p ->> 'protocol' as protocol,
  (p ->> 'has_vulnerability')::bool as has_vulnerability,
  p ->> 'confirmed_time' as confirmed_time
from
  criminalip_ip_privacy_threat,
  jsonb_array_elements(other_ports) as p
where
  ip = '8.8.8.8';
```

```sql+sqlite
select
  ip,
  json_extract(p.value, '$.port') as port,
  json_extract(p.value, '$.protocol') as protocol,
  json_extract(p.value, '$.has_vulnerability') as has_vulnerability,
  json_extract(p.value, '$.confirmed_time') as confirmed_time
from
  criminalip_ip_privacy_threat,
  json_each(other_ports) as p
where
  ip = '8.8.8.8';
```
