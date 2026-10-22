---
title: "Steampipe Table: criminalip_ip_hosting - Query Criminal IP Hosting and Cloud Detection using SQL"
description: "Allows users to query whether an IPv4 address belongs to a hosting or cloud provider, and why."
---

# Table: criminalip_ip_hosting - Query Criminal IP Hosting and Cloud Detection using SQL

The `criminalip_ip_hosting` table returns Criminal IP's hosting verdict for an IPv4 address (`/v1/ip/hosting`), with the evidence behind it: a matching published cloud IP range, a hosting keyword in the AS name, or many domains on the IP.

## Table Usage Guide

Use this table to separate residential or corporate traffic from datacenter traffic, for example to flag logins from cloud IPs.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- Each IP looked up costs one API call. Steampipe caches results (5 minutes by default), so repeating a query is free.

## Examples

### Check whether an IP is hosted
See the verdict and the matching cloud range.

```sql+postgres
select
  ip,
  is_hosting,
  cloud_service,
  cloud_ip_range
from
  criminalip_ip_hosting
where
  ip = '8.8.8.8';
```

```sql+sqlite
select
  ip,
  is_hosting,
  cloud_service,
  cloud_ip_range
from
  criminalip_ip_hosting
where
  ip = '8.8.8.8';
```

### Group IPs by cloud provider
Count a list of IPs by the cloud service whose range contains them.

```sql+postgres
select
  coalesce(cloud_service, 'none') as cloud_service,
  count(*) as ips
from
  criminalip_ip_hosting
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1')
group by
  1
order by
  ips desc;
```

```sql+sqlite
select
  coalesce(cloud_service, 'none') as cloud_service,
  count(*) as ips
from
  criminalip_ip_hosting
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1')
group by
  1
order by
  ips desc;
```

### Explain a hosting verdict
Show every signal behind the verdict.

```sql+postgres
select
  ip,
  is_hosting,
  cloud_service,
  as_name_hosting_match,
  domains_more_than_5
from
  criminalip_ip_hosting
where
  ip in ('8.8.8.8', '1.1.1.1');
```

```sql+sqlite
select
  ip,
  is_hosting,
  cloud_service,
  as_name_hosting_match,
  domains_more_than_5
from
  criminalip_ip_hosting
where
  ip in ('8.8.8.8', '1.1.1.1');
```
