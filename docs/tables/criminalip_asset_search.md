---
title: "Steampipe Table: criminalip_asset_search - Query Criminal IP Asset Search Results using SQL"
description: "Allows users to search Criminal IP assets (one row per IP address and port) in pages of 100, using the Criminal IP query language."
---

# Table: criminalip_asset_search - Query Criminal IP Asset Search Results using SQL

The Criminal IP asset search endpoint (`/v2/asset/search`) takes the same query language and returns the same record shape as banner search, but returns 100 records per API call instead of 10.

## Table Usage Guide

The `criminalip_asset_search` table is the bulk version of `criminalip_banner_search`. Use it when you want hundreds of matching services, for example to build an inventory of a product's deployments, using a tenth as many API calls.

**Important Notes**
- You must specify the `query` column in the `where` clause.
- Each API call returns 100 records and costs credits. **Always use `limit`.** The plugin also never fetches more than the connection's `max_search_results` setting (100 records by default), even when the `limit` is larger. Raise that setting to pull more. At most 10,000 records are reachable per query.
- Steampipe only passes the `limit` to the plugin when it can apply it directly. With `order by`, a `where` condition on a column other than `query`, or a join, the plugin cannot see the `limit` and fetches up to `max_search_results` records. Put filters such as country or port inside `query` instead (for example `query = 'product: OpenSSH country: KR port: 22'`): that is cheaper and lets the `limit` through.
- `scan_dtime` is sent by the API in Korea Standard Time (UTC+9) without a timezone. The plugin converts it to UTC.
- Unlike banner search, this endpoint does not report a total match count (its `count` is the page size), so this table has no `total_count` column. Use `criminalip_banner_search` or `criminalip_banner_stats` to get the total.
- The query syntax and its pitfalls are the same as for `criminalip_banner_search`:
  - Filter values cannot contain spaces, and quoted values return 0 results.
  - Use `service:`, not `service_name:`.
  - Unknown filter names silently become keywords; check `groups`.
  - `after:` is broken.

## Examples

### Inventory nginx versions in a country
Count the nginx versions exposed in South Korea, from up to 500 services (5 API calls). This needs `max_search_results` set to 500 or more; with the default of 100, only the first 100 services are counted.

```sql+postgres
select
  s ->> 'version' as nginx_version,
  count(*) as services
from
  (
    select
      software
    from
      criminalip_asset_search
    where
      query = 'product: nginx country: KR'
    limit 500
  ) as a,
  jsonb_array_elements(a.software) as s
where
  s ->> 'product' = 'nginx'
group by
  nginx_version
order by
  services desc;
```

```sql+sqlite
select
  json_extract(s.value, '$.version') as nginx_version,
  count(*) as services
from
  (
    select
      software
    from
      criminalip_asset_search
    where
      query = 'product: nginx country: KR'
    limit 500
  ) as a,
  json_each(a.software) as s
where
  json_extract(s.value, '$.product') = 'nginx'
group by
  nginx_version
order by
  services desc;
```

### List the services exposed in a network range
Pull every service Criminal IP has seen in a range in one API call.

```sql+postgres
select
  ip_address,
  open_port_no,
  socket_type,
  service_name,
  hostname
from
  criminalip_asset_search
where
  query = 'ip: 8.8.8.0/24'
limit 100;
```

```sql+sqlite
select
  ip_address,
  open_port_no,
  socket_type,
  service_name,
  hostname
from
  criminalip_asset_search
where
  query = 'ip: 8.8.8.0/24'
limit 100;
```

### Find SSH services hosted by each cloud provider
Group exposed SSH services by cloud provider. As above, a `limit` of 200 needs `max_search_results` of at least 200.

```sql+postgres
select
  coalesce(cloud_source, 'none') as cloud,
  count(*) as ssh_services
from
  (
    select
      cloud_source
    from
      criminalip_asset_search
    where
      query = 'service: ssh country: KR'
    limit 200
  ) as a
group by
  cloud
order by
  ssh_services desc;
```

```sql+sqlite
select
  coalesce(cloud_source, 'none') as cloud,
  count(*) as ssh_services
from
  (
    select
      cloud_source
    from
      criminalip_asset_search
    where
      query = 'service: ssh country: KR'
    limit 200
  ) as a
group by
  cloud
order by
  ssh_services desc;
```
