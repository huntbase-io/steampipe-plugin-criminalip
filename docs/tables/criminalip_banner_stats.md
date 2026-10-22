---
title: "Steampipe Table: criminalip_banner_stats - Query Criminal IP Banner Statistics using SQL"
description: "Allows users to get aggregate counts (by country, AS name, port, service, product and favicon) of the Criminal IP banners that match a search query."
---

# Table: criminalip_banner_stats - Query Criminal IP Banner Statistics using SQL

The Criminal IP banner stats endpoint (`/v1/banner/stats`) returns the total number of banners that match a query, plus the top values of several fields across all matches.

## Table Usage Guide

The `criminalip_banner_stats` table returns one row per aggregation bucket: an `agg_type` (`country`, `as_name`, `port`, `service_name`, `product` or `favicons`), a `key` and its `doc_count`. Use it to size an exposure (how many hosts, where and who hosts them) for the cost of one API call, before deciding whether to page through results with `criminalip_banner_search`.

**Important Notes**
- You must specify the `query` column in the `where` clause.
- Each query makes exactly one API call, whatever the `limit`.
- Bucket keys are returned in lower case, for example `kr` or `amazon.com, inc.`.
- The API returns only the top buckets of each aggregation, not every value.
- The query syntax and its pitfalls are the same as for `criminalip_banner_search`. Check the `groups` column to make sure every filter was recognised.

## Examples

### Get the total number of matches for a query
Count matching banners without paging through them.

```sql+postgres
select distinct
  total_count
from
  criminalip_banner_stats
where
  query = 'service: https country: KR';
```

```sql+sqlite
select distinct
  total_count
from
  criminalip_banner_stats
where
  query = 'service: https country: KR';
```

### Find which networks host the most exposed services
List the top AS names for a query, with their share of all matches.

```sql+postgres
select
  key as as_name,
  doc_count,
  round(100.0 * doc_count / total_count, 1) as percent
from
  criminalip_banner_stats
where
  query = 'service: https country: KR'
  and agg_type = 'as_name'
order by
  doc_count desc;
```

```sql+sqlite
select
  key as as_name,
  doc_count,
  round(100.0 * doc_count / total_count, 1) as percent
from
  criminalip_banner_stats
where
  query = 'service: https country: KR'
  and agg_type = 'as_name'
order by
  doc_count desc;
```

### Find the countries and ports where a product is exposed
Break down OpenSSH exposure by country and port.

```sql+postgres
select
  agg_type,
  key,
  doc_count
from
  criminalip_banner_stats
where
  query = 'product: OpenSSH'
  and agg_type in ('country', 'port')
order by
  agg_type,
  doc_count desc;
```

```sql+sqlite
select
  agg_type,
  key,
  doc_count
from
  criminalip_banner_stats
where
  query = 'product: OpenSSH'
  and agg_type in ('country', 'port')
order by
  agg_type,
  doc_count desc;
```

### Find the most common products behind a CVE
See which products and services Criminal IP associates with a CVE.

```sql+postgres
select
  agg_type,
  key,
  doc_count
from
  criminalip_banner_stats
where
  query = 'cve_id: CVE-2023-38408'
  and agg_type in ('product', 'service_name')
order by
  doc_count desc;
```

```sql+sqlite
select
  agg_type,
  key,
  doc_count
from
  criminalip_banner_stats
where
  query = 'cve_id: CVE-2023-38408'
  and agg_type in ('product', 'service_name')
order by
  doc_count desc;
```
