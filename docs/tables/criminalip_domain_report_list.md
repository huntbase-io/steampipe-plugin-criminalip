---
title: "Steampipe Table: criminalip_domain_report_list - Query Existing Criminal IP Domain Scan Reports using SQL"
description: "Allows users to list the existing Criminal IP domain scan reports for a domain or URL, with each report's score, issues and technologies."
---

# Table: criminalip_domain_report_list - Query Existing Criminal IP Domain Scan Reports using SQL

Every time someone scans a domain with Criminal IP, the result is kept as a report. The report search endpoint (`/v1/domain/reports`) lists the existing reports for a domain or URL.

## Table Usage Guide

The `criminalip_domain_report_list` table returns one row per existing scan report. Use it to see how a domain has been rated over time, or to find a `scan_id` to pass to `criminalip_domain_report`.

**Important Notes**
- You must specify the `query` column in the `where` clause, for example `query = 'example.com'`.
- This table is read-only and **never starts a new scan.** If no one has scanned a domain, it returns no rows.
- Each API call returns up to 100 reports. **Use `limit`**, because popular domains have thousands of reports. The plugin fetches at most `max_search_results` records per query (100 by default), even if the `limit` is larger.
- `score` casing varies in the API (`Safe` here, `safe` in the full report). Compare it case-insensitively.
- `reg_dtime` has no timezone in the API and is assumed to be UTC.

## Examples

### List recent scan reports for a domain
Show the latest scans of a domain and their scores.

```sql+postgres
select
  scan_id,
  url,
  score,
  reg_dtime,
  issue
from
  criminalip_domain_report_list
where
  query = 'example.com'
order by
  reg_dtime desc
limit 10;
```

```sql+sqlite
select
  scan_id,
  url,
  score,
  reg_dtime,
  issue
from
  criminalip_domain_report_list
where
  query = 'example.com'
order by
  reg_dtime desc
limit 10;
```

### Count reports by score
See how often scans of a domain were rated at each risk level.

```sql+postgres
select
  lower(score) as score,
  count(*) as reports
from
  (
    select
      score
    from
      criminalip_domain_report_list
    where
      query = 'example.com'
    limit 100
  ) as r
group by
  lower(score)
order by
  reports desc;
```

```sql+sqlite
select
  lower(score) as score,
  count(*) as reports
from
  (
    select
      score
    from
      criminalip_domain_report_list
    where
      query = 'example.com'
    limit 100
  ) as r
group by
  lower(score)
order by
  reports desc;
```

### Get the full report of the most recent scan
Join to `criminalip_domain_report` to fetch the details of the newest scan.

```sql+postgres
select
  r.scan_id,
  r.main_domain,
  r.score,
  r.summary ->> 'url_phishing_prob' as phishing_probability,
  r.mapped_ip
from
  criminalip_domain_report as r
where
  r.scan_id = (
    select
      scan_id
    from
      criminalip_domain_report_list
    where
      query = 'example.com'
    order by
      reg_dtime desc
    limit 1
  );
```

```sql+sqlite
select
  r.scan_id,
  r.main_domain,
  r.score,
  json_extract(r.summary, '$.url_phishing_prob') as phishing_probability,
  r.mapped_ip
from
  criminalip_domain_report as r
where
  r.scan_id = (
    select
      scan_id
    from
      criminalip_domain_report_list
    where
      query = 'example.com'
    order by
      reg_dtime desc
    limit 1
  );
```

### List the technologies detected on a domain
Expand the technologies array of recent reports.

```sql+postgres
select distinct
  t ->> 'tech_name' as technology
from
  (
    select
      technologies
    from
      criminalip_domain_report_list
    where
      query = 'example.com'
    limit 10
  ) as r,
  jsonb_array_elements(r.technologies) as t;
```

```sql+sqlite
select distinct
  json_extract(t.value, '$.tech_name') as technology
from
  (
    select
      technologies
    from
      criminalip_domain_report_list
    where
      query = 'example.com'
    limit 10
  ) as r,
  json_each(r.technologies) as t;
```
