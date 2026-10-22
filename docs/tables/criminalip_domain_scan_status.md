---
title: "Steampipe Table: criminalip_domain_scan_status - Query Criminal IP Domain Scan Progress using SQL"
description: "Allows users to check the progress of a Criminal IP domain scan by scan ID."
---

# Table: criminalip_domain_scan_status - Query Criminal IP Domain Scan Progress using SQL

Criminal IP domain scans run asynchronously and usually finish in 20 to 40 seconds. The status endpoint (`/v1/domain/status/{scan_id}`) reports a scan's progress.

## Table Usage Guide

The `criminalip_domain_scan_status` table returns one row for a scan ID, with the progress from 0 to 100 and a `status` word. Use it to check whether a scan you started elsewhere has finished before you read its report with `criminalip_domain_report`.

**Important Notes**
- You must specify the `scan_id` column in the `where` clause.
- This table is read-only and **never starts a scan.**
- `scan_percentage` is -1 when the scan failed and -2 when the domain does not exist. The `status` column maps these values to `in_progress`, `complete`, `failed` and `domain_not_found`.
- An unknown `scan_id` returns no rows.

## Examples

### Check the progress of a scan
Show how far a scan has got.

```sql+postgres
select
  scan_id,
  scan_percentage,
  status
from
  criminalip_domain_scan_status
where
  scan_id = 73935155;
```

```sql+sqlite
select
  scan_id,
  scan_percentage,
  status
from
  criminalip_domain_scan_status
where
  scan_id = 73935155;
```

### Get the report only when the scan has finished
Join the status to the report so that you get a row only for a complete scan.

```sql+postgres
select
  r.scan_id,
  r.main_domain,
  r.score,
  r.report_time
from
  criminalip_domain_scan_status as s
  join criminalip_domain_report as r on r.scan_id = s.scan_id
where
  s.scan_id = 73935155
  and s.status = 'complete';
```

```sql+sqlite
select
  r.scan_id,
  r.main_domain,
  r.score,
  r.report_time
from
  criminalip_domain_scan_status as s
  join criminalip_domain_report as r on r.scan_id = s.scan_id
where
  s.scan_id = 73935155
  and s.status = 'complete';
```

### Check the status of the latest scans of a domain
Combine with `criminalip_domain_report_list` to check several recent scans.

```sql+postgres
select
  l.scan_id,
  l.reg_dtime,
  s.status
from
  (
    select
      scan_id,
      reg_dtime
    from
      criminalip_domain_report_list
    where
      query = 'example.com'
    order by
      reg_dtime desc
    limit 3
  ) as l
  join criminalip_domain_scan_status as s on s.scan_id = l.scan_id;
```

```sql+sqlite
select
  l.scan_id,
  l.reg_dtime,
  s.status
from
  (
    select
      scan_id,
      reg_dtime
    from
      criminalip_domain_report_list
    where
      query = 'example.com'
    order by
      reg_dtime desc
    limit 3
  ) as l
  join criminalip_domain_scan_status as s on s.scan_id = l.scan_id;
```
