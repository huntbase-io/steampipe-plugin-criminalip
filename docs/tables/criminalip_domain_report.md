---
title: "Steampipe Table: criminalip_domain_report - Query Criminal IP Domain Scan Reports using SQL"
description: "Allows users to get the full report of an existing Criminal IP domain scan, including the risk score, phishing heuristics, DNS records, mapped IP addresses, certificates and technologies."
---

# Table: criminalip_domain_report - Query Criminal IP Domain Scan Reports using SQL

A Criminal IP domain scan visits a site and records its DNS, certificates, network activity, technologies and about 40 phishing and abuse heuristics. The report endpoint (`/v2/domain/report/{scan_id}`) returns the full result of a finished scan.

## Table Usage Guide

The `criminalip_domain_report` table returns one row for a scan ID. The main scalar fields (domain, title, score, registrar, report time) are columns, and the large sections are JSON columns. Use it to investigate a suspicious domain in depth.

**Important Notes**
- You must specify the `scan_id` column in the `where` clause. Find scan IDs with `criminalip_domain_report_list`.
- This table is read-only and **never starts a new scan.** Scans are asynchronous and cost credits, so start them in the Criminal IP console or API, then query the report here.
- An unknown `scan_id` returns no rows.
- `score` casing varies in the API (`safe` here, `Safe` in the report list). Compare it case-insensitively.
- Timestamps have no timezone in the API. `report_time` was checked against a live scan and is UTC; the others are read as UTC.

## Examples

### Get the summary of a report
Show the score and main details of a scan.

```sql+postgres
select
  scan_id,
  main_domain,
  title,
  score,
  score_percentage,
  domain_registrar,
  domain_created,
  report_time
from
  criminalip_domain_report
where
  scan_id = 73935155;
```

```sql+sqlite
select
  scan_id,
  main_domain,
  title,
  score,
  score_percentage,
  domain_registrar,
  domain_created,
  report_time
from
  criminalip_domain_report
where
  scan_id = 73935155;
```

### Review the phishing heuristics
Pull the most useful phishing indicators out of the `summary` section.

```sql+postgres
select
  main_domain,
  summary ->> 'url_phishing_prob' as url_phishing_prob,
  summary ->> 'dga_score' as dga_score,
  summary ->> 'fake_domain' as fake_domain,
  summary ->> 'punycode' as punycode,
  summary ->> 'newborn_domain' as newborn_domain,
  summary -> 'abuse_record' as abuse_record
from
  criminalip_domain_report
where
  scan_id = 73935155;
```

```sql+sqlite
select
  main_domain,
  json_extract(summary, '$.url_phishing_prob') as url_phishing_prob,
  json_extract(summary, '$.dga_score') as dga_score,
  json_extract(summary, '$.fake_domain') as fake_domain,
  json_extract(summary, '$.punycode') as punycode,
  json_extract(summary, '$.newborn_domain') as newborn_domain,
  json_extract(summary, '$.abuse_record') as abuse_record
from
  criminalip_domain_report
where
  scan_id = 73935155;
```

### List the IP addresses a domain maps to, with their scores
Expand `mapped_ip` to see where the domain is hosted.

```sql+postgres
select
  m ->> 'ip' as ip,
  m ->> 'score' as score,
  m ->> 'as_name' as as_name,
  m ->> 'country' as country
from
  criminalip_domain_report,
  jsonb_array_elements(mapped_ip) as m
where
  scan_id = 73935155;
```

```sql+sqlite
select
  json_extract(m.value, '$.ip') as ip,
  json_extract(m.value, '$.score') as score,
  json_extract(m.value, '$.as_name') as as_name,
  json_extract(m.value, '$.country') as country
from
  criminalip_domain_report,
  json_each(mapped_ip) as m
where
  scan_id = 73935155;
```

### Check for exposed sensitive files
Find which sensitive files, such as `.git/config` or `phpinfo`, the scan found exposed.

```sql+postgres
select
  f.key as file,
  f.value as exposed
from
  criminalip_domain_report,
  jsonb_each(file_exposure) as f
where
  scan_id = 73935155
  and f.value = 'true';
```

```sql+sqlite
select
  f.key as file,
  f.value as exposed
from
  criminalip_domain_report,
  json_each(file_exposure) as f
where
  scan_id = 73935155
  and f.value = 1;
```

### List the certificates seen during the scan
Review the TLS certificates and their validity periods.

```sql+postgres
select
  c ->> 'subject' as subject,
  c ->> 'issuer' as issuer,
  c ->> 'valid_from' as valid_from,
  c ->> 'valid_to' as valid_to
from
  criminalip_domain_report,
  jsonb_array_elements(certificates) as c
where
  scan_id = 73935155;
```

```sql+sqlite
select
  json_extract(c.value, '$.subject') as subject,
  json_extract(c.value, '$.issuer') as issuer,
  json_extract(c.value, '$.valid_from') as valid_from,
  json_extract(c.value, '$.valid_to') as valid_to
from
  criminalip_domain_report,
  json_each(certificates) as c
where
  scan_id = 73935155;
```
