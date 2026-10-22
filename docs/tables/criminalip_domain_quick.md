---
title: "Steampipe Table: criminalip_domain_quick - Query Criminal IP Quick Domain Verdicts using SQL"
description: "Allows users to get fast, synchronous Criminal IP verdicts for domains from the quick hash lookup and the malicious and trusted domain lists."
---

# Table: criminalip_domain_quick - Query Criminal IP Quick Domain Verdicts using SQL

Criminal IP's quick domain lookups (`/v1/domain/quick/hash/view`, `/v1/domain/quick/malicious/view` and `/v1/domain/quick/trusted/view`) answer in about a second from Criminal IP's existing data. They never start a domain scan.

## Table Usage Guide

The `criminalip_domain_quick` table returns one row per domain. Use it to triage domain IOCs, for example from logs or threat feeds.
- `result` and `type` come from the quick hash lookup, which is the best single domain verdict.
- The `is_malicious_listed` and `is_trusted_listed` columns show whether the domain is on Criminal IP's malicious or trusted list.

**Important Notes**
- You must specify the `domain` column in the `where` clause. `domain in (...)` is supported and makes one lookup per domain.
- The hash lookup costs one API call per domain. The `malicious_*` columns and the `trusted_*` columns each add one more call per domain, but only when you select them.
- A domain Criminal IP does not know still returns a row, with `found = false` and null verdict columns.
- Compare `result` case-insensitively.
- For a full analysis (DNS, certificates, phishing heuristics), look up an existing scan with `criminalip_domain_report_list` and `criminalip_domain_report`. Steampipe never starts a new scan, because scans are asynchronous and cost credits.

## Examples

### Get the quick verdict for a domain
Check whether Criminal IP considers a domain safe.

```sql+postgres
select
  domain,
  found,
  result,
  type,
  call_count,
  reg_dtime
from
  criminalip_domain_quick
where
  domain = 'google.com';
```

```sql+sqlite
select
  domain,
  found,
  result,
  type,
  call_count,
  reg_dtime
from
  criminalip_domain_quick
where
  domain = 'google.com';
```

### Triage a list of domains against the malicious and trusted lists
Check several domains at once and show which list each one is on.

```sql+postgres
select
  domain,
  result,
  is_malicious_listed,
  malicious_type,
  is_trusted_listed,
  trusted_type
from
  criminalip_domain_quick
where
  domain in ('github.com', 'example.com', 'google.com');
```

```sql+sqlite
select
  domain,
  result,
  is_malicious_listed,
  malicious_type,
  is_trusted_listed,
  trusted_type
from
  criminalip_domain_quick
where
  domain in ('github.com', 'example.com', 'google.com');
```

### Find the domains that are not rated safe
Keep only the domains whose verdict is something other than safe, or that Criminal IP does not know.

```sql+postgres
select
  domain,
  found,
  result,
  type
from
  criminalip_domain_quick
where
  domain in ('github.com', 'example.com')
  and (not found or lower(result) <> 'safe');
```

```sql+sqlite
select
  domain,
  found,
  result,
  type
from
  criminalip_domain_quick
where
  domain in ('github.com', 'example.com')
  and (not found or lower(result) <> 'safe');
```
