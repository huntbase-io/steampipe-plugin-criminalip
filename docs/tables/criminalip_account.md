---
title: "Steampipe Table: criminalip_account - Query the Criminal IP Account using SQL"
description: "Allows users to query the Criminal IP account that owns the configured API key."
---

# Table: criminalip_account - Query the Criminal IP Account using SQL

Criminal IP is a threat-intelligence search engine that scans the internet and scores IP addresses, domains and exposed services. The `criminalip_account` table returns the account behind the configured API key.

## Table Usage Guide

Use this table to check that the connection works and to see which account and plan a key belongs to. It calls `POST /v1/user/me`, which does not touch threat data.

**Important Notes**
- The API echoes the full API key in this response. The plugin drops it before building the row, so it is never returned, cached or logged.
- Timestamps carry no timezone in the API and are read as UTC. This could not be verified.

## Examples

### Check which account the key belongs to
Confirm the connection is configured and see the account details.

```sql+postgres
select
  email,
  name,
  company_name,
  account_type
from
  criminalip_account;
```

```sql+sqlite
select
  email,
  name,
  company_name,
  account_type
from
  criminalip_account;
```

### Show when the account was created and last used
Useful when auditing which keys are still in active use.

```sql+postgres
select
  email,
  membership_date,
  last_access_date,
  now() - last_access_date as idle_for
from
  criminalip_account;
```

```sql+sqlite
select
  email,
  membership_date,
  last_access_date,
  julianday('now') - julianday(last_access_date) as idle_days
from
  criminalip_account;
```

### Use the account as a connection test
Return a single boolean that monitoring can alert on.

```sql+postgres
select
  count(*) = 1 as criminalip_ok
from
  criminalip_account;
```

```sql+sqlite
select
  count(*) = 1 as criminalip_ok
from
  criminalip_account;
```
