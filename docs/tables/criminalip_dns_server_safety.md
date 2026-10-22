---
title: "Steampipe Table: criminalip_dns_server_safety - Query Criminal IP DNS Server Safety using SQL"
description: "Allows users to query whether an IPv4 address is a safe DNS server to use, with the reasons behind the verdict."
---

# Table: criminalip_dns_server_safety - Query Criminal IP DNS Server Safety using SQL

The `criminalip_dns_server_safety` table returns Criminal IP's verdict on whether an IPv4 address is a safe DNS resolver (`/v1/feature/ip/is_safe_dns_server`), with the reasons: a malicious IP, unusual open ports, DNS vulnerabilities, or not a known public resolver.

## Table Usage Guide

Use this table to audit the DNS resolvers configured on your hosts or handed out by DHCP.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- Each IP looked up costs one API call. Steampipe caches results (5 minutes by default), so repeating a query is free.
- The verdict is strict. 1.1.1.1 was rated not safe because it has open ports that are unusual for a DNS server (`opened_unusual_port`). Read the reason columns before acting on the verdict.

## Examples

### Check a resolver
See the verdict and the reasons for one DNS server.

```sql+postgres
select
  ip,
  is_safe_dns_server,
  is_malicious_ip,
  opened_unusual_port,
  has_dns_vulnerability,
  is_unpublic_dns
from
  criminalip_dns_server_safety
where
  ip = '1.1.1.1';
```

```sql+sqlite
select
  ip,
  is_safe_dns_server,
  is_malicious_ip,
  opened_unusual_port,
  has_dns_vulnerability,
  is_unpublic_dns
from
  criminalip_dns_server_safety
where
  ip = '1.1.1.1';
```

### Audit a list of resolvers
Return the resolvers that failed, with the reasons.

```sql+postgres
select
  ip,
  is_malicious_ip,
  opened_unusual_port,
  has_dns_vulnerability,
  is_unpublic_dns
from
  criminalip_dns_server_safety
where
  ip in ('1.1.1.1', '8.8.8.8')
  and not is_safe_dns_server;
```

```sql+sqlite
select
  ip,
  is_malicious_ip,
  opened_unusual_port,
  has_dns_vulnerability,
  is_unpublic_dns
from
  criminalip_dns_server_safety
where
  ip in ('1.1.1.1', '8.8.8.8')
  and is_safe_dns_server = 0;
```

### Find resolvers that are malicious or vulnerable
Ignore the port-based reason and keep only the serious ones.

```sql+postgres
select
  ip
from
  criminalip_dns_server_safety
where
  ip in ('1.1.1.1', '8.8.8.8')
  and (is_malicious_ip or has_dns_vulnerability);
```

```sql+sqlite
select
  ip
from
  criminalip_dns_server_safety
where
  ip in ('1.1.1.1', '8.8.8.8')
  and (is_malicious_ip or has_dns_vulnerability);
```
