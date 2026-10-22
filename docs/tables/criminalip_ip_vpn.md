---
title: "Steampipe Table: criminalip_ip_vpn - Query Criminal IP VPN, Tor and Proxy Detection using SQL"
description: "Allows users to query whether an IPv4 address is a VPN, anonymous VPN, Tor node or proxy."
---

# Table: criminalip_ip_vpn - Query Criminal IP VPN, Tor and Proxy Detection using SQL

The `criminalip_ip_vpn` table returns Criminal IP's anonymisation verdict for an IPv4 address (`/v1/ip/vpn`): whether it is a VPN endpoint, an anonymous VPN, a Tor node or a proxy.

## Table Usage Guide

Use this table for a cheap yes/no check on anonymising infrastructure, for example on login source IPs.

**Important Notes**
- You must specify `ip` in the `where` clause, either `ip = '...'` or `ip in (...)`. Only IPv4 is supported: IPv6 addresses are skipped without an API call and return no rows.
- Each IP looked up costs one API call. Steampipe caches results (5 minutes by default), so repeating a query is free.

## Examples

### Check whether an IP is anonymising
See all four flags for an IP.

```sql+postgres
select
  ip,
  is_vpn,
  is_anonymous_vpn,
  is_tor,
  is_proxy
from
  criminalip_ip_vpn
where
  ip = '185.220.101.1';
```

```sql+sqlite
select
  ip,
  is_vpn,
  is_anonymous_vpn,
  is_tor,
  is_proxy
from
  criminalip_ip_vpn
where
  ip = '185.220.101.1';
```

### Find anonymising IPs in a list
Return only the IPs that hide their origin.

```sql+postgres
select
  ip,
  is_vpn,
  is_tor,
  is_proxy
from
  criminalip_ip_vpn
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1')
  and (is_vpn or is_anonymous_vpn or is_tor or is_proxy);
```

```sql+sqlite
select
  ip,
  is_vpn,
  is_tor,
  is_proxy
from
  criminalip_ip_vpn
where
  ip in ('8.8.8.8', '1.1.1.1', '185.220.101.1')
  and (is_vpn or is_anonymous_vpn or is_tor or is_proxy);
```

### Show VPN provider details
See the provider information when an IP is a known VPN.

```sql+postgres
select
  ip,
  vpn_info
from
  criminalip_ip_vpn
where
  ip = '185.220.101.1'
  and is_vpn;
```

```sql+sqlite
select
  ip,
  vpn_info
from
  criminalip_ip_vpn
where
  ip = '185.220.101.1'
  and is_vpn;
```
