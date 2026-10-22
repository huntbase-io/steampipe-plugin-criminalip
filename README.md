# Criminal IP Plugin for Steampipe

Use SQL to query IP, domain, banner and exploit threat intelligence from [Criminal IP](https://www.criminalip.io).

- **[Get started →](docs/index.md)**
- Documentation: [Table definitions & examples](docs/tables)
- Maintained by [Huntbase](https://huntbase.io). Issues and pull requests are welcome.

## Quick start

Install the plugin with [Steampipe](https://steampipe.io):

```shell
steampipe plugin install huntbase-io/criminalip
```

Configure your API key in `~/.steampipe/config/criminalip.spc`, or set it in the environment:

```shell
export CRIMINALIP_API_KEY=your_api_key
```

Run a query:

```sql
select
  ip,
  score_inbound,
  is_malicious,
  is_tor,
  abuse_record_count
from
  criminalip_ip
where
  ip = '185.220.101.1';
```

```
+---------------+---------------+--------------+--------+--------------------+
| ip            | score_inbound | is_malicious | is_tor | abuse_record_count |
+---------------+---------------+--------------+--------+--------------------+
| 185.220.101.1 | Critical      | true         | true   | 37                 |
+---------------+---------------+--------------+--------+--------------------+
```

## Tables

| Area | Tables |
| :--- | :----- |
| Account | `criminalip_account` |
| IP intelligence | `criminalip_ip`, `criminalip_ip_report`, `criminalip_ip_port`, `criminalip_ip_vulnerability`, `criminalip_ip_malicious`, `criminalip_ip_suspicious`, `criminalip_ip_privacy_threat`, `criminalip_ip_vpn`, `criminalip_ip_hosting`, `criminalip_dns_server_safety` |
| Search | `criminalip_banner_search`, `criminalip_asset_search`, `criminalip_banner_stats`, `criminalip_exploit_search` |
| Domains | `criminalip_domain_quick`, `criminalip_domain_report_list`, `criminalip_domain_report`, `criminalip_domain_scan_status` |

The plugin is read-only: no query starts a domain scan or changes anything. Searches are bounded by the SQL `limit` and the `max_search_results` setting (100 by default), because every page of results costs API credits.

## Engines

This plugin is available for the following engines:

| Engine | Description |
| ------ | ----------- |
| [Steampipe](https://steampipe.io/docs) | The Steampipe CLI exposes APIs and services as a high-performance relational database, giving you the ability to write SQL-based queries to explore dynamic data. |
| [Postgres FDW](https://steampipe.io/docs/steampipe_postgres/overview) | Steampipe Postgres FDWs are native Postgres Foreign Data Wrappers that translate APIs to foreign tables. |
| [SQLite Extension](https://steampipe.io/docs/steampipe_sqlite/overview) | Steampipe SQLite Extensions provide SQLite virtual tables that translate your queries into API calls. |
| [Export](https://steampipe.io/docs/steampipe_export/overview) | Steampipe Plugin Exporters provide a flexible mechanism for exporting information from cloud services and APIs. |

## Developing

Prerequisites:

- [Steampipe](https://steampipe.io/downloads)
- [Golang](https://golang.org/doc/install) 1.26 or later

Clone:

```sh
git clone https://github.com/huntbase-io/steampipe-plugin-criminalip.git
cd steampipe-plugin-criminalip
```

Build and install as a local plugin (`~/.steampipe/plugins/local/criminalip/criminalip.plugin`):

```sh
make install
```

Configure the plugin. For a local build, use `plugin = "local/criminalip"`:

```sh
cat > ~/.steampipe/config/criminalip.spc <<'EOF'
connection "criminalip" {
  plugin = "local/criminalip"
}
EOF
export CRIMINALIP_API_KEY=your_api_key
```

Try it:

```shell
steampipe query
> .inspect criminalip
```

Run the unit tests. They use the recorded API responses in `testdata/fixtures` and make no network calls:

```sh
make test
```

### Layout

- `apiclient/`: a small, dependency-free client for the Criminal IP API. It covers auth, body-status error mapping, Cloudflare and HTML handling, flexible JSON types and bounded pagination. See the package documentation.
- `criminalip/`: the plugin: connection config, retry and rate-limit settings, and one file per table.
- `docs/`: the plugin and table documentation, in Steampipe Hub format.

Further reading:

- [Writing plugins](https://steampipe.io/docs/develop/writing-plugins)
- [Writing your first table](https://steampipe.io/docs/develop/writing-your-first-table)

## Contributing

Please see the [contribution guidelines](.github/CONTRIBUTING.md). This repository is published under the [Apache 2.0](LICENSE) license.

## License

Apache 2.0. Criminal IP is a trademark of AI Spera. This plugin is not affiliated with or endorsed by AI Spera.
