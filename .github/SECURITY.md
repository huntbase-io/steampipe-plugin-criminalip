# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/huntbase-io/steampipe-plugin-criminalip/security/advisories/new)
("Report a vulnerability" on the repository's **Security** tab). Do not open a
public issue or pull request for a suspected vulnerability.

Include the plugin version (`steampipe plugin list`, or the commit), how you
run it (Steampipe or the SQLite extension), and steps to reproduce. We will
acknowledge your report within 5 working days, keep you updated while we look
into it, and credit you in the advisory unless you prefer otherwise.

Security fixes are made on the latest release only.

## Scope

The plugin queries the Criminal IP API with the key you configure and returns
the results as tables. In scope are issues in the plugin itself, for example:

- the API key (`api_key` or `CRIMINALIP_API_KEY`) leaking into query results,
  logs, error messages or anywhere other than requests to the Criminal IP API;
- the plugin sending the key or a request to a host other than the Criminal IP
  API, for example by following a redirect off that host;
- a qualifier or other query input changing an API request in a way the table
  does not document;
- vulnerabilities in `apiclient/`, or in the published plugin binaries and
  SQLite extension assets.

Vulnerabilities in the Criminal IP API or service should be reported to AI
Spera, which runs Criminal IP. Issues in Steampipe or the Steampipe plugin SDK
should be reported to [Turbot](https://github.com/turbot).

## Using the plugin safely

**Treat the API key as a credential.** Prefer the `CRIMINALIP_API_KEY`
environment variable to writing the key into `criminalip.spc`, and keep that
file out of version control.

**Mind the credit budget.** Every page of search results costs API credits.
`max_search_results` caps how many records a search fetches (100 by default);
raise it only when you mean to.
