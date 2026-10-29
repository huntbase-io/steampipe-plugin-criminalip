# Contributing to steampipe-plugin-criminalip

Thanks for your interest. Bug reports, new tables for Criminal IP endpoints,
query examples and docs fixes are all welcome.

## Before you start

- For a new table or anything bigger than a small fix, open an issue first so
  we can agree on the approach.
- Security issues: do not open a public issue; see [SECURITY.md](SECURITY.md).
- This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Never commit API keys or responses that identify your own infrastructure.
  Test fixtures in `testdata/fixtures` should use public or documentation IP
  addresses and domains.

## Development setup

You need Go 1.26 or newer, [Steampipe](https://steampipe.io/downloads) and,
for linting, [golangci-lint](https://golangci-lint.run/welcome/install/).

```bash
git clone https://github.com/huntbase-io/steampipe-plugin-criminalip.git
cd steampipe-plugin-criminalip
make install      # builds into ~/.steampipe/plugins/local/criminalip/
make test         # unit tests against recorded responses; no network calls
```

CI runs these checks on every pull request:

```bash
go mod verify && go mod tidy -diff
go build ./...
go vet ./...
go test -race -count=1 ./...
golangci-lint run
govulncheck ./...
```

To try a change against the live API, configure `plugin = "local/criminalip"`
and set `CRIMINALIP_API_KEY`, as described in the
[README](../README.md#developing). `make sqlite` builds the SQLite extension.

## Pull requests

- Keep each PR focused, with tests for behaviour changes. Add recorded
  responses under `testdata/fixtures` rather than calling the API from tests.
- Make sure the CI checks above pass locally before pushing.
- Add or update the table's page in `docs/tables/` and, for user-visible
  changes, an entry in [CHANGELOG.md](../CHANGELOG.md).
- By contributing you certify the
  [Developer Certificate of Origin](DEVELOPER_CERTIFICATE_OF_ORIGIN). Signing
  off your commits (`git commit -s`) is welcome but not required.

Releases are cut by the maintainers from `v*` tags; see
[RELEASING.md](../RELEASING.md).

## Licence

By contributing you agree that your contributions are licensed under the
project's [Apache License 2.0](../LICENSE).
