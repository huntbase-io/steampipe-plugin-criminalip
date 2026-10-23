# Releasing

Releases are built by [GoReleaser](https://goreleaser.com) from `.goreleaser.yml`, following Turbot's Steampipe plugin convention.

## Cut a release

1. Make sure `main` is green in CI and `CHANGELOG.md` has an entry for the new version.
2. Tag the release commit and push the tag:

   ```sh
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

3. The [Release workflow](.github/workflows/release.yml) runs the unit tests, then GoReleaser builds the plugin and publishes a GitHub release for the tag with these assets:

   | Asset | Contents |
   | :---- | :------- |
   | `steampipe-plugin-criminalip_linux_amd64.gz` | Linux x86-64 plugin binary (gzip) |
   | `steampipe-plugin-criminalip_linux_arm64.gz` | Linux ARM64 plugin binary |
   | `steampipe-plugin-criminalip_darwin_amd64.gz` | macOS Intel plugin binary |
   | `steampipe-plugin-criminalip_darwin_arm64.gz` | macOS Apple silicon plugin binary |
   | `steampipe-plugin-criminalip_<version>_SHA256SUMS` | SHA-256 checksums of the plugin binaries above |
   | `steampipe_sqlite_criminalip.{linux_amd64,linux_arm64,darwin_arm64}.tar.gz` | SQLite extension (`make sqlite`), uploaded by the `sqlite` jobs after GoReleaser finishes |

   Tags with a pre-release suffix, such as `v0.2.0-rc.1`, are published as pre-releases.

To try the build without publishing anything:

```sh
goreleaser check
goreleaser release --snapshot --clean   # artifacts land in dist/
```

## Install a downloaded binary

Until the plugin is on the Steampipe Hub, install a release binary as a local plugin. For example, on Linux x86-64 (with `gh`, or from the release page):

```sh
VERSION=v0.1.0
gh release download "$VERSION" -R huntbase-io/steampipe-plugin-criminalip \
  -p 'steampipe-plugin-criminalip_linux_amd64.gz' -p '*_SHA256SUMS'
sha256sum --ignore-missing -c steampipe-plugin-criminalip_*_SHA256SUMS   # macOS: shasum -a 256 --ignore-missing -c

mkdir -p ~/.steampipe/plugins/local/criminalip
gunzip -c steampipe-plugin-criminalip_linux_amd64.gz > ~/.steampipe/plugins/local/criminalip/criminalip.plugin
chmod +x ~/.steampipe/plugins/local/criminalip/criminalip.plugin
```

On macOS, also clear the download quarantine flag: `xattr -d com.apple.quarantine ~/.steampipe/plugins/local/criminalip/criminalip.plugin`.

Then point a connection at the local plugin, exactly as for a source build (see [Developing](README.md#developing)):

```hcl
connection "criminalip" {
  plugin = "local/criminalip"
}
```

If you use a non-default `STEAMPIPE_INSTALL_DIR`, replace `~/.steampipe` with it. Restart Steampipe (`steampipe service restart`) if it is running.

## Rebuild a missing SQLite asset

If a `sqlite` job fails, fix it on `main`, then run the Release workflow by hand for the existing tag. It skips GoReleaser and uploads only the SQLite archives the release is missing; attached assets are never replaced:

```sh
gh workflow run release.yml -R huntbase-io/steampipe-plugin-criminalip -f tag=v0.1.0
```
