STEAMPIPE_INSTALL_DIR ?= ~/.steampipe
BUILD_TAGS = netgo

# Build and install as a local plugin: use `plugin = "local/criminalip"` in the
# connection config (see config/criminalip.spc).
install:
	go build -o $(STEAMPIPE_INSTALL_DIR)/plugins/local/criminalip/criminalip.plugin -tags "${BUILD_TAGS}" *.go

# Copy the keyless config template into place (does not overwrite).
reconfigure:
	cp -n config/criminalip.spc $(STEAMPIPE_INSTALL_DIR)/config/criminalip.spc || true

# Build the plugin as a SQLite loadable extension
# (./steampipe_sqlite_criminalip.so) from this checkout. It uses Huntbase's
# fork of turbot/steampipe-sqlite at its SDK v5 commit: upstream main targets
# steampipe-plugin-sdk v6, and the fork also fixes rows dropped for IN lists
# and joins (hb-backend#2573). This is how release.yml builds the extension
# assets; Huntbase's platform builds of linux_amd64 come from the fork itself.
STEAMPIPE_SQLITE_REPO ?= https://github.com/huntbase-io/steampipe-sqlite.git
STEAMPIPE_SQLITE_REF ?= d0ceab74e97c2a7d58219022a26e8ec7e512fd43
# Extra environment for the final `go build` only, for cross-compiling, e.g.
#   make sqlite SQLITE_BUILD_ENV="GOARCH=amd64 CGO_ENABLED=1 CC='clang -arch x86_64'"
SQLITE_BUILD_ENV ?=

sqlite:
	rm -rf build/steampipe-sqlite && mkdir -p build
	git clone --quiet $(STEAMPIPE_SQLITE_REPO) build/steampipe-sqlite
	git -C build/steampipe-sqlite checkout --quiet $(STEAMPIPE_SQLITE_REF)
	cd build/steampipe-sqlite && \
		go run generate/generator.go templates . criminalip "" github.com/huntbase-io/steampipe-plugin-criminalip && \
		go mod edit -require=github.com/huntbase-io/steampipe-plugin-criminalip@v0.0.0 \
			-replace=github.com/huntbase-io/steampipe-plugin-criminalip=$(CURDIR) && \
		go mod tidy && \
		env $(SQLITE_BUILD_ENV) $(MAKE) -f out/Makefile build
	cp build/steampipe-sqlite/steampipe_sqlite_criminalip.so .
	@echo "Built ./steampipe_sqlite_criminalip.so"

clean:
	rm -rf build steampipe_sqlite_criminalip.so

test:
	go test ./...

vet:
	go vet ./...

.PHONY: install reconfigure sqlite clean test vet
