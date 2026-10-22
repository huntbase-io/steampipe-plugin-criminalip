STEAMPIPE_INSTALL_DIR ?= ~/.steampipe
BUILD_TAGS = netgo

# Build and install as a local plugin: use `plugin = "local/criminalip"` in the
# connection config (see config/criminalip.spc).
install:
	go build -o $(STEAMPIPE_INSTALL_DIR)/plugins/local/criminalip/criminalip.plugin -tags "${BUILD_TAGS}" *.go

# Copy the keyless config template into place (does not overwrite).
reconfigure:
	cp -n config/criminalip.spc $(STEAMPIPE_INSTALL_DIR)/config/criminalip.spc || true

test:
	go test ./...

vet:
	go vet ./...

.PHONY: install reconfigure test vet
