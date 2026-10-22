# rollcall: build, package and release.
#
#   make build                                          static binaries for every target
#   make packages                                       .ipk and .apk for every target, and luci-app-rollcall
#   make release VERSION=1.0.0                          packages, binaries and SHA256SUMS in dist/release/
#   make release VERSION=0.0.0-test TARGETS=x86_64      one target, as a local check
#
# Binaries are CGO_ENABLED=0 with -trimpath and -buildvcs=false, so one commit built with one
# toolchain gives the same bytes. ci.yml (reproducible job) and release.yml compare them.

GO      ?= go
VERSION ?= 0.0.0-dev
DIST    ?= dist
# All shipped OpenWrt architectures. TARGETS narrows a local run, for example TARGETS=x86_64.
TARGETS ?= aarch64_cortex-a53 aarch64_generic arm_cortex-a7 arm_cortex-a9 mipsel_24kc mips_24kc x86_64

# OpenWrt architecture -> Go environment. The MIPS parts have no FPU, so they use softfloat.
goenv_aarch64_cortex-a53 = GOARCH=arm64
goenv_aarch64_generic    = GOARCH=arm64
goenv_arm_cortex-a7      = GOARCH=arm GOARM=7
goenv_arm_cortex-a9      = GOARCH=arm GOARM=7
goenv_mipsel_24kc        = GOARCH=mipsle GOMIPS=softfloat
goenv_mips_24kc          = GOARCH=mips GOMIPS=softfloat
goenv_x86_64             = GOARCH=amd64

BUILD_FLAGS = -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION)"

BIN_DIR := $(DIST)/bin
PKG_DIR := $(DIST)/pkg
REL_DIR := $(DIST)/release

BINARIES := $(foreach a,$(TARGETS),$(BIN_DIR)/$(a)/rollcalld $(BIN_DIR)/$(a)/rollcall)

# A binary is rebuilt only when a Go source is newer than it. The release workflow relies on
# this: it downloads the binaries it has already compared and packages them without a rebuild.
GO_SOURCES := $(shell find cmd internal -name '*.go' 2>/dev/null) go.mod go.sum

build: $(BINARIES)

$(BIN_DIR)/%/rollcalld: $(GO_SOURCES)
	@mkdir -p $(@D)
	CGO_ENABLED=0 GOOS=linux $(goenv_$*) $(GO) build $(BUILD_FLAGS) -o $@ ./cmd/rollcalld

$(BIN_DIR)/%/rollcall: $(GO_SOURCES)
	@mkdir -p $(@D)
	CGO_ENABLED=0 GOOS=linux $(goenv_$*) $(GO) build $(BUILD_FLAGS) -o $@ ./cmd/rollcall

# Packages. Each architecture gets its own directory; the LuCI package is noarch and is
# built once, under luci/.
ipk: $(BINARIES)
	@for a in $(TARGETS); do \
		OUTDIR=$(PKG_DIR)/$$a ./scripts/mkipk.sh $(BIN_DIR)/$$a/rollcalld $(BIN_DIR)/$$a/rollcall $(VERSION) $$a || exit 1; \
	done

apk: $(BINARIES)
	@for a in $(TARGETS); do \
		OUTDIR=$(PKG_DIR)/$$a ./scripts/mkapk.sh $(BIN_DIR)/$$a/rollcalld $(BIN_DIR)/$$a/rollcall $(VERSION) $$a || exit 1; \
	done

luci:
	OUTDIR=$(PKG_DIR)/luci ./scripts/mkipk.sh --luci $(VERSION) all
	OUTDIR=$(PKG_DIR)/luci ./scripts/mkapk.sh --luci $(VERSION) noarch

# Extension point: a further package gets its own target here, writes under $(PKG_DIR), and
# its files are added to the copy loop in release below.
packages: ipk apk luci

# The release set: both binaries per target, every package, and one checksum file. Everything
# is named with the version and, where it applies, the architecture, so the names are unique.
release: build packages
	rm -rf $(REL_DIR) && mkdir -p $(REL_DIR)
	for a in $(TARGETS); do \
		cp $(BIN_DIR)/$$a/rollcalld $(REL_DIR)/rollcalld-$(VERSION)-$$a && \
		cp $(BIN_DIR)/$$a/rollcall $(REL_DIR)/rollcall-$(VERSION)-$$a && \
		cp $(PKG_DIR)/$$a/* $(REL_DIR)/ || exit 1; \
	done
	cp $(PKG_DIR)/luci/* $(REL_DIR)/
	cd $(REL_DIR) && shasum -a 256 * > SHA256SUMS
	@echo "release set in $(REL_DIR):" && ls -1 $(REL_DIR)

clean:
	rm -rf $(DIST)

.PHONY: build ipk apk luci packages release clean
