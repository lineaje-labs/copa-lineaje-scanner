################################################################################
# Global: Variables                                                            #
################################################################################

# Formatted symbol markers (=>, [needs root]) for info output
INFOMARK = $(shell printf "\033[34;1m=>\033[0m")

# Go build metadata variables
GOARCH            := $(shell go env GOARCH)
GOOS              := $(shell go env GOOS)
BUILDTYPE_DIR     := release
BUILD_NUM         := 2025

# Build output variables
OUT_DIR           := ./dist
BINS_OUT_DIR      := $(OUT_DIR)/$(GOOS)_$(GOARCH)/$(BUILDTYPE_DIR)
CLI_VERSION       := $(shell git describe --abbrev=0 --tags | sed -e 's/^v//g')
CLI_BUILD_NUM     := ${BUILD_NUM}
CLI_BINARY        := copa-lineaje-scanner_${CLI_VERSION}_$(GOOS)_$(GOARCH)

DEBUG ?= 1
ifeq ($(DEBUG), 1)
    STRIP_DEBUG_FLAGS =
else
    STRIP_DEBUG_FLAGS = -s -w
endif

################################################################################
# Target: build (default action)                                               #
################################################################################
.PHONY: build
build:
	$(info $(INFOMARK) Building $(CLI_BINARY) ...)
	go build -ldflags="$(STRIP_DEBUG_FLAGS) -X 'github.com/lineaje-labs/copa-lineaje-scanner/internal/buildinfo.Version=$(CLI_VERSION)' -X 'github.com/lineaje-labs/copa-lineaje-scanner/internal/buildinfo.BuildNum=$(CLI_BUILD_NUM)'" -o $(BINS_OUT_DIR)/$(CLI_BINARY)

################################################################################
# Target: test - unit testing                                                  #
################################################################################
.PHONY: test
test:
	$(info $(INFOMARK) Running unit tests on pkg libraries ...)
	go test ./... $(CODECOV_OPTS)
