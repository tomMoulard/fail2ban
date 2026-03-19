REPO=blacktop
NAME=go-macho
VERSION=$(shell svu current)
NEXT_VERSION:=$(shell svu patch)

GIT_COMMIT=$(git rev-parse HEAD)
GIT_DIRTY=$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)
GIT_DESCRIBE=$(git describe --tags)

.PHONY: dev-deps
dev-deps: ## Install the dev dependencies
	@brew install gh
	@go install github.com/goreleaser/chglog/cmd/chglog@latest
	@go install github.com/caarlos0/svu@v1.4.1

OBJC_SRC := internal/testdata/test.m
OBJC_BIN := internal/testdata/objc_fixture
CLANG    := $(shell xcrun -f clang 2>/dev/null)
SDK      := $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null)

.PHONY: objc-fixture
objc-fixture: ## Build the ObjC demo binary with protocol class properties (requires Xcode CLT)
	@if [ "$(CLANG)" = "" ]; then echo "xcrun clang not found; install Xcode Command Line Tools"; exit 1; fi
	@echo "Compiling $(OBJC_SRC) -> $(OBJC_BIN)"
	@$(CLANG) -fobjc-arc -isysroot "$(SDK)" -framework Foundation -o "$(OBJC_BIN)" "$(OBJC_SRC)"
	@echo "Built $(OBJC_BIN)"

.PHONY: bump
bump: ## Incriment version patch number
	@echo " > Bumping VERSION"
	@chglog add --version ${NEXT_VERSION}

.PHONY: changelog
changelog: bump ## Create a new CHANGELOG.md
	@echo " > Creating CHANGELOG.md"
	@chglog format --template release > CHANGELOG.md

.PHONY: release
release: changelog ## Create a new release from the VERSION
	@echo " > Creating Release"
	@gh release create ${NEXT_VERSION} -F CHANGELOG.md

.PHONY: destroy
destroy: ## Remove release from the VERSION
	@echo " > Deleting Release"
	git tag -d ${VERSION}
	git push origin :refs/tags/${VERSION}

.PHONY: fmt
fmt: ## Format code
	@echo " > Formatting code"
	@gofmt -w -r 'interface{} -> any' .
	@goimports -w .
	@gofmt -w -s .
	@go mod tidy	

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help