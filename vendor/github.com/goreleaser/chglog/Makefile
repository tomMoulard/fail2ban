SOURCE_FILES?=./...
TEST_PATTERN?=.
TEST_OPTIONS?=
TEST_TIMEOUT?=5m

test:
	go test $(TEST_OPTIONS) -v -failfast -race -coverpkg=./... -covermode=atomic -coverprofile=coverage.out $(SOURCE_FILES) -run $(TEST_PATTERN) -timeout=$(TEST_TIMEOUT)
.PHONY: test

cover: test
	go tool cover -html=coverage.out
.PHONY: cover

fmt:
	go mod tidy
	gofumpt -w -l .
.PHONY: fmt

ci: build test
.PHONY: ci

build:
	goreleaser build --clean --snapshot --single-target -o chglog
.PHONY: build

.DEFAULT_GOAL := build
