.POSIX: # the first failing command in a recipe will cause the recipe to fail immediately

.PHONY: all
all: spell lint build test

.PHONY: ci
ci: tidy all vulncheck

.PHONY: lint
lint:
	go tool goreleaser check
	go tool golangci-lint run

.PHONY: test
TEST_ARGS ?= -cover -race -tags DEBUG,TEST
test:
	go test ${TEST_ARGS} ./...

vendor:
	go mod vendor -v

.PHONY: clean
clean:
	$(RM) -r ./vendor

.PHONY: yaegi_test
YAEGI_TEST_ARGS ?= -v
yaegi_test: vendor
	go run github.com/traefik/yaegi/cmd/yaegi@v0.16.1 test ${YAEGI_TEST_ARGS} .

.PHONY: entr
# https://github.com/eradman/entr
entr:
	find | entr -r -s "docker compose up --remove-orphans"

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: spell
spell:
	go tool misspell -error -locale=US -w **.md

.PHONY: mod
mod: ## go mod tidy
	go mod tidy

.PHONY: vulncheck
vulncheck:
	go tool govulncheck ./...

.PHONY: build
build:
	go tool goreleaser build --clean --single-target --snapshot
