.POSIX: # the first failing command in a recipe will cause the recipe to fail immediately

.PHONY: all
all: spell lint build test

.PHONY: ci
ci: inst tidy all vulncheck

.PHONY: lint
lint:
	goreleaser check
	golangci-lint run

.PHONY: test
TEST_ARGS ?= -v -cover -race -tags DEBUG
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
	yaegi test ${YAEGI_TEST_ARGS} .

.PHONY: entr
# https://github.com/eradman/entr
entr:
	find | entr -r -s "docker compose up --remove-orphans"

tidy:
	go mod tidy
	cd tools && go mod tidy

spell:
	misspell -error -locale=US -w **.md

inst:
	cd tools && go install $(shell cd tools && go list -e -f '{{ join .Imports " " }}' -tags=tools)

vulncheck:
	govulncheck ./...

build:
	goreleaser build --clean --single-target --snapshot
