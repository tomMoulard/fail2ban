.POSIX: # the first failing command in a recipe will cause the recipe to fail immediately

.PHONY: all
all: lint test

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
TEST_ARGS ?= -v -cover -race -tags DEBUG
test:
	go test ${TEST_ARGS} ./...

vendor:
	go mod vendor -v

fail2ban.wasm: vendor
	# https://tinygo.org/getting-started/install/
	tinygo build \
		-o fail2ban.wasm \
		-scheduler=none \
		--no-debug \
		-target=wasi \
		-tags WASM \
		./wasm/fail2ban.wasm.go

.PHONY: yaegi_test
YAEGI_TEST_ARGS ?= -v
yaegi_test: vendor
	yaegi test ${YAEGI_TEST_ARGS} .

.PHONY: entr
# https://github.com/eradman/entr
entr:
	find | entr -r -s "docker compose up --remove-orphans"
