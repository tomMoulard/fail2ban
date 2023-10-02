.POSIX: # the first failing command in a recipe will cause the recipe to fail immediately

.PHONY: all
all: lint test

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test -v -cover ./...

.PHONY: yaegi_test
yaegi_test:
	yaegi test -v .

.PHONY: entr
# https://github.com/eradman/entr
entr:
	find | entr -r -s "docker compose up --remove-orphans"
