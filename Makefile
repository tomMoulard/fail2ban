.PHONY: lint test vendor clean

export GO111MODULE=on

SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

default: fmt lint test

lint:
	golangci-lint run

fmt:
	gofmt -l -w $(SRC)

test:
	go test -v -cover ./...

yaegi_test:
	yaegi test .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
