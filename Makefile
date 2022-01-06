.PHONY: lint test vendor clean

export GO111MODULE=on

SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

default: fmt lint test

lint:
	golangci-lint run
	golint ./...

fmt:
	gofmt -l -w $(SRC)

test-v:
	go test -v -cover ./...
	go test -v -race ./...

test:
	go test -cover ./...

cover:
	go test $(ARGS) -tags mock -covermode=count -cover -coverprofile=coverage.txt ./...
	go tool cover -html=coverage.txt -o test.html

yaegi_test:
	yaegi test .

vendor:
	go mod vendor

clean:
	$(RM) -rf ./vendor
	$(RM) -r coverage.txt test.html
