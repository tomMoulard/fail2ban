//go:build tools
// +build tools

// Package tools manages tool dependencies, like golangci-lint, via go.mod.
package tools

// Manage tool dependencies via go.mod.
//
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
// https://github.com/golang/go/issues/25922
import (
	_ "github.com/client9/misspell/cmd/misspell"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/goreleaser/goreleaser"
	_ "github.com/traefik/yaegi/cmd/yaegi"
	_ "golang.org/x/vuln/cmd/govulncheck"
)
