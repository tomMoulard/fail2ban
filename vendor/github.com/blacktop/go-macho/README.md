# go-macho

[![Go](https://github.com/blacktop/go-macho/actions/workflows/go.yml/badge.svg)](https://github.com/blacktop/go-macho/actions/workflows/go.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/blacktop/go-macho.svg)](https://pkg.go.dev/github.com/blacktop/go-macho) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

> Package macho implements access to and creation of Mach-O object files.

---

## Why 🤔

This package goes beyond the Go's `debug/macho` to:

- Cover ALL load commands and architectures
- Provide nice summary string output
- Allow for creating custom MachO files
- Parse Objective-C runtime information
- Parse Swift runtime information
- Read/Write code signature information
- Parse fixup chain information

## Install

```bash
$ go get github.com/blacktop/go-macho
```

## Getting Started

```go
package main

import "github.com/blacktop/go-macho"

func main() {
    m, err := macho.Open("/path/to/macho")
    if err != nil {
        panic(err)
    }
    defer m.Close()

    fmt.Println(m.FileTOC.String())
}
```

## Logging

This library uses Go's structured logging (`log/slog`) for diagnostic messages. By default, no logs are emitted. To see library diagnostics (warnings about malformed Mach-O data, etc.), set up an slog handler in your application:

```go
import (
	"log/slog"
	"os"
)

// Enable debug logging
slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelWarn, // Or slog.LevelDebug for more verbose output
})))
```

This allows you to control go-macho's logging output in your application without it polluting stdout by default.

## License

MIT Copyright (c) 2020-2025 **blacktop**
