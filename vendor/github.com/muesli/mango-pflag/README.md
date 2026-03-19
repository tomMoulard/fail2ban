# mango-pflag

[![Latest Release](https://img.shields.io/github/release/muesli/mango-pflag.svg?style=for-the-badge)](https://github.com/muesli/mango-pflag/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](/LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/muesli/mango-pflag/build.yml?style=for-the-badge&branch=main)](https://github.com/muesli/mango-pflag/actions)
[![Go ReportCard](https://goreportcard.com/badge/github.com/muesli/mango-pflag?style=for-the-badge)](https://goreportcard.com/report/muesli/mango-pflag)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=for-the-badge)](https://pkg.go.dev/github.com/muesli/mango-pflag)

pflag adapter for [mango](https://github.com/muesli/mango).

## Example

```go
import (
    "fmt"

    "github.com/muesli/mango"
    mpflag "github.com/muesli/mango-pflag"
    "github.com/muesli/roff"
    flag "github.com/spf13/pflag"
)

func main() {
    flag.Parse()

    manPage := mango.NewManPage(1, "mango", "a man-page generator").
        WithLongDescription("mango is a man-page generator for Go.").
        WithSection("Copyright", "(C) 2022 Christian Muehlhaeuser.\n"+
            "Released under MIT license.")

    flag.VisitAll(mpflag.PFlagVisitor(manPage))
    fmt.Println(manPage.Build(roff.NewDocument()))
}
```
