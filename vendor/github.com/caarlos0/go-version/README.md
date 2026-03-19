# go-version

This package was originally extracted from
[`sigs.k8s.io/release-utils`](https://github.com/kubernetes-sigs/release-utils).

Since then, it has been changed quite a bit (see full list below).

Original license can be found in [NOTICE.md](./NOTICE.md).

## Changes

Full list of changes from the original library:

- drop all dependencies:
  - use std testing only
  - allow to pass a previously generated ASCII art instead of generating it
    at runtime
- optional overrides:
  - caller can pass one or more functions that change the version info, so
    callers are free to use whatever methods they want to provide some options
  - a range of functions are provided by the library
- added more fields:
  - `URL`
  - `BuiltBy`
- testing
  - added more tests, hopefully preventing breaking changes in the future
