# csp

[![GoDoc](https://godoc.org/github.com/novrin/csp?status.svg)](https://pkg.go.dev/github.com/novrin/csp) 
![tests](https://github.com/novrin/csp/workflows/tests/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/novrin/csp)](https://goreportcard.com/report/github.com/novrin/csp)

`csp` is a tiny Go (golang) library to create Content-Security-Policy HTTP headers.

### Features

* **Tiny** - less than 200 LOC and no external dependencies
* **Simple** - easy to use API

### Installation

```shell
go get github.com/novrin/csp
``` 

## Usage

```go
package main

import (
	"net/http"

	"github.com/novrin/csp"
)

func SecureHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use HeaderKey and Policy + Directives.
		w.Header().Set(csp.HeaderKey, csp.Policy(csp.Directives{
			DefaultSrc:    []string{"self", "example.com"},
			ImgSrc:        []string{"https:"},
			ScriptSrcElem: []string{"self", "https://example.com/static/app.js"},
			// Optionally use keyword source constants.
			StyleSrc: []string{csp.SourceSelf, csp.SourceUnsafeInline},
		}))
		...
		next.ServeHTTP(w, r)
	})
}
```

Better yet, use convenience defaults. Basic sets 'self' as the value for default-src, form-action, and frame-ancestors.

```go
func SecureHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set a basic non-strict CSP.
		w.Header().Set(csp.HeaderKey, csp.Basic())
		...
		next.ServeHTTP(w, r)
	})
}
```

## License

Copyright (c) 2023-present [novrin](https://github.com/novrin)

Licensed under [MIT License](./LICENSE)