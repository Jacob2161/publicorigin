# publicorigin

[![Go Reference](https://pkg.go.dev/badge/github.com/jacob2161/publicorigin.svg)](https://pkg.go.dev/github.com/jacob2161/publicorigin)
[![CI](https://github.com/jacob2161/publicorigin/actions/workflows/ci.yml/badge.svg)](https://github.com/jacob2161/publicorigin/actions/workflows/ci.yml)

The scheme and host clients reach a server at, from a configured public URL instead of X-Forwarded headers: for links, CSRF Origin checks, and Secure cookies behind a TLS-terminating proxy.

```bash
go get github.com/jacob2161/publicorigin
```

## Usage

```go
origin, err := publicorigin.Parse(configuredURL) // such as https://app.example.com
if err != nil {
	log.Fatal(err)
}
handler := publicorigin.Middleware(origin)(mux)

// In a handler:
link := publicorigin.Origin(req) + "/invites/" + token
secure := publicorigin.Secure(req) // set cookies Secure, allow the __Host- prefix
```

- X-Forwarded headers are never read, so with an origin configured a client cannot change it.
- Without one, `Origin` falls back to the connection's scheme and the Host header, which the client chooses.
- `Parse` normalizes like browsers do: lowercase host, canonical IP addresses, no default port, no trailing slash. It refuses paths, queries, user info, zones, out-of-range ports, and hosts outside ASCII (use the xn-- form).

Tested on the two newest Go releases. Licensed under the MIT license.
