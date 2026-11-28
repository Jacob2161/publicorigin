# Changelog

This module follows semantic versioning. Before v1, a minor version may
change the API; each such change says what callers must do.

## v0.2.0 (2026-11-28)

- Requires Go 1.27, the newest Go release; Go 1.26 is no longer
  supported.
- CI runs staticcheck and govulncheck at the versions pinned in
  `tools/go.mod`, a module of its own that importers never see.

## v0.1.1 (2026-11-27)

- Security: `Parse` no longer quotes a refused URL in its error. The error
  still wraps `ErrInvalid`, and names only the scheme and host, so a
  password, user, or token in the URL no longer reaches logs or terminals.
  A caller that showed the error to help a user fix the URL may want to
  add the flag or setting name; it should not add the URL itself.
- CI also checks formatting, `go mod tidy -diff`, and `govulncheck`.

No API change.

## v0.1.0 (2026-11-27)

First release.

- `Parse` reads a configured public URL and returns its origin as a
  browser serializes it.
- `Middleware` gives every request the configured origin, and `Origin`,
  `Secure`, and `Host` read it, falling back to the connection when none
  is configured. X-Forwarded headers are never read.
