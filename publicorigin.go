// Package publicorigin says which scheme and host clients reach a server at.
//
// A server behind a proxy that ends TLS, such as Caddy, HAProxy, or a cloud
// load balancer, answers plain HTTP but is reached over HTTPS. Configured
// with its public URL, links, the CSRF Origin check, and cookies' Secure
// attribute follow that URL, not the connection. X-Forwarded headers are
// never read, so a client cannot change the origin.
package publicorigin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// originKey holds the origin in a request's context.
type originKey struct{}

// WithOrigin returns ctx carrying origin, the scheme and host without a path.
func WithOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, originKey{}, origin)
}

// Middleware gives every request origin when it is not "".
func Middleware(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if origin == "" {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(WithOrigin(req.Context(), origin)))
		})
	}
}

// Origin is the scheme and host req reached: the one its context carries,
// or else the connection's scheme and the Host header.
func Origin(req *http.Request) string {
	if origin, _ := req.Context().Value(originKey{}).(string); origin != "" {
		return origin
	}
	if req.TLS != nil {
		return "https://" + req.Host
	}
	return "http://" + req.Host
}

// Secure reports whether clients reach the server over HTTPS, so its cookies
// are Secure and may take the __Host- prefix.
func Secure(req *http.Request) bool {
	return strings.HasPrefix(Origin(req), "https://")
}

// Host is the host and port of Origin.
func Host(req *http.Request) string {
	origin := Origin(req)
	return origin[strings.Index(origin, "://")+3:]
}

// ErrInvalid means a public URL is not an origin Parse accepts.
var ErrInvalid = errors.New(
	"the public URL must be http:// or https:// and a host, with no path, query, or user",
)

// Parse reads a public URL such as https://app.example.com and returns its
// origin as a browser serializes it: lowercase, without the scheme's default
// port, without a trailing slash. It accepts ASCII hostnames (an
// internationalized name in its xn-- form), IPv4 addresses, and IPv6
// addresses without a zone, with an optional port from 1 to 65535.
//
// A refused URL's error wraps ErrInvalid and names at most its scheme and
// host, never its user, password, path, or query, which may hold a
// credential.
func Parse(text string) (string, error) {
	parsed, err := url.Parse(strings.TrimSuffix(strings.TrimSpace(text), "/"))
	invalid := invalidError(parsed, err)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.User != nil || parsed.Opaque != "" {
		return "", invalid
	}
	host, ok := canonicalHost(parsed.Hostname())
	if !ok {
		return "", invalid
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", invalid
	}
	if portText := parsed.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return "", invalid
		}
		// Browsers send Origin without the scheme's default port, so the
		// origin leaves it out too, or every form would be refused.
		if !(parsed.Scheme == "https" && port == 443) && !(parsed.Scheme == "http" && port == 80) {
			host = net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
		}
	}
	return parsed.Scheme + "://" + host, nil
}

// invalidError is ErrInvalid naming the scheme and host of a refused URL,
// or nothing when it did not parse or has no host, so a credential in the
// URL never reaches a log or a terminal.
func invalidError(parsed *url.URL, parseErr error) error {
	if parseErr != nil || parsed.Host == "" {
		return ErrInvalid
	}
	return fmt.Errorf("%w: got %s://%s", ErrInvalid, parsed.Scheme, parsed.Host)
}

// isDecimal reports whether label is one or more decimal digits.
func isDecimal(label string) bool {
	if label == "" {
		return false
	}
	for _, character := range []byte(label) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// canonicalHost returns a hostname or IP address as an origin writes it, and
// false for anything else: a zone, a character outside ASCII letters,
// digits, hyphens, and dots, or an empty label.
func canonicalHost(hostname string) (string, bool) {
	address, err := netip.ParseAddr(hostname)
	if err == nil {
		// A browser writes an IPv4-mapped address in hexadecimal, which
		// netip does not; such an origin is refused rather than misnamed.
		if address.Zone() != "" || address.Is4In6() {
			return "", false
		}
		if address.Is4() {
			return address.String(), true
		}
		return "[" + address.String() + "]", true
	}
	hostname = strings.ToLower(hostname)
	if hostname == "" || len(hostname) > 253 {
		return "", false
	}
	// A browser parses a host whose last label is a number (127.1, 0x7f.1,
	// 2130706433) as an IPv4 address and serializes it differently; one
	// that is not a canonical address is refused rather than misnamed.
	labels := strings.Split(strings.TrimSuffix(hostname, "."), ".")
	if last := labels[len(labels)-1]; isDecimal(last) || strings.HasPrefix(last, "0x") {
		return "", false
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(hostname, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range []byte(label) {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
				character != '-' {
				return "", false
			}
		}
	}
	return hostname, true
}
