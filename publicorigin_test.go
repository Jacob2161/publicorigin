package publicorigin

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOrigin checks that a configured server URL wins over the connection
// and over X-Forwarded headers, and that without one the connection's
// scheme and Host apply.
func TestOrigin(t *testing.T) {
	for _, step := range []struct {
		name, configured string
		tls              bool
		origin           string
		secure           bool
		host             string
	}{
		{"https behind a proxy", "https://backup.example.com", false, "https://backup.example.com", true, "backup.example.com"},
		{"http server URL", "http://backup.internal:8080", false, "http://backup.internal:8080", false, "backup.internal:8080"},
		{"no server URL, TLS", "", true, "https://server.test", true, "server.test"},
		{"no server URL, plain", "", false, "http://server.test", false, "server.test"},
	} {
		var seen *http.Request
		handler := Middleware(step.configured)(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { seen = req }))
		req := httptest.NewRequest(http.MethodGet, "http://server.test/", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "evil.example")
		if step.tls {
			req.TLS = &tls.ConnectionState{}
		}
		handler.ServeHTTP(httptest.NewRecorder(), req)
		if Origin(seen) != step.origin || Secure(seen) != step.secure || Host(seen) != step.host {
			t.Errorf("%s: %s %v %s", step.name, Origin(seen), Secure(seen), Host(seen))
		}
	}
}

// TestParse checks which server URLs are accepted.
func TestParse(t *testing.T) {
	for text, want := range map[string]string{
		"https://Backup.Example.com/":    "https://backup.example.com",
		"http://10.0.0.5:8080":           "http://10.0.0.5:8080",
		"https://backup.example.com:443": "https://backup.example.com",
		"http://backup.internal:80":      "http://backup.internal",
		"https://[::1]:443":              "https://[::1]",
	} {
		if got, err := Parse(text); err != nil || got != want {
			t.Errorf("%s: %s %v", text, got, err)
		}
	}
	for _, text := range []string{"backup.example.com", "ftp://x", "https://x/path", "https://user@x", "https://x?a=1", "", "https://:443", "https://x:"} {
		if _, err := Parse(text); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", text, err)
		}
	}
}

// FuzzParse checks that Parse's origins parse again to themselves.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{"https://app.example.com", "http://10.0.0.5:8080/", "HTTPS://A.B:443", "https://[::1]:8443", "http://[fe80::1%25eth0]", "https://x:0443"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		origin, err := Parse(text)
		if err != nil {
			return
		}
		again, err := Parse(origin)
		if err != nil || again != origin {
			t.Fatalf("Parse(%q) = %q, which parses to %q, %v", text, origin, again, err)
		}
	})
}

// TestParseCanonical checks the forms browsers serialize, and refusals of
// what they would not.
func TestParseCanonical(t *testing.T) {
	for text, want := range map[string]string{
		"https://example.com:0443":     "https://example.com",
		"http://example.com:08080":     "http://example.com:8080",
		"https://[2001:DB8:0:0::1]":    "https://[2001:db8::1]",
		"https://[2001:db8::1]:8443/":  "https://[2001:db8::1]:8443",
		"http://xn--bcher-kva.example": "http://xn--bcher-kva.example",
	} {
		got, err := Parse(text)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", text, got, err, want)
		}
	}
	for _, text := range []string{
		"http://[fe80::1%25eth0]",
		"https://example.com:65536",
		"https://example.com:0",
		"https://bücher.example",
		"https://exa_mple.com",
		"https://-bad.example",
		"https://a..b",
		"https://example.com?",
		"http://127.1",
		"http://2130706433",
		"http://0x7f.0.0.1",
		"http://1.2.3.04",
		"http://[::ffff:192.0.2.1]",
	} {
		if _, err := Parse(text); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) accepted: %v", text, err)
		}
	}
}
