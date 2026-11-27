package publicorigin_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/jacob2161/publicorigin"
)

func ExampleMiddleware() {
	origin, err := publicorigin.Parse("https://App.Example.com:443/")
	if err != nil {
		log.Fatal(err)
	}
	handler := publicorigin.Middleware(origin)(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Println(publicorigin.Origin(req), publicorigin.Secure(req))
	}))
	// The proxy ended TLS, so the request arrives over plain HTTP.
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://10.0.0.5:8080/", nil))
	// Output: https://app.example.com true
}
