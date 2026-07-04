package vhost

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPSRedirectorRedirect(t *testing.T) {
	r := NewHTTPSRedirector(443)
	r.Add("a.example.com")

	// registered domain, port stripped from host, path and query preserved
	req := httptest.NewRequest("GET", "http://a.example.com:8080/foo?x=1", nil)
	rw := httptest.NewRecorder()
	require.True(t, r.Redirect(rw, req))
	require.Equal(t, 301, rw.Code)
	require.Equal(t, "https://a.example.com/foo?x=1", rw.Header().Get("Location"))

	// unknown domain is not handled
	req = httptest.NewRequest("GET", "http://b.example.com/", nil)
	require.False(t, r.Redirect(httptest.NewRecorder(), req))
}

func TestHTTPSRedirectorNonDefaultPort(t *testing.T) {
	r := NewHTTPSRedirector(8443)
	r.Add("a.example.com")

	req := httptest.NewRequest("GET", "http://a.example.com/", nil)
	rw := httptest.NewRecorder()
	require.True(t, r.Redirect(rw, req))
	require.Equal(t, "https://a.example.com:8443/", rw.Header().Get("Location"))
}

func TestHTTPSRedirectorRefCount(t *testing.T) {
	r := NewHTTPSRedirector(443)
	r.Add("a.example.com")
	r.Add("a.example.com")

	r.Remove("a.example.com")
	require.True(t, r.match("a.example.com"), "domain removed while another proxy still references it")

	r.Remove("a.example.com")
	require.False(t, r.match("a.example.com"))
}
