// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vhost

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	httppkg "github.com/fatedier/frp/pkg/util/http"
)

// HTTPSRedirector tracks domains of HTTPS proxies that opted into automatic
// HTTP to HTTPS redirection. The HTTP reverse proxy consults it as a fallback
// for hosts that have no real HTTP route, so registered HTTP proxies on the
// same domain always take precedence over the redirect.
type HTTPSRedirector struct {
	mu      sync.RWMutex
	domains map[string]int // domain -> number of proxies requesting the redirect
	port    int            // port used in the redirect Location, as seen by browsers
}

func NewHTTPSRedirector(port int) *HTTPSRedirector {
	return &HTTPSRedirector{
		domains: make(map[string]int),
		port:    port,
	}
}

func (r *HTTPSRedirector) Add(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domains[domain]++
}

func (r *HTTPSRedirector) Remove(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.domains[domain] <= 1 {
		delete(r.domains, domain)
	} else {
		r.domains[domain]--
	}
}

func (r *HTTPSRedirector) match(host string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.domains[host] > 0
}

// Redirect responds with a redirect to the HTTPS endpoint of the requested
// host if the host opted into redirection. It reports whether the request
// was handled.
func (r *HTTPSRedirector) Redirect(rw http.ResponseWriter, req *http.Request) bool {
	if req.Method == http.MethodConnect {
		return false
	}
	host, err := httppkg.CanonicalHost(req.Host)
	if err != nil || !r.match(host) {
		return false
	}

	target := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     req.URL.Path,
		RawPath:  req.URL.RawPath,
		RawQuery: req.URL.RawQuery,
	}
	if r.port != 443 {
		target.Host = net.JoinHostPort(host, strconv.Itoa(r.port))
	}
	// Not an open redirect: the host is validated against the registered
	// domain set above, the scheme is fixed, and only the same-host path and
	// query are echoed back.
	http.Redirect(rw, req, target.String(), http.StatusMovedPermanently) //nolint:gosec // G710
	return true
}
