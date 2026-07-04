// Copyright 2026 The LoliaTeam Authors
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

//go:build !frps

package client

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

func init() {
	Register(v1.PluginHTTP2HTTPSRedirect, NewHTTP2HTTPSRedirectPlugin)
}

type HTTP2HTTPSRedirectPlugin struct {
	opts *v1.HTTP2HTTPSRedirectPluginOptions

	l *Listener
	s *http.Server
}

func NewHTTP2HTTPSRedirectPlugin(_ PluginContext, options v1.ClientPluginOptions) (Plugin, error) {
	opts := options.(*v1.HTTP2HTTPSRedirectPluginOptions)

	listener := NewProxyListener()
	p := &HTTP2HTTPSRedirectPlugin{
		opts: opts,
		l:    listener,
	}

	p.s = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Not an open redirect: the target scheme is fixed to https and the
			// host is the one the client already connected to.
			http.Redirect(w, req, buildHTTPSRedirectURL(req, opts.HTTPSPort), http.StatusFound) //nolint:gosec // G710
		}),
		ReadHeaderTimeout: 60 * time.Second,
	}

	go func() {
		_ = p.s.Serve(listener)
	}()

	return p, nil
}

func buildHTTPSRedirectURL(req *http.Request, httpsPort int) string {
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = strings.TrimSpace(req.URL.Host)
	}

	targetHost := host
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		targetHost = parsedHost
		if httpsPort == 0 && parsedPort == "443" {
			httpsPort = 443
		}
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		targetHost = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}

	if httpsPort != 0 && httpsPort != 443 {
		targetHost = net.JoinHostPort(targetHost, strconv.Itoa(httpsPort))
	}

	return (&url.URL{
		Scheme:   "https",
		Host:     targetHost,
		Path:     req.URL.Path,
		RawPath:  req.URL.RawPath,
		RawQuery: req.URL.RawQuery,
	}).String()
}

func (p *HTTP2HTTPSRedirectPlugin) Handle(_ context.Context, connInfo *ConnectionInfo) {
	wrapConn := netpkg.WrapReadWriteCloserToConn(connInfo.Conn, connInfo.UnderlyingConn)
	if connInfo.SrcAddr != nil {
		wrapConn.SetRemoteAddr(connInfo.SrcAddr)
	}
	_ = p.l.PutConn(wrapConn)
}

func (p *HTTP2HTTPSRedirectPlugin) Name() string {
	return v1.PluginHTTP2HTTPSRedirect
}

func (p *HTTP2HTTPSRedirectPlugin) Close() error {
	return p.s.Close()
}
