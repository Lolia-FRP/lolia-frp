// Copyright 2026 The Lolia Team
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

package net

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	dohMimeType        = "application/dns-message"
	dohMaxResponseSize = 65535
	dohRequestTimeout  = 10 * time.Second
)

// SetDefaultDNSOverHTTPS replaces net.DefaultResolver with one that sends
// DNS queries to the given DNS-over-HTTPS (RFC 8484) endpoint,
// e.g. "https://1.1.1.1/dns-query" or "https://dns.google/dns-query".
func SetDefaultDNSOverHTTPS(dohURL string) {
	client := &http.Client{
		Timeout: dohRequestTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: dohRequestTimeout,
				// Use a fresh resolver to look up the DoH server hostname itself,
				// avoiding infinite recursion through net.DefaultResolver.
				Resolver: &net.Resolver{},
			}).DialContext,
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return &dohConn{
				ctx:     ctx,
				client:  client,
				url:     dohURL,
				network: network,
			}, nil
		},
	}
}

// dohConn adapts the DNS wire-format messages exchanged by net.Resolver
// into DNS-over-HTTPS requests. Since dohConn does not implement
// net.PacketConn, the resolver always uses stream (TCP-style) framing with a
// 2-byte big-endian length prefix, regardless of the dialed network. The
// resolver writes a query and then reads the response from the same
// connection; the HTTP round trip happens synchronously inside Write.
type dohConn struct {
	ctx     context.Context
	client  *http.Client
	url     string
	network string

	mu       sync.Mutex
	deadline time.Time
	reqBuf   bytes.Buffer // unprocessed request bytes
	respBuf  bytes.Buffer // response stream with 2-byte length prefixes
}

func (c *dohConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reqBuf.Write(b)
	for {
		data := c.reqBuf.Bytes()
		if len(data) < 2 {
			break
		}
		msgLen := int(binary.BigEndian.Uint16(data))
		if len(data) < 2+msgLen {
			break
		}
		msg := make([]byte, msgLen)
		copy(msg, data[2:2+msgLen])
		c.reqBuf.Next(2 + msgLen)

		resp, err := c.roundTrip(msg)
		if err != nil {
			return 0, err
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
		c.respBuf.Write(lenBuf[:])
		c.respBuf.Write(resp)
	}
	return len(b), nil
}

func (c *dohConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.respBuf.Len() == 0 {
		return 0, io.EOF
	}
	return c.respBuf.Read(b)
}

func (c *dohConn) roundTrip(query []byte) ([]byte, error) {
	ctx := c.ctx
	if !c.deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, c.deadline)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohMimeType)
	req.Header.Set("Accept", dohMimeType)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh server %s returned status %d", c.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > dohMaxResponseSize {
		return nil, fmt.Errorf("doh response from %s exceeds %d bytes", c.url, dohMaxResponseSize)
	}
	return body, nil
}

func (c *dohConn) Close() error { return nil }

func (c *dohConn) LocalAddr() net.Addr  { return &dohAddr{network: c.network, addr: "doh-client"} }
func (c *dohConn) RemoteAddr() net.Addr { return &dohAddr{network: c.network, addr: c.url} }

func (c *dohConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *dohConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *dohConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

type dohAddr struct {
	network string
	addr    string
}

func (a *dohAddr) Network() string { return a.network }
func (a *dohAddr) String() string  { return a.addr }
