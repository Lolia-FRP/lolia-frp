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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/log"
)

func buildAutoTLSServerConfigWithHosts(pluginName string, auto *v1.AutoTLSOptions, fallbackHosts []string) (*tls.Config, error) {
	if auto == nil || !auto.Enable {
		return nil, fmt.Errorf("插件 %s 未启用 autoTLS", pluginName)
	}

	if err := os.MkdirAll(auto.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("插件 %s 创建 autoTLS 缓存目录失败: %w", pluginName, err)
	}

	hostSet := make(map[string]struct{})
	hosts := make([]string, 0, len(auto.HostAllowList))
	addHost := func(host string) {
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			return
		}
		if strings.Contains(host, "*") {
			log.Warnf("[autoTLS][%s] 域名 [%s] 含通配符，自动申请不支持，已忽略", pluginName, host)
			return
		}
		if _, ok := hostSet[host]; ok {
			return
		}
		hostSet[host] = struct{}{}
		hosts = append(hosts, host)
	}

	for _, host := range auto.HostAllowList {
		addHost(host)
	}
	if len(hosts) == 0 {
		for _, host := range fallbackHosts {
			addHost(host)
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("插件 %s 的 hostAllowList 为空；请设置 autoTLS.hostAllowList 或 customDomains", pluginName)
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      strings.TrimSpace(auto.Email),
		HostPolicy: autocert.HostWhitelist(hosts...),
	}
	caDirURL := strings.TrimSpace(auto.CADirURL)
	if caDirURL != "" {
		manager.Client = &acme.Client{DirectoryURL: caDirURL}
	} else {
		caDirURL = autocert.DefaultACMEDirectory
	}
	managedHosts := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		managedHosts[host] = struct{}{}
	}
	var warmupInProgress sync.Map
	var warmupMissLogged sync.Map
	manager.Cache = &autoTLSCache{
		inner:            autocert.DirCache(auto.CacheDir),
		managedHosts:     managedHosts,
		pluginName:       pluginName,
		caDirURL:         caDirURL,
		warmupInProgress: &warmupInProgress,
		warmupMissLogged: &warmupMissLogged,
	}

	cfg := manager.TLSConfig()
	log.Infof("[autoTLS][%s] 已启用 autoTLS，管理域名=%v，缓存目录=%s", pluginName, hosts, auto.CacheDir)

	var readySeen sync.Map

	handleCertReady := func(host string, cert *tls.Certificate) {
		var (
			notAfter  time.Time
			hasExpiry bool
		)
		if t, ok := getCertificateNotAfter(cert); ok {
			notAfter = t
			hasExpiry = true
		}

		_, readyLogged := readySeen.LoadOrStore(host, struct{}{})
		if hasExpiry {
			if !readyLogged {
				log.Infof("[autoTLS][%s] 域名 [%s] 证书已就绪，过期时间 %s", pluginName, host, notAfter.Format(time.RFC3339))
			}
		} else if !readyLogged {
			log.Infof("[autoTLS][%s] 域名 [%s] 证书已就绪", pluginName, host)
		}
	}

	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host := strings.TrimSpace(strings.ToLower(hello.ServerName))
		if host == "" {
			host = "<空SNI>"
		}

		cert, err := manager.GetCertificate(hello)
		if err != nil {
			log.Warnf("[autoTLS][%s] 获取域名 [%s] 证书失败: %v", pluginName, host, err)
			return nil, err
		}
		handleCertReady(host, cert)
		return cert, nil
	}

	// Warm up certificates in background after startup.
	for _, host := range hosts {
		h := host
		go func() {
			// Leave time for listener setup and route registration.
			time.Sleep(1 * time.Second)
			warmupMissLogged.Delete(h)
			warmupInProgress.Store(h, struct{}{})
			cert, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: h})
			warmupInProgress.Delete(h)
			if err != nil {
				log.Warnf("[autoTLS][%s] 域名 [%s] 预申请失败: %v", pluginName, h, err)
				return
			}
			handleCertReady(h, cert)
		}()
	}
	return cfg, nil
}

func getCertificateNotAfter(cert *tls.Certificate) (time.Time, bool) {
	if cert == nil {
		return time.Time{}, false
	}
	if cert.Leaf != nil {
		return cert.Leaf.NotAfter, true
	}
	if len(cert.Certificate) == 0 {
		return time.Time{}, false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}

type autoTLSCache struct {
	inner            autocert.Cache
	managedHosts     map[string]struct{}
	pluginName       string
	caDirURL         string
	warmupInProgress *sync.Map
	warmupMissLogged *sync.Map
}

func (c *autoTLSCache) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := c.inner.Get(ctx, key)
	if err != autocert.ErrCacheMiss {
		return data, err
	}

	host := strings.TrimSuffix(key, "+rsa")
	if _, ok := c.managedHosts[host]; !ok {
		return data, err
	}
	if _, warming := c.warmupInProgress.Load(host); !warming {
		return data, err
	}
	if _, loaded := c.warmupMissLogged.LoadOrStore(host, struct{}{}); !loaded {
		log.Infof("[autoTLS][%s] 开始预申请域名 [%s] 证书，申请方式=TLS-ALPN-01，caDirURL=%s", c.pluginName, host, c.caDirURL)
	}
	return data, err
}

func (c *autoTLSCache) Put(ctx context.Context, key string, data []byte) error {
	return c.inner.Put(ctx, key, data)
}

func (c *autoTLSCache) Delete(ctx context.Context, key string) error {
	return c.inner.Delete(ctx, key)
}
