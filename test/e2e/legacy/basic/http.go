package basic

import (
	"fmt"
	"io"
	"net/http"

	"github.com/onsi/ginkgo/v2"
	"golang.org/x/net/websocket"

	"github.com/fatedier/frp/test/e2e/framework"
	"github.com/fatedier/frp/test/e2e/framework/consts"
	"github.com/fatedier/frp/test/e2e/mock/server/httpserver"
	"github.com/fatedier/frp/test/e2e/pkg/request"
)

var _ = ginkgo.Describe("[Feature: HTTP]", func() {
	f := framework.NewDefaultFramework()

	getDefaultServerConf := func(vhostHTTPPort int) string {
		conf := consts.LegacyDefaultServerConfig + `
		vhost_http_port = %d
		`
		return fmt.Sprintf(conf, vhostHTTPPort)
	}
	newHTTPServer := func(port int, respContent string) *httpserver.Server {
		return httpserver.New(
			httpserver.WithBindPort(port),
			httpserver.WithHandler(framework.SpecifiedHTTPBodyHandler([]byte(respContent))),
		)
	}

	ginkgo.It("HTTP route by locations", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := getDefaultServerConf(vhostHTTPPort)

		fooPort := f.AllocPort()
		f.RunServer("", newHTTPServer(fooPort, "foo"))

		barPort := f.AllocPort()
		f.RunServer("", newHTTPServer(barPort, "bar"))

		clientConf := consts.LegacyDefaultClientConfig
		clientConf += fmt.Sprintf(`
			[foo]
			type = http
			local_port = %d
			custom_domains = normal.example.com
			locations = /,/foo

			[bar]
			type = http
			local_port = %d
			custom_domains = normal.example.com
			locations = /bar
			`, fooPort, barPort)

		f.RunProcesses(serverConf, []string{clientConf})

		tests := []struct {
			path       string
			expectResp string
			desc       string
		}{
			{path: "/foo", expectResp: "foo", desc: "foo path"},
			{path: "/bar", expectResp: "bar", desc: "bar path"},
			{path: "/other", expectResp: "foo", desc: "other path"},
		}

		for _, test := range tests {
			framework.NewRequestExpect(f).Explain(test.desc).Port(vhostHTTPPort).
				RequestModify(func(r *request.Request) {
					r.HTTP().HTTPHost("normal.example.com").HTTPPath(test.path)
				}).
				ExpectResp([]byte(test.expectResp)).
				Ensure()
		}
	})

	ginkgo.It("HTTP route by HTTP user", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := getDefaultServerConf(vhostHTTPPort)

		fooPort := f.AllocPort()
		f.RunServer("", newHTTPServer(fooPort, "foo"))

		barPort := f.AllocPort()
		f.RunServer("", newHTTPServer(barPort, "bar"))

		otherPort := f.AllocPort()
		f.RunServer("", newHTTPServer(otherPort, "other"))

		clientConf := consts.LegacyDefaultClientConfig
		clientConf += fmt.Sprintf(`
			[foo]
			type = http
			local_port = %d
			custom_domains = normal.example.com
			route_by_http_user = user1

			[bar]
			type = http
			local_port = %d
			custom_domains = normal.example.com
			route_by_http_user = user2

			[catchAll]
			type = http
			local_port = %d
			custom_domains = normal.example.com
			`, fooPort, barPort, otherPort)

		f.RunProcesses(serverConf, []string{clientConf})

		// user1
		framework.NewRequestExpect(f).Explain("user1").Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("normal.example.com").HTTPAuth("user1", "")
			}).
			ExpectResp([]byte("foo")).
			Ensure()

		// user2
		framework.NewRequestExpect(f).Explain("user2").Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("normal.example.com").HTTPAuth("user2", "")
			}).
			ExpectResp([]byte("bar")).
			Ensure()

		// other user
		framework.NewRequestExpect(f).Explain("other user").Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("normal.example.com").HTTPAuth("user3", "")
			}).
			ExpectResp([]byte("other")).
			Ensure()
	})

	ginkgo.It("HTTP Basic Auth", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := getDefaultServerConf(vhostHTTPPort)

		clientConf := consts.LegacyDefaultClientConfig
		clientConf += fmt.Sprintf(`
			[test]
			type = http
			local_port = {{ .%s }}
			custom_domains = normal.example.com
			http_user = test
			http_pwd = test
			`, framework.HTTPSimpleServerPort)

		f.RunProcesses(serverConf, []string{clientConf})

		// not set auth header
		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("normal.example.com")
			}).
			Ensure(framework.ExpectResponseCode(401))

		// set incorrect auth header
		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("normal.example.com").HTTPAuth("test", "invalid")
			}).
			Ensure(framework.ExpectResponseCode(401))

		// set correct auth header
		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("normal.example.com").HTTPAuth("test", "test")
			}).
			Ensure()
	})

	ginkgo.It("Wildcard domain", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := getDefaultServerConf(vhostHTTPPort)

		clientConf := consts.LegacyDefaultClientConfig
		clientConf += fmt.Sprintf(`
			[test]
			type = http
			local_port = {{ .%s }}
			custom_domains = *.example.com
			`, framework.HTTPSimpleServerPort)

		f.RunProcesses(serverConf, []string{clientConf})

		// not match host
		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("not-match.test.com")
			}).
			Ensure(framework.ExpectResponseCode(404))

		// test.example.com match *.example.com
		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("test.example.com")
			}).
			Ensure()

		// sub.test.example.com match *.example.com
		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("sub.test.example.com")
			}).
			Ensure()
	})

	ginkgo.It("Subdomain", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := getDefaultServerConf(vhostHTTPPort)
		serverConf += `
		subdomain_host = example.com
		`

		fooPort := f.AllocPort()
		f.RunServer("", newHTTPServer(fooPort, "foo"))

		barPort := f.AllocPort()
		f.RunServer("", newHTTPServer(barPort, "bar"))

		clientConf := consts.LegacyDefaultClientConfig
		clientConf += fmt.Sprintf(`
			[foo]
			type = http
			local_port = %d
			subdomain = foo

			[bar]
			type = http
			local_port = %d
			subdomain = bar
			`, fooPort, barPort)

		f.RunProcesses(serverConf, []string{clientConf})

		// foo
		framework.NewRequestExpect(f).Explain("foo subdomain").Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("foo.example.com")
			}).
			ExpectResp([]byte("foo")).
			Ensure()

		// bar
		framework.NewRequestExpect(f).Explain("bar subdomain").Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("bar.example.com")
			}).
			ExpectResp([]byte("bar")).
			Ensure()
	})

	ginkgo.It("Modify headers", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := getDefaultServerConf(vhostHTTPPort)

		localPort := f.AllocPort()
		localServer := httpserver.New(
			httpserver.WithBindPort(localPort),
			httpserver.WithHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				_, _ = w.Write([]byte(req.Header.Get("X-From-Where")))
			})),
		)
		f.RunServer("", localServer)

		clientConf := consts.LegacyDefaultClientConfig
		clientConf += fmt.Sprintf(`
			[test]
			type = http
			local_port = %d
			custom_domains = normal.example.com
			header_X-From-Where = frp
			`, localPort)

		f.RunProcesses(serverConf, []string{clientConf})

		// not set auth header
		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("normal.example.com")
			}).
			ExpectResp([]byte("frp")). // local http server will write this X-From-Where header to response body
			Ensure()
	})

	ginkgo.It("Host Header Rewrite", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := getDefaultServerConf(vhostHTTPPort)

		localPort := f.AllocPort()
		localServer := httpserver.New(
			httpserver.WithBindPort(localPort),
			httpserver.WithHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				_, _ = w.Write([]byte(req.Host))
			})),
		)
		f.RunServer("", localServer)

		clientConf := consts.LegacyDefaultClientConfig
		clientConf += fmt.Sprintf(`
			[test]
			type = http
			local_port = %d
			custom_domains = normal.example.com
			host_header_rewrite = rewrite.example.com
			`, localPort)

		f.RunProcesses(serverConf, []string{clientConf})

		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("normal.example.com")
			}).
			ExpectResp([]byte("rewrite.example.com")). // local http server will write host header to response body
			Ensure()
	})

	ginkgo.It("Websocket protocol", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := getDefaultServerConf(vhostHTTPPort)

		localPort := f.AllocPort()
		localServer := httpserver.New(
			httpserver.WithBindPort(localPort),
			httpserver.WithHandler(websocket.Handler(func(c *websocket.Conn) {
				_, _ = io.Copy(c, c)
			})),
		)

		f.RunServer("", localServer)

		clientConf := consts.LegacyDefaultClientConfig
		clientConf += fmt.Sprintf(`
			[test]
			type = http
			local_port = %d
			custom_domains = 127.0.0.1
			`, localPort)

		f.RunProcesses(serverConf, []string{clientConf})

		c, err := websocket.Dial(fmt.Sprintf("ws://127.0.0.1:%d/", vhostHTTPPort), "", "http://127.0.0.1/")
		framework.ExpectNoError(err)
		defer c.Close()

		_, err = c.Write([]byte(consts.TestString))
		framework.ExpectNoError(err)

		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		framework.ExpectNoError(err)
		framework.ExpectEqualValues(consts.TestString, string(buf[:n]))
	})
})
