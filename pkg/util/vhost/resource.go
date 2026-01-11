// Copyright 2017 fatedier, fatedier@gmail.com
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
	"bytes"
	"io"
	"net/http"
	"os"

	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
)

var NotFoundPagePath = ""

const (
	NotFound = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - 未绑定域名</title>
    <style>
        body {
            font-family: -apple-system, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #fff;
            color: #333;
        }
        .container {
            max-width: 600px;
            padding: 40px 20px;
            text-align: center;
        }
        h1 { 
            font-size: 32px; 
            font-weight: 600;
            margin-bottom: 20px; 
        }
        p { 
            line-height: 1.8; 
            color: #666; 
            margin: 10px 0;
        }
        ul {
            text-align: left;
            margin: 20px auto;
            max-width: 400px;
        }
        li {
            margin: 8px 0;
            color: #666;
        }
        a { 
            color: #0066cc; 
            text-decoration: none;
        }
        a:hover { text-decoration: underline; }
        .footer {
            margin-top: 40px;
            font-size: 14px;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>域名未绑定</h1>
        <p>这个域名还没有绑定到任何隧道哦 (；д；)</p>
        <p><strong>可能是这些原因：</strong></p>
        <ul>
            <li>域名配置不对，或者没有正确解析</li>
            <li>隧道可能还没启动，或者已经停止</li>
            <li>自定义域名忘记在服务端配置了</li>
        </ul>
        <div class="footer">由 <a href="https://lolia.link/">LoliaFRP</a> 与捐赠者们用爱发电</div>
    </div>
</body>
</html>
`
)

func getNotFoundPageContent() []byte {
	var (
		buf []byte
		err error
	)
	if NotFoundPagePath != "" {
		buf, err = os.ReadFile(NotFoundPagePath)
		if err != nil {
			log.Warnf("read custom 404 page error: %v", err)
			buf = []byte(NotFound)
		}
	} else {
		buf = []byte(NotFound)
	}
	return buf
}

func NotFoundResponse() *http.Response {
	header := make(http.Header)
	header.Set("server", version.Full())
	header.Set("Content-Type", "text/html")

	content := getNotFoundPageContent()
	res := &http.Response{
		Status:        "Not Found",
		StatusCode:    404,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(content)),
		ContentLength: int64(len(content)),
	}
	return res
}
