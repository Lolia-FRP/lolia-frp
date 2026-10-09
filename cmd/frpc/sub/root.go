// Copyright 2018 fatedier, fatedier@gmail.com
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

package sub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/fatedier/frp/pkg/util/banner"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
)

var (
	cfgFiles         []string
	cfgDir           string
	showVersion      bool
	strictConfigMode bool
	allowUnsafe      []string
	authTokens       []string

	bannerDisplayed bool
)

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&cfgFiles, "config", "c", []string{"./frpc.ini"}, "config files of frpc (support multiple files)")
	rootCmd.PersistentFlags().StringVarP(&cfgDir, "config_dir", "", "", "config directory, run one frpc service for each file in config directory")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "version of frpc")
	rootCmd.PersistentFlags().BoolVarP(&strictConfigMode, "strict_config", "", true, "strict config parsing mode, unknown fields will cause an errors")
	rootCmd.PersistentFlags().StringArrayVarP(&authTokens, "token", "t", []string{}, "authentication tokens in format 'id[,id2,...]:token' (LoliaFRP only)")
	rootCmd.PersistentFlags().StringSliceVarP(&allowUnsafe, "allow-unsafe", "", []string{},
		fmt.Sprintf("allowed unsafe features, one or more of: %s", strings.Join(security.ClientUnsafeFeatures, ", ")))
}

var rootCmd = &cobra.Command{
	Use:   "frpc",
	Short: "frpc is the client of frp (https://github.com/fatedier/frp)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Println(version.Full())
			return nil
		}

		unsafeFeatures := security.NewUnsafeFeatures(allowUnsafe)

		// If authTokens is provided, fetch config from API
		if len(authTokens) > 0 {
			err := runClientWithTokens(authTokens, unsafeFeatures)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			return nil
		}

		// If cfgDir is not empty, run multiple frpc service for each config file in cfgDir.
		if cfgDir != "" {
			_ = runMultipleClients(cfgDir, unsafeFeatures)
			return nil
		}

		// If multiple config files are specified, run one frpc service for each file
		if len(cfgFiles) > 1 {
			runMultipleClientsFromFiles(cfgFiles, unsafeFeatures)
			return nil
		}

		// Do not show command usage here.
		err := runClient(cfgFiles[0], unsafeFeatures)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return nil
	},
}

func runMultipleClients(cfgDir string, unsafeFeatures *security.UnsafeFeatures) error {
	var wg sync.WaitGroup
	err := filepath.WalkDir(cfgDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		wg.Add(1)
		time.Sleep(time.Millisecond)
		go func() {
			defer wg.Done()
			err := runClient(path, unsafeFeatures)
			if err != nil {
				fmt.Printf("frpc service error for config file [%s]\n", path)
			}
		}()
		return nil
	})
	wg.Wait()
	return err
}

func runMultipleClientsFromFiles(cfgFiles []string, unsafeFeatures *security.UnsafeFeatures) {
	var wg sync.WaitGroup

	// Display banner first
	banner.DisplayBanner()
	bannerDisplayed = true
	log.Infof("检测到 %d 个配置文件，将启动多个 frpc 服务实例", len(cfgFiles))

	for _, cfgFile := range cfgFiles {
		wg.Add(1)
		// Add a small delay to avoid log output mixing
		time.Sleep(100 * time.Millisecond)
		go func(path string) {
			defer wg.Done()
			err := runClient(path, unsafeFeatures)
			if err != nil {
				fmt.Printf("\n配置文件 [%s] 启动失败: %v\n", path, err)
			}
		}(cfgFile)
	}
	wg.Wait()
}

func Execute() {
	rootCmd.SetGlobalNormalizationFunc(config.WordSepNormalizeFunc)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func handleTermSignal(svr *client.Service) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	svr.GracefulClose(500 * time.Millisecond)
}

func runClient(cfgFilePath string, unsafeFeatures *security.UnsafeFeatures) error {
	// Load configuration
	result, err := config.LoadClientConfigResult(cfgFilePath, strictConfigMode)
	if err != nil {
		return err
	}
	if result.IsLegacyFormat {
		fmt.Printf("WARNING: ini format is deprecated and the support will be removed in the future, " +
			"please use yaml/json/toml format instead!\n")
	}

	return runClientWithAggregator(result, unsafeFeatures, cfgFilePath)
}

// runClientWithAggregator runs the client using the internal source aggregator.
func runClientWithAggregator(result *config.ClientConfigLoadResult, unsafeFeatures *security.UnsafeFeatures, cfgFilePath string) error {
	configSource := source.NewConfigSource()
	if err := configSource.ReplaceAll(result.Proxies, result.Visitors); err != nil {
		return fmt.Errorf("failed to set config source: %w", err)
	}

	var storeSource *source.StoreSource

	if result.Common.Store.IsEnabled() {
		storePath := result.Common.Store.Path
		if storePath != "" && cfgFilePath != "" && !filepath.IsAbs(storePath) {
			storePath = filepath.Join(filepath.Dir(cfgFilePath), storePath)
		}

		s, err := source.NewStoreSource(source.StoreSourceConfig{
			Path: storePath,
		})
		if err != nil {
			return fmt.Errorf("failed to create store source: %w", err)
		}
		storeSource = s
	}

	aggregator := source.NewAggregator(configSource)
	if storeSource != nil {
		aggregator.SetStoreSource(storeSource)
	}

	proxyCfgs, visitorCfgs, err := aggregator.Load()
	if err != nil {
		return fmt.Errorf("failed to load config from sources: %w", err)
	}

	proxyCfgs, visitorCfgs = config.FilterClientConfigurers(result.Common, proxyCfgs, visitorCfgs)
	proxyCfgs = config.CompleteProxyConfigurers(proxyCfgs)
	visitorCfgs = config.CompleteVisitorConfigurers(visitorCfgs)

	warning, err := validation.ValidateAllClientConfig(result.Common, proxyCfgs, visitorCfgs, unsafeFeatures)
	if warning != nil {
		fmt.Printf("WARNING: %v\n", warning)
	}
	if err != nil {
		return err
	}

	return startServiceWithAggregator(result.Common, aggregator, unsafeFeatures, cfgFilePath, "", "")
}

func startServiceWithAggregator(
	cfg *v1.ClientCommonConfig,
	aggregator *source.Aggregator,
	unsafeFeatures *security.UnsafeFeatures,
	cfgFile string,
	nodeName string,
	tunnelRemark string,
) error {
	log.InitLogger(cfg.Log.To, cfg.Log.Level, int(cfg.Log.MaxDays), cfg.Log.DisablePrintColor)

	// Display banner only once before starting the first service
	if !bannerDisplayed {
		banner.DisplayBanner()
		bannerDisplayed = true
	}

	// Display node information if available
	if nodeName != "" {
		log.Info("已获取到配置文件", "隧道名称", tunnelRemark, "使用节点", nodeName)
	}

	if cfgFile != "" {
		log.Infof("启动 frpc 服务 [%s]", cfgFile)
		defer log.Infof("frpc 服务 [%s] 已停止", cfgFile)
	}
	svr, err := client.NewService(client.ServiceOptions{
		Common:                 cfg,
		ConfigSourceAggregator: aggregator,
		UnsafeFeatures:         unsafeFeatures,
		ConfigFilePath:         cfgFile,
	})
	if err != nil {
		return err
	}

	shouldGracefulClose := cfg.Transport.Protocol == "kcp" || cfg.Transport.Protocol == "quic"
	if shouldGracefulClose {
		go handleTermSignal(svr)
	}
	return svr.Run(context.Background())
}

// APIResponse represents the response from LoliaFRP API
type APIResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Config       string `json:"config"`
		NodeName     string `json:"node_name"`
		TunnelRemark string `json:"tunnel_remark"`
	} `json:"data"`
}

// TokenInfo stores parsed ids and token from the -t parameter
type TokenInfo struct {
	IDs   []string
	Token string
}

func runClientWithTokens(tokens []string, unsafeFeatures *security.UnsafeFeatures) error {
	// Compatible with the following parameter inputs:
	// -t 10000:chinatelecom -t 10085:chinamobile
	// -t 10000:chinatelecom,10085:chinamobile
	// -t 10000,10001:chinatelecom
	// -t 10000:chinatelecom,10085,10086:chinamobile
	// ids belong to the next token if they appear between two token markers,
	// e.g. "10000:chinatelecom,10085,10086:chinamobile" means
	// 10000 belongs to chinatelecom and 28025,24470 belongs to chinamobile
	idTokenSplit := regexp.MustCompile(`(?:^|,)(\s*[0-9]+\s*:)`)
	expanded := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !strings.Contains(t, ":") {
			expanded = append(expanded, t)
			continue
		}
		matches := idTokenSplit.FindAllStringSubmatchIndex(t, -1)
		if len(matches) == 0 {
			expanded = append(expanded, t)
			continue
		}
		// leftover[i] is bare ids accumulated from the previous iteration
		// that should be prepended to segment i's id list. Also covers bare
		// ids that appear at the start of the string.
		leftover := make([]string, len(matches)+1)
		if matches[0][0] > 0 {
			head := strings.TrimRight(strings.TrimSpace(t[:matches[0][0]]), ",")
			leftover[0] = strings.TrimSpace(head)
		}
		for i := range matches {
			capStart, capEnd := matches[i][2], matches[i][3]
			colonPos := capEnd - 1
			thisId := strings.TrimSpace(t[capStart:colonPos])

			tokenStart := colonPos + 1
			var tokenEnd int
			if i+1 < len(matches) {
				tokenEnd = matches[i+1][0]
			} else {
				tokenEnd = len(t)
			}
			tokenStr := strings.TrimSpace(t[tokenStart:tokenEnd])
			if idx := strings.Index(tokenStr, ","); idx >= 0 {
				leftover[i+1] = tokenStr[idx+1:]
				tokenStr = tokenStr[:idx]
			}

			parts := []string{}
			if prev := leftover[i]; prev != "" {
				parts = append(parts, prev)
			}
			if thisId != "" {
				parts = append(parts, thisId)
			}
			expanded = append(expanded, strings.TrimSpace(strings.Join(parts, ",")+":"+tokenStr))
		}
		// Trailing bare ids after the last token belong to the last
		// token's id list.
		if last := leftover[len(matches)]; last != "" && len(expanded) > 0 {
			lastSeg := expanded[len(expanded)-1]
			if idx := strings.Index(lastSeg, ":"); idx >= 0 {
				expanded[len(expanded)-1] = lastSeg[:idx] + "," + last + lastSeg[idx:]
			}
		}
	}
	tokens = expanded

	// Parse all tokens (format: id:token)
	tokenInfos := make([]TokenInfo, 0, len(tokens))
	for _, t := range tokens {
		parts := strings.SplitN(t, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid token format '%s', expected 'id[,id2,...]:token'", t)
		}
		var ids []string
		for _, id := range strings.Split(parts[0], ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			return fmt.Errorf("invalid token format '%s', id list is empty", t)
		}
		tokenInfos = append(tokenInfos, TokenInfo{
			IDs:   ids,
			Token: strings.TrimSpace(parts[1]),
		})
	}

	// Group tokens by token value (same token can have multiple IDs)
	tokenToIDs := make(map[string][]string)
	for _, ti := range tokenInfos {
		tokenToIDs[ti.Token] = append(tokenToIDs[ti.Token], ti.IDs...)
	}

	// If we have multiple different tokens, start one service for each token group
	if len(tokenToIDs) > 1 {
		return runMultipleClientsWithTokens(tokenToIDs, unsafeFeatures)
	}

	// Get the single token and all its IDs
	var token string
	var ids []string
	for t, idList := range tokenToIDs {
		token = t
		ids = idList
		break
	}

	return runClientWithTokenAndIDs(token, ids, unsafeFeatures)
}

func runClientWithTokenAndIDs(token string, ids []string, unsafeFeatures *security.UnsafeFeatures) error {
	// Get API server address from environment variable
	apiServer := os.Getenv("LOLIA_API")
	if apiServer == "" {
		apiServer = "https://api.lolia.link"
	}

	// Build URL with query parameters
	url := fmt.Sprintf("%s/api/v1/tunnel/frpc/config?token=%s&id=%s", apiServer, token, strings.Join(ids, ","))
	// URL is constructed from trusted source (environment variable or hardcoded)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create API request: %v", err)
	}
	// Carry client version in User-Agent so the API knows which frpc version is requesting
	req.Header.Set("User-Agent", version.Full())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch config from API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status code: %d", resp.StatusCode)
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to decode API response: %v", err)
	}

	if apiResp.Code != 200 {
		return fmt.Errorf("API error: %s", apiResp.Msg)
	}

	// Decode base64 config
	configBytes, err := base64.StdEncoding.DecodeString(apiResp.Data.Config)
	if err != nil {
		return fmt.Errorf("failed to decode base64 config: %v", err)
	}

	// Load config directly from bytes
	return runClientWithConfig(configBytes, unsafeFeatures, apiResp.Data.NodeName, apiResp.Data.TunnelRemark)
}

func runMultipleClientsWithTokens(tokenToIDs map[string][]string, unsafeFeatures *security.UnsafeFeatures) error {
	var wg sync.WaitGroup

	// Display banner first
	banner.DisplayBanner()
	bannerDisplayed = true
	log.Infof("检测到 %d 个不同的 token，将并行启动多个 frpc 服务实例", len(tokenToIDs))

	index := 0
	for token, ids := range tokenToIDs {
		wg.Add(1)
		currentIndex := index
		currentToken := token
		currentIDs := ids
		totalCount := len(tokenToIDs)

		// Add a small delay to avoid log output mixing
		time.Sleep(100 * time.Millisecond)

		go func() {
			defer wg.Done()
			maskedToken := currentToken
			if len(maskedToken) > 6 {
				maskedToken = maskedToken[:3] + "***" + maskedToken[len(maskedToken)-3:]
			} else {
				maskedToken = "***"
			}
			log.Infof("[%d/%d] 启动 token: %s (IDs: %v)", currentIndex+1, totalCount, maskedToken, currentIDs)
			err := runClientWithTokenAndIDs(currentToken, currentIDs, unsafeFeatures)
			if err != nil {
				fmt.Printf("\nToken [%s] 启动失败: %v\n", maskedToken, err)
			}
		}()
		index++
	}
	wg.Wait()
	return nil
}

func runClientWithConfig(configBytes []byte, unsafeFeatures *security.UnsafeFeatures, nodeName, tunnelRemark string) error {
	// Render template first
	renderedBytes, err := config.RenderWithTemplate(configBytes, config.GetValues())
	if err != nil {
		return fmt.Errorf("failed to render template: %v", err)
	}

	var allCfg v1.ClientConfig
	if err := config.LoadConfigure(renderedBytes, &allCfg, strictConfigMode); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	cfg := &allCfg.ClientCommonConfig
	proxyCfgs := make([]v1.ProxyConfigurer, 0, len(allCfg.Proxies))
	for _, c := range allCfg.Proxies {
		proxyCfgs = append(proxyCfgs, c.ProxyConfigurer)
	}
	visitorCfgs := make([]v1.VisitorConfigurer, 0, len(allCfg.Visitors))
	for _, c := range allCfg.Visitors {
		visitorCfgs = append(visitorCfgs, c.VisitorConfigurer)
	}

	// Call Complete to fill in default values
	if err := cfg.Complete(); err != nil {
		return fmt.Errorf("failed to complete config: %v", err)
	}

	proxyCfgs, visitorCfgs = config.FilterClientConfigurers(cfg, proxyCfgs, visitorCfgs)
	proxyCfgs = config.CompleteProxyConfigurers(proxyCfgs)
	visitorCfgs = config.CompleteVisitorConfigurers(visitorCfgs)

	warning, err := validation.ValidateAllClientConfig(cfg, proxyCfgs, visitorCfgs, unsafeFeatures)
	if warning != nil {
		fmt.Printf("WARNING: %v\n", warning)
	}
	if err != nil {
		return err
	}

	return startService(cfg, proxyCfgs, visitorCfgs, unsafeFeatures, "", nodeName, tunnelRemark)
}
