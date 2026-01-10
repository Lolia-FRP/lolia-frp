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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/featuregate"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/fatedier/frp/pkg/util/banner"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
)

var (
	cfgFile          string
	cfgDir           string
	showVersion      bool
	strictConfigMode bool
	allowUnsafe      []string
	authToken        string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "./frpc.ini", "config file of frpc")
	rootCmd.PersistentFlags().StringVarP(&cfgDir, "config_dir", "", "", "config directory, run one frpc service for each file in config directory")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "version of frpc")
	rootCmd.PersistentFlags().BoolVarP(&strictConfigMode, "strict_config", "", true, "strict config parsing mode, unknown fields will cause an errors")
	rootCmd.PersistentFlags().StringVarP(&authToken, "token", "t", "", "authentication token of frpc (LoliaFRP only)")
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

		// If authToken is provided, fetch config from API
		if authToken != "" {
			err := runClientWithToken(authToken, unsafeFeatures)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			return nil
		}

		// If cfgDir is not empty, run multiple frpc service for each config file in cfgDir.
		// Note that it's only designed for testing. It's not guaranteed to be stable.
		if cfgDir != "" {
			_ = runMultipleClients(cfgDir, unsafeFeatures)
			return nil
		}

		// Do not show command usage here.
		err := runClient(cfgFile, unsafeFeatures)
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
	cfg, proxyCfgs, visitorCfgs, isLegacyFormat, err := config.LoadClientConfig(cfgFilePath, strictConfigMode)
	if err != nil {
		return err
	}
	if isLegacyFormat {
		fmt.Printf("WARNING: ini format is deprecated and the support will be removed in the future, " +
			"please use yaml/json/toml format instead!\n")
	}

	if len(cfg.FeatureGates) > 0 {
		if err := featuregate.SetFromMap(cfg.FeatureGates); err != nil {
			return err
		}
	}

	warning, err := validation.ValidateAllClientConfig(cfg, proxyCfgs, visitorCfgs, unsafeFeatures)
	if warning != nil {
		fmt.Printf("WARNING: %v\n", warning)
	}
	if err != nil {
		return err
	}

	return startService(cfg, proxyCfgs, visitorCfgs, unsafeFeatures, cfgFilePath, "", "")
}

func startService(
	cfg *v1.ClientCommonConfig,
	proxyCfgs []v1.ProxyConfigurer,
	visitorCfgs []v1.VisitorConfigurer,
	unsafeFeatures *security.UnsafeFeatures,
	cfgFile string,
	nodeName string,
	tunnelRemark string,
) error {
	log.InitLogger(cfg.Log.To, cfg.Log.Level, int(cfg.Log.MaxDays), cfg.Log.DisablePrintColor)

	// Display banner before starting the service
	banner.DisplayBanner()

	log.Infof("Nya! %s 启动中", version.Full())

	// Display node information if available
	if nodeName != "" {
		log.Info("已获取到配置文件", "隧道名称", tunnelRemark, "使用节点", nodeName)
	}

	if cfgFile != "" {
		log.Infof("启动 frpc 服务 [%s]", cfgFile)
		defer log.Infof("frpc 服务 [%s] 已停止", cfgFile)
	}
	svr, err := client.NewService(client.ServiceOptions{
		Common:         cfg,
		ProxyCfgs:      proxyCfgs,
		VisitorCfgs:    visitorCfgs,
		UnsafeFeatures: unsafeFeatures,
		ConfigFilePath: cfgFile,
	})
	if err != nil {
		return err
	}

	shouldGracefulClose := cfg.Transport.Protocol == "kcp" || cfg.Transport.Protocol == "quic"
	// Capture the exit signal if we use kcp or quic.
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

func runClientWithToken(token string, unsafeFeatures *security.UnsafeFeatures) error {
	// Get API server address from environment variable
	apiServer := os.Getenv("LOLIA_API")
	if apiServer == "" {
		apiServer = "https://api.lolia.link"
	}

	// Fetch config from API
	url := fmt.Sprintf("%s/api/v1/tunnel/frpc/config/%s", apiServer, token)
	// #nosec G107 -- URL is constructed from trusted source (environment variable or hardcoded)
	resp, err := http.Get(url)
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

	// Call Complete for all proxies to add name prefix (e.g., user.tunnel_name)
	for _, c := range proxyCfgs {
		c.Complete(cfg.User)
	}
	for _, c := range visitorCfgs {
		c.Complete(cfg)
	}

	if len(cfg.FeatureGates) > 0 {
		if err := featuregate.SetFromMap(cfg.FeatureGates); err != nil {
			return err
		}
	}

	warning, err := validation.ValidateAllClientConfig(cfg, proxyCfgs, visitorCfgs, unsafeFeatures)
	if warning != nil {
		fmt.Printf("WARNING: %v\n", warning)
	}
	if err != nil {
		return err
	}

	return startService(cfg, proxyCfgs, visitorCfgs, unsafeFeatures, "", nodeName, tunnelRemark)
}
