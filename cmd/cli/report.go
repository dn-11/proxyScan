package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/dn-11/proxyScan/proxy_test"
	"gopkg.in/yaml.v3"
)

type ProxyConfig struct {
	Proxies []struct {
		Name     string `yaml:"name"`
		Type     string `yaml:"type"`
		Server   string `yaml:"server"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username,omitempty"`
		Password string `yaml:"password,omitempty"`
	} `yaml:"proxies"`
}

func GenerateReport() {
	// Read proxy list from scan results
	configFile := "proxies.yaml"
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var config ProxyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	// Build proxy address list
	var proxies []string
	for _, p := range config.Proxies {
		proxyAddr := fmt.Sprintf("%s:%d", p.Server, p.Port)
		proxies = append(proxies, proxyAddr)
	}

	if len(proxies) == 0 {
		log.Println("No available proxies found")
		return
	}

	// Create proxy tester
	tester := proxy_test.NewProxyTester(nil, proxies)

	// Run tests
	log.Println("Starting proxy tests...")
	results := tester.Run()

	// Generate report
	report := proxy_test.NewReport(results)
	if err := report.GenerateTXT("proxy_test_results.txt"); err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}

	log.Println("Proxy testing completed, results saved to proxy_test_results.txt")
}
