package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	testURL = "https://speed.cloudflare.com/__down?bytes=10000000" // 10MB test file
)

type IPInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	Org     string `json:"org"`
	ASN     string `json:"asn"`
	Source  string `json:"source"`
}

type FieldValue struct {
	Value   string   `json:"value"`
	Sources []string `json:"sources"`
}

type IPInfoResult struct {
	Same       map[string]FieldValue   `json:"same"`
	Different  map[string][]FieldValue `json:"different"`
	AllSources []string                `json:"all_sources"`
}

type ProxyResult struct {
	Proxy           string       `json:"proxy"`
	Status          string       `json:"status"`
	IPInfo          IPInfoResult `json:"ip_info"`
	Latency         string       `json:"latency"`
	DownloadSpeed   string       `json:"download_speed"`
	DownloadSpeedMB float64      `json:"download_speed_mb"`
	TotalBytes      string       `json:"total_bytes"`
	DownloadTime    string       `json:"download_time"`
	Error           string       `json:"error"`
}

type IPCheckAPI struct {
	Name      string
	URL       string
	Fields    map[string]string
	ParseFunc func(string) (IPInfoResult, error)
}

var ipCheckAPIs = []IPCheckAPI{
	{
		Name: "speedtestcn",
		URL:  "https://api-v3.speedtest.cn/ip",
		Fields: map[string]string{
			"ip":      "data.ip",
			"country": "data.country",
			"region":  "data.province",
			"city":    "data.city",
			"org":     "data.isp",
			"asn":     "data.operator",
		},
	},
	{
		Name: "ipip",
		URL:  "https://myip.ipip.net/",
		ParseFunc: func(text string) (IPInfoResult, error) {
			parts := strings.Split(text, "：")
			if len(parts) < 3 {
				return IPInfoResult{}, fmt.Errorf("invalid response format")
			}
			ip := strings.TrimSpace(parts[1])
			location := strings.TrimSpace(parts[2])
			locationParts := strings.Split(location, " ")

			result := IPInfoResult{
				Same:       make(map[string]FieldValue),
				Different:  make(map[string][]FieldValue),
				AllSources: []string{"ipip"},
			}

			result.Same["ip"] = FieldValue{
				Value:   ip,
				Sources: []string{"ipip"},
			}

			if len(locationParts) > 0 {
				result.Same["country"] = FieldValue{
					Value:   locationParts[0],
					Sources: []string{"ipip"},
				}
			}

			if len(locationParts) > 1 {
				result.Same["region"] = FieldValue{
					Value:   locationParts[1],
					Sources: []string{"ipip"},
				}
			}

			if len(locationParts) > 2 {
				result.Same["city"] = FieldValue{
					Value:   locationParts[2],
					Sources: []string{"ipip"},
				}
			}

			if len(locationParts) > 3 {
				result.Same["org"] = FieldValue{
					Value:   locationParts[len(locationParts)-1],
					Sources: []string{"ipip"},
				}
			}

			return result, nil
		},
	},
	{
		Name: "ip.sb",
		URL:  "https://api.ip.sb/geoip",
		Fields: map[string]string{
			"ip":      "ip",
			"country": "country",
			"region":  "region",
			"city":    "city",
			"org":     "organization",
			"asn":     "asn_organization",
		},
	},
	{
		Name: "ipinfo",
		URL:  "https://ipinfo.io/json",
		Fields: map[string]string{
			"ip":      "ip",
			"country": "country",
			"region":  "region",
			"city":    "city",
			"org":     "org",
			"asn":     "asn",
		},
	},
	{
		Name: "ipapi",
		// Public token from ip.skk.moe
		URL: "https://ipinfo.io/json?token=ba0234c01f79d3",
		Fields: map[string]string{
			"ip":      "ip",
			"country": "country_name",
			"region":  "region",
			"city":    "city",
			"org":     "org",
			"asn":     "asn",
		},
	},
	{
		Name: "ip-api",
		// Public token from ip.skk.moe
		URL: "https://pro.ip-api.com/json/?fields=16985625&key=EEKS6bLi6D91G1p",
		Fields: map[string]string{
			"ip":      "query",
			"country": "country",
			"region":  "regionName",
			"city":    "city",
			"org":     "org",
			"asn":     "as",
		},
	},
	{
		Name: "cf(skkmoe)",
		URL:  "https://ip.skk.moe/cdn-cgi/trace",
		ParseFunc: func(text string) (IPInfoResult, error) {
			result := IPInfoResult{
				Same:       make(map[string]FieldValue),
				Different:  make(map[string][]FieldValue),
				AllSources: []string{"cf(skkmoe)"},
			}

			// Parse IP
			if ipIndex := strings.Index(text, "ip="); ipIndex != -1 {
				ipEnd := strings.Index(text[ipIndex:], "\n")
				if ipEnd != -1 {
					result.Same["ip"] = FieldValue{
						Value:   text[ipIndex+3 : ipIndex+ipEnd],
						Sources: []string{"cf(skkmoe)"},
					}
				}
			}

			// Parse country
			if locIndex := strings.Index(text, "loc="); locIndex != -1 {
				locEnd := strings.Index(text[locIndex:], "\n")
				if locEnd != -1 {
					result.Same["country"] = FieldValue{
						Value:   text[locIndex+4 : locIndex+locEnd],
						Sources: []string{"cf(skkmoe)"},
					}
				}
			}

			return result, nil
		},
	},
	{
		Name: "cf(chatgpt)",
		URL:  "https://chatgpt.com/cdn-cgi/trace",
		ParseFunc: func(text string) (IPInfoResult, error) {
			result := IPInfoResult{
				Same:       make(map[string]FieldValue),
				Different:  make(map[string][]FieldValue),
				AllSources: []string{"cf(chatgpt)"},
			}

			// Parse IP
			if ipIndex := strings.Index(text, "ip="); ipIndex != -1 {
				ipEnd := strings.Index(text[ipIndex:], "\n")
				if ipEnd != -1 {
					result.Same["ip"] = FieldValue{
						Value:   text[ipIndex+3 : ipIndex+ipEnd],
						Sources: []string{"cf(chatgpt)"},
					}
				}
			}

			// Parse country
			if locIndex := strings.Index(text, "loc="); locIndex != -1 {
				locEnd := strings.Index(text[locIndex:], "\n")
				if locEnd != -1 {
					result.Same["country"] = FieldValue{
						Value:   text[locIndex+4 : locIndex+locEnd],
						Sources: []string{"cf(chatgpt)"},
					}
				}
			}

			return result, nil
		},
	},
	{
		Name: "cf(cp)",
		URL:  "https://cp.cloudflare.com/cdn-cgi/trace",
		ParseFunc: func(text string) (IPInfoResult, error) {
			result := IPInfoResult{
				Same:       make(map[string]FieldValue),
				Different:  make(map[string][]FieldValue),
				AllSources: []string{"cf(cp)"},
			}

			// Parse IP
			if ipIndex := strings.Index(text, "ip="); ipIndex != -1 {
				ipEnd := strings.Index(text[ipIndex:], "\n")
				if ipEnd != -1 {
					result.Same["ip"] = FieldValue{
						Value:   text[ipIndex+3 : ipIndex+ipEnd],
						Sources: []string{"cf(cp)"},
					}
				}
			}

			// Parse country
			if locIndex := strings.Index(text, "loc="); locIndex != -1 {
				locEnd := strings.Index(text[locIndex:], "\n")
				if locEnd != -1 {
					result.Same["country"] = FieldValue{
						Value:   text[locIndex+4 : locIndex+locEnd],
						Sources: []string{"cf(cp)"},
					}
				}
			}

			return result, nil
		},
	},
	{
		Name: "ipwhois",
		URL:  "https://ipwho.is/",
		Fields: map[string]string{
			"ip":      "ip",
			"country": "country",
			"region":  "region",
			"city":    "city",
			"org":     "connection.org",
			"asn":     "connection.asn",
		},
	},
}

type ProxyTester struct {
	proxies []string
	client  *http.Client
	ctx     context.Context
}

func NewProxyTester(ctx context.Context, proxies []string) *ProxyTester {
	// Remove duplicate proxy list
	uniqueProxies := make(map[string]struct{})
	for _, proxy := range proxies {
		uniqueProxies[proxy] = struct{}{}
	}

	// Convert the deduplicated proxy list to a slice
	deduplicatedProxies := make([]string, 0, len(uniqueProxies))
	for proxy := range uniqueProxies {
		deduplicatedProxies = append(deduplicatedProxies, proxy)
	}

	return &ProxyTester{
		proxies: deduplicatedProxies,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		ctx: ctx,
	}
}

func (t *ProxyTester) TestProxy(proxy string) ProxyResult {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxy))
	if err != nil {
		return ProxyResult{
			Proxy:  proxy,
			Status: "Unavailable",
			Error:  fmt.Sprintf("Invalid proxy URL: %v", err),
		}
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	result := ProxyResult{
		Proxy:  proxy,
		Status: "Available",
	}

	// Test latency
	startTime := time.Now()
	resp, err := client.Get(testURL)
	if err != nil {
		result.Status = "Unavailable"
		result.Error = fmt.Sprintf("Connection failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Status = "Unavailable"
		result.Error = fmt.Sprintf("HTTP status: %d", resp.StatusCode)
		return result
	}

	latency := time.Since(startTime).Milliseconds()
	result.Latency = fmt.Sprintf("%dms", latency)

	// Test download speed
	startTime = time.Now()
	totalBytes := int64(0)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if err != nil && err != io.EOF {
			result.Status = "Unavailable"
			result.Error = fmt.Sprintf("Download failed: %v", err)
			return result
		}
		if n == 0 {
			break
		}
		totalBytes += int64(n)
	}
	downloadTime := time.Since(startTime).Seconds()
	if downloadTime == 0 {
		result.Status = "Unavailable"
		result.Error = "Download time is zero"
		return result
	}
	downloadSpeed := float64(totalBytes) / downloadTime
	result.DownloadSpeed = formatSpeed(downloadSpeed)
	result.DownloadSpeedMB = downloadSpeed / (1024 * 1024)
	result.TotalBytes = fmt.Sprintf("%.2fMB", float64(totalBytes)/(1024*1024))
	result.DownloadTime = fmt.Sprintf("%.2fs", downloadTime)

	// Get IP information
	ipInfo, err := t.getIPInfo(client)
	if err != nil {
		result.IPInfo = IPInfoResult{
			Same: map[string]FieldValue{
				"ip":      {Value: "Failed to get", Sources: []string{}},
				"country": {Value: "Failed to get", Sources: []string{}},
				"region":  {Value: "Failed to get", Sources: []string{}},
				"city":    {Value: "Failed to get", Sources: []string{}},
				"org":     {Value: "Failed to get", Sources: []string{}},
				"asn":     {Value: "Failed to get", Sources: []string{}},
			},
			Different:  make(map[string][]FieldValue),
			AllSources: []string{},
		}
	} else {
		result.IPInfo = ipInfo
	}

	return result
}

func (t *ProxyTester) getIPInfo(client *http.Client) (IPInfoResult, error) {
	var results []IPInfoResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Set request headers
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	}

	for _, api := range ipCheckAPIs {
		wg.Add(1)
		go func(api IPCheckAPI) {
			defer wg.Done()

			// Create request
			req, err := http.NewRequest("GET", api.URL, nil)
			if err != nil {
				return
			}

			// Add headers
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			// Send request
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Read response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			var info IPInfoResult
			if api.ParseFunc != nil {
				info, err = api.ParseFunc(string(body))
				if err != nil {
					return
				}
			} else {
				var data map[string]interface{}
				if err := json.Unmarshal(body, &data); err != nil {
					return
				}

				info = IPInfoResult{
					Same:       make(map[string]FieldValue),
					Different:  make(map[string][]FieldValue),
					AllSources: []string{api.Name},
				}

				for field, path := range api.Fields {
					value := getFieldValue(data, path)
					if value != "" {
						info.Same[field] = FieldValue{
							Value:   value,
							Sources: []string{api.Name},
						}
					}
				}
			}

			// Check if valid information was obtained
			if len(info.Same) == 0 {
				return
			}

			mu.Lock()
			results = append(results, info)
			mu.Unlock()
		}(api)
	}

	wg.Wait()

	if len(results) == 0 {
		return IPInfoResult{}, fmt.Errorf("Failed to get IP information")
	}

	// Analyze results
	fieldValues := make(map[string]map[string][]string)
	for _, result := range results {
		for field, info := range result.Same {
			if _, ok := fieldValues[field]; !ok {
				fieldValues[field] = make(map[string][]string)
			}
			fieldValues[field][info.Value] = append(fieldValues[field][info.Value], info.Sources...)
		}
	}

	// Build result
	finalResult := IPInfoResult{
		Same:       make(map[string]FieldValue),
		Different:  make(map[string][]FieldValue),
		AllSources: make([]string, 0),
	}

	// Find same and different results
	for field, values := range fieldValues {
		if len(values) == 1 {
			// All APIs return same value
			for value, sources := range values {
				finalResult.Same[field] = FieldValue{
					Value:   value,
					Sources: sources,
				}
				finalResult.AllSources = append(finalResult.AllSources, sources...)
			}
		} else {
			// Different APIs return different values
			var diffs []FieldValue
			for value, sources := range values {
				diffs = append(diffs, FieldValue{
					Value:   value,
					Sources: sources,
				})
				finalResult.AllSources = append(finalResult.AllSources, sources...)
			}
			finalResult.Different[field] = diffs
		}
	}

	// Deduplicate and sort all sources
	sourceMap := make(map[string]bool)
	for _, source := range finalResult.AllSources {
		sourceMap[source] = true
	}
	finalResult.AllSources = make([]string, 0, len(sourceMap))
	for source := range sourceMap {
		finalResult.AllSources = append(finalResult.AllSources, source)
	}
	sort.Strings(finalResult.AllSources)

	return finalResult, nil
}

func getFieldValue(data map[string]interface{}, fieldPath string) string {
	if fieldPath == "" {
		return ""
	}
	parts := strings.Split(fieldPath, ".")
	var value interface{} = data
	for _, part := range parts {
		if m, ok := value.(map[string]interface{}); ok {
			value = m[part]
		} else {
			return ""
		}
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func (t *ProxyTester) Run() []ProxyResult {
	var wg sync.WaitGroup
	results := make([]ProxyResult, len(t.proxies))
	sem := make(chan struct{}, 10) // Limit concurrency

	for i, proxy := range t.proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, proxy string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = t.TestProxy(proxy)
		}(i, proxy)
	}

	wg.Wait()

	// Sort by download speed
	sort.Slice(results, func(i, j int) bool {
		return results[i].DownloadSpeedMB > results[j].DownloadSpeedMB
	})

	return results
}

func formatSpeed(bytesPerSecond float64) string {
	if bytesPerSecond == 0 {
		return "0 B/s"
	}
	sizeName := []string{"B/s", "KB/s", "MB/s", "GB/s"}
	i := 0
	for bytesPerSecond >= 1024 && i < len(sizeName)-1 {
		bytesPerSecond /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", bytesPerSecond, sizeName[i])
}
