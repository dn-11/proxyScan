package proxy

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Report struct {
	Results []ProxyResult
	TestURL string
}

func NewReport(results []ProxyResult) *Report {
	return &Report{
		Results: results,
		TestURL: "https://speed.cloudflare.com/__down?bytes=10000000", // 10MB test file
	}
}

func (r *Report) GenerateTXT(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "Test Time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Test URL: %s\n", r.TestURL)
	fmt.Fprintf(file, "Proxy Count: %d\n\n", len(r.Results))

	// Write test results
	fmt.Fprintln(file, "=== Test Results ===\n")
	availableCount := 0
	for _, result := range r.Results {
		fmt.Fprintf(file, "%s:\n", result.Proxy)
		fmt.Fprintf(file, "  Status: %s\n", result.Status)
		if result.Error != "" {
			fmt.Fprintf(file, "  Error: %s\n", result.Error)
		}
		if result.Latency != "" {
			fmt.Fprintf(file, "  Latency: %s\n", result.Latency)
		}
		if result.DownloadSpeed != "" {
			fmt.Fprintf(file, "  Download Speed: %s\n", result.DownloadSpeed)
		}
		if result.TotalBytes != "" {
			fmt.Fprintf(file, "  Total Bytes: %s\n", result.TotalBytes)
		}
		if result.DownloadTime != "" {
			fmt.Fprintf(file, "  Download Time: %s\n", result.DownloadTime)
		}

		// Write IP information
		if len(result.IPInfo.Same) > 0 {
			fmt.Fprintln(file, "  === IP Information ===")
			for field, value := range result.IPInfo.Same {
				fmt.Fprintf(file, "  %s: %s (Sources: %s)\n", field, value.Value, strings.Join(value.Sources, ", "))
			}
		}

		if len(result.IPInfo.Different) > 0 {
			fmt.Fprintln(file, "  === Different IP Information ===")
			for field, values := range result.IPInfo.Different {
				fmt.Fprintf(file, "  %s:\n", field)
				for _, value := range values {
					fmt.Fprintf(file, "    - %s (Sources: %s)\n", value.Value, strings.Join(value.Sources, ", "))
				}
			}
		}

		fmt.Fprintln(file, "\n"+strings.Repeat("=", 50)+"\n")

		// Count available proxies
		if result.Status == "Available" && result.Error == "" {
			availableCount++
		}
	}

	// Write statistics
	fmt.Fprintln(file, "\n=== Test Statistics ===")
	fmt.Fprintf(file, "Total Proxies: %d\n", len(r.Results))
	fmt.Fprintf(file, "Available Proxies: %d\n", availableCount)
	fmt.Fprintf(file, "Unavailable Proxies: %d\n", len(r.Results)-availableCount)
	if len(r.Results) > 0 {
		availabilityRate := float64(availableCount) / float64(len(r.Results)) * 100
		fmt.Fprintf(file, "Availability Rate: %.2f%%\n", availabilityRate)
	}

	return nil
}
