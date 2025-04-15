package cli

import (
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dn-11/proxyScan/convert"
	"github.com/dn-11/proxyScan/scan"
	"gopkg.in/yaml.v3"
)

func Cli() {
	var (
		Prefix  string
		Port    string
		TestURL string
		Output  string
		Pcap    bool
		Rate    int
		Report  bool
	)

	flag.StringVar(&Prefix, "prefix", "", "prefix")
	flag.StringVar(&Port, "port", "10808,10809,20170-20172,7890-7893", "split by , use - for range, eg: 10808,10809,20171-20172,7890-7893")
	flag.StringVar(&TestURL, "url", "http://www.gstatic.com/generate_204", "")
	flag.StringVar(&Output, "output", "proxies.yaml", "output file")
	flag.BoolVar(&Pcap, "pcap", false, "use pcap")
	flag.IntVar(&Rate, "rate", 3000, "rate, -1 for unlimited")
	flag.BoolVar(&Report, "report", false, "generate proxy test report")
	flag.Parse()

	// assert rate
	if !(Rate == -1 || Rate > 0) {
		log.Fatal("rate must be -1 or >0")
	}
	// parse prefix
	var prefixs []netip.Prefix
	for _, prefix := range strings.Split(Prefix, ",") {
		prefixs = append(prefixs, netip.MustParsePrefix(prefix))
	}

	// parse port
	var ports []int
	for _, port := range strings.Split(Port, ",") {
		if strings.Contains(port, "-") {
			strings.Split(port, "-")
			start, err := strconv.Atoi(strings.Split(port, "-")[0])
			if err != nil {
				log.Fatal(err)
			}
			end, err := strconv.Atoi(strings.Split(port, "-")[1])
			if err != nil {
				log.Fatal(err)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			i, err := strconv.Atoi(port)
			if err != nil {
				log.Fatal(err)
			}
			ports = append(ports, i)
		}
	}

	s := scan.Default()
	s.TestUrl = TestURL
	s.PortScanRate = Rate
	if Pcap {
		s.ScannerType = "pcap"
	}

	// setup signal handling
	sigChan := make(chan os.Signal, 1)
	doneChan := make(chan struct{})
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// start scanning
	go func() {
		list := s.ScanSocks5(prefixs, ports)

		// generate output
		output := make(map[string][]*convert.ClashSocks5Proxy)
		output["proxies"] = make([]*convert.ClashSocks5Proxy, 0, len(list))
		for _, addr := range list {
			output["proxies"] = append(output["proxies"], convert.ToClash(addr))
		}

		log.Printf("total %d proxies", len(list))
		data, err := yaml.Marshal(output)
		if err != nil {
			log.Fatal(err)
		}
		abs, _ := filepath.Abs(Output)
		log.Printf("output to %s", abs)
		err = os.WriteFile(Output, data, 0644)
		if err != nil {
			log.Fatal(err)
		}

		// Wait a moment to ensure file is written
		time.Sleep(1 * time.Second)
		close(doneChan)
	}()

	// wait for signal or scan completion
	select {
	case <-sigChan:
		log.Println("received termination signal, stopping scan...")
		log.Println("scan stopped")
		os.Exit(0)
	case <-doneChan:
		log.Println("scan completed")
	}

	// generate report if -report flag is specified
	if Report {
		// Wait a moment to ensure file is written
		time.Sleep(1 * time.Second)
		GenerateReport()
	}
}
