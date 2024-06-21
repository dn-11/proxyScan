package main

import (
	"flag"
	"fmt"
	"github.com/hdu-dn11/proxyScan/scan"
	"gopkg.in/yaml.v3"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type Proxy struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
	Udp    bool   `yaml:"udp"`
}

var (
	ArgPrefix  string
	ArgPort    string
	ArgTestURL string
	ArgOutput  string
	ArgPcap    bool
	ArgRate    int
)

func main() {
	flag.StringVar(&ArgPrefix, "prefix", "", "prefix")
	flag.StringVar(&ArgPort, "port", "10808,10809,20170-20172,7890-7893", "split by , use - for range, eg: 10808,10809,20171-20172,7890-7893")
	flag.StringVar(&ArgTestURL, "url", "http://www.gstatic.com/generate_204", "")
	flag.StringVar(&ArgOutput, "output", "proxies.yaml", "output file")
	flag.BoolVar(&ArgPcap, "pcap", false, "use pcap")
	flag.IntVar(&ArgRate, "rate", 3000, "rate, -1 for unlimited")
	flag.Parse()

	// assert rate
	if !(ArgRate == -1 || ArgRate > 0) {
		log.Fatal("rate must be -1 or >0")
	}

	// parse prefix
	var prefixs []netip.Prefix
	for _, prefix := range strings.Split(ArgPrefix, ",") {
		prefixs = append(prefixs, netip.MustParsePrefix(prefix))
	}

	// parse port
	var ports []int
	for _, port := range strings.Split(ArgPort, ",") {
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
	s.TestUrl = ArgTestURL
	s.PortScanRate = ArgRate
	s.UsePcap = ArgPcap
	list := s.ScanAll(prefixs, ports)

	// generate output
	output := make(map[string][]Proxy)
	output["proxies"] = make([]Proxy, 0, len(list))
	for _, addr := range list {
		var name string
		geo, err := s.Position(addr.String())
		if err != nil {
			log.Println(err)
			name = "[Unknown]" + addr.String()
		} else {
			pos := geo.City
			if pos == "" {
				pos = geo.Organization
			}
			name = fmt.Sprintf("[%s]%s(%s)", geo.CountryCode, pos, addr.String())
		}
		output["proxies"] = append(output["proxies"], Proxy{
			Name:   name,
			Type:   "socks5",
			Server: addr.Addr().String(),
			Port:   int(addr.Port()),
			Udp:    true,
		},
		)
	}

	data, err := yaml.Marshal(output)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(ArgOutput, data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
