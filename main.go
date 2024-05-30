package main

import (
	"flag"
	"gopkg.in/yaml.v3"
	"log"
	"net/netip"
	"os"
	"proxyScan/scan"
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
)

func main() {
	flag.StringVar(&ArgPrefix, "prefix", "", "prefix")
	flag.StringVar(&ArgPort, "port", "10808,10809,20171,20170,20172,7890,7891,7892,7893", "")
	flag.StringVar(&ArgTestURL, "url", "http://www.gstatic.com/generate_204", "")
	flag.StringVar(&ArgOutput, "output", "proxies.yaml", "output file")
	flag.Parse()

	scan.TestURL = ArgTestURL

	var prefixs []netip.Prefix
	for _, prefix := range strings.Split(ArgPrefix, ",") {
		prefixs = append(prefixs, netip.MustParsePrefix(prefix))
	}

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

	list := scan.ScanAll(prefixs, ports)
	output := make(map[string][]Proxy)
	output["proxies"] = make([]Proxy, 0, len(list))
	for _, addr := range list {
		name, err := scan.Position(addr.String())
		if err != nil {
			log.Println(err)
			name = "[Unknown]" + addr.String()
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
