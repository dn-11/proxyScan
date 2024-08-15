package geoip

import (
	"fmt"
	"golang.org/x/net/proxy"
	"net/http"
	"time"
)

type GeoIP struct {
	City    string
	Country string
	ASOrg   string
}

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0"

var (
	TestTimeout = time.Second * 5
)

var tryOrder = []func(*http.Client) *GeoIP{
	CloudFlare, IPsb, ipWho,
}

func GetGeo(addrPort string) (*GeoIP, error) {
	dialer, err := proxy.SOCKS5("tcp", addrPort, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	dialerCtx, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, err
	}
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: dialerCtx.DialContext,
		},
		Timeout: TestTimeout,
	}

	for _, f := range tryOrder {
		if geo := f(c); geo != nil {
			return geo, nil
		}
	}

	return nil, fmt.Errorf("no geoip found")
}
