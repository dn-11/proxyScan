package geoip

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net/http"
	"time"
)

type GeoIP struct {
	Query       string  `json:"query"`
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	Isp         string  `json:"isp"`
	Org         string  `json:"org"`
	As          string  `json:"as"`
}

var TestTimeout = time.Second * 5

func GetGeo(addrPort string) (*GeoIP, error) {
	dialer, err := proxy.SOCKS5("tcp", addrPort, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	dialerCtx, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, err
	}
	c := http.Client{
		Transport: &http.Transport{
			DialContext: dialerCtx.DialContext,
		},
		Timeout: TestTimeout,
	}
	resp, err := c.Get("http://ip-api.com/json/")
	if err != nil {
		return nil, err
	}
	defer c.CloseIdleConnections()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}
	var geo GeoIP
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &geo)
	if err != nil {
		return nil, err
	}

	return &geo, nil
}
