package scan

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net/http"
)

type GeoIP struct {
	Ip            string  `json:"ip"`
	ContinentCode string  `json:"continent_code"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"country_code"`
	CountryCode3  string  `json:"country_code3"`
	Region        string  `json:"region"`
	RegionCode    string  `json:"region_code"`
	City          string  `json:"city"`
	PostalCode    string  `json:"postal_code"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Timezone      string  `json:"timezone"`
	Offset        int     `json:"offset"`
	Asn           int     `json:"asn"`
	Organization  string  `json:"organization"`
}

func (s *Scanner) Position(addrPort string) (*GeoIP, error) {
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
		Timeout: s.TestTimeout,
	}
	resp, err := c.Get("https://ip.seeip.org/geoip")
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
