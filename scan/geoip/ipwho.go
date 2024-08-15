package geoip

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type ipWhoResp struct {
	Ip            string  `json:"ip"`
	Success       bool    `json:"success"`
	Type          string  `json:"type"`
	Continent     string  `json:"continent"`
	ContinentCode string  `json:"continent_code"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"country_code"`
	Region        string  `json:"region"`
	RegionCode    string  `json:"region_code"`
	City          string  `json:"city"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	IsEu          bool    `json:"is_eu"`
	Postal        string  `json:"postal"`
	CallingCode   string  `json:"calling_code"`
	Capital       string  `json:"capital"`
	Borders       string  `json:"borders"`
	Flag          struct {
		Img          string `json:"img"`
		Emoji        string `json:"emoji"`
		EmojiUnicode string `json:"emoji_unicode"`
	} `json:"flag"`
	Connection struct {
		Asn    int    `json:"asn"`
		Org    string `json:"org"`
		Isp    string `json:"isp"`
		Domain string `json:"domain"`
	} `json:"connection"`
	Timezone struct {
		Id          string    `json:"id"`
		Abbr        string    `json:"abbr"`
		IsDst       bool      `json:"is_dst"`
		Offset      int       `json:"offset"`
		Utc         string    `json:"utc"`
		CurrentTime time.Time `json:"current_time"`
	} `json:"timezone"`
}

func ipWho(c *http.Client) *GeoIP {
	req, err := http.NewRequest(http.MethodGet, "https://ipwho.is/", nil)
	if err != nil {
		log.Printf("ipwho geo request: %v", err)
		return nil
	}

	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("ipwho do request: %v", err)
		return nil
	}

	var ipResp ipWhoResp
	if err := json.NewDecoder(resp.Body).Decode(&ipResp); err != nil {
		log.Printf("ipwho decode response: %v", err)
		return nil
	}

	return &GeoIP{
		City:    ipResp.City,
		Country: ipResp.Country,
		ASOrg:   ipResp.Connection.Org,
	}
}
