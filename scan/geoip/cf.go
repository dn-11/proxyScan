package geoip

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type cloudFlareResp struct {
	Ip             string `json:"ip"`
	City           string `json:"city"`
	Country        string `json:"country"`
	Flag           string `json:"flag"`
	CountryRegion  string `json:"countryRegion"`
	Region         string `json:"region"`
	Latitude       string `json:"latitude"`
	Longitude      string `json:"longitude"`
	AsOrganization string `json:"asOrganization"`
}

func CloudFlare(c *http.Client) *GeoIP {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://cloudflare-ip.html.zone/geo?_t=%d", time.Now().UnixMilli()), nil)
	if err != nil {
		log.Printf("cloudflare geo request: %v", err)
		return nil
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("cloudflare do request: %v", err)
		return nil
	}

	var cfResp cloudFlareResp
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		log.Printf("cloudflare decode response: %v", err)
		return nil
	}

	return &GeoIP{
		City:    cfResp.City,
		Country: cfResp.Country,
		ASOrg:   cfResp.AsOrganization,
	}
}
