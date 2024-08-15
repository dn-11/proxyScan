package geoip

import (
	"encoding/json"
	"log"
	"net/http"
)

type ipsbResp struct {
	Organization    string  `json:"organization"`
	Longitude       float64 `json:"longitude"`
	City            string  `json:"city"`
	Timezone        string  `json:"timezone"`
	Isp             string  `json:"isp"`
	Offset          int     `json:"offset"`
	Region          string  `json:"region"`
	Asn             int     `json:"asn"`
	AsnOrganization string  `json:"asn_organization"`
	Country         string  `json:"country"`
	Ip              string  `json:"ip"`
	Latitude        float64 `json:"latitude"`
	PostalCode      string  `json:"postal_code"`
	ContinentCode   string  `json:"continent_code"`
	CountryCode     string  `json:"country_code"`
	RegionCode      string  `json:"region_code"`
}

func IPsb(c *http.Client) *GeoIP {
	req, err := http.NewRequest(http.MethodGet, "https://api-ipv4.ip.sb/geoip", nil)
	if err != nil {
		log.Printf("ip.sb geo request: %v", err)
		return nil
	}

	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("ip.sb do request: %v", err)
		return nil
	}

	var ipResp ipsbResp
	if err := json.NewDecoder(resp.Body).Decode(&ipResp); err != nil {
		log.Printf("ip.sb decode response: %v", err)
		return nil
	}

	return &GeoIP{
		City:    ipResp.City,
		Country: ipResp.Country,
		ASOrg:   ipResp.AsnOrganization,
	}
}
