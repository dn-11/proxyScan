package convert

import (
	"bytes"
	"errors"
	"github.com/hdu-dn11/proxyScan/scan/geoip"
	"github.com/hdu-dn11/proxyScan/scan/socks5"
	"github.com/hdu-dn11/proxyScan/utils"
	"net"
	"strconv"
	"text/template"
)

type ClashSocks5Proxy struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
	Udp    bool   `yaml:"udp"`
}

var ErrInvalidSocks5Result = errors.New("invalid input")

var clashTmpl = template.Must(template.New("clash").Funcs(template.FuncMap{
	"geo": func(addrPort string) *geoip.GeoIP {
		pos, err := geoip.GetGeo(addrPort)
		if err != nil {
			return nil
		}
		return pos
	},
}).Parse(`{{ $pos := geo .AddrPort }}
{{- with $pos -}}
[{{ .CountryCode }}{{ if and (ne "" .CountryCode) (ne "" .Region) }}-{{ end }}{{ .Region }}]
{{- $pos.Org }}({{$.AddrPort}})
{{- else -}}
[Unknown]{{ .AddrPort }}
{{- end }}`))

func ToClash(res *socks5.Result) (*ClashSocks5Proxy, error) {
	host, port, err := net.SplitHostPort(res.AddrPort)
	if err != nil {
		return nil, ErrInvalidSocks5Result
	}

	var buf bytes.Buffer
	if err := clashTmpl.Execute(&buf, res); err != nil {
		return nil, err
	}

	return &ClashSocks5Proxy{
		Name:   buf.String(),
		Type:   "socks5",
		Server: host,
		Port:   utils.Must(strconv.Atoi(port)),
		Udp:    res.UDP,
	}, nil
}
