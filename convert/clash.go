package convert

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/hdu-dn11/proxyScan/scan/geoip"
	"github.com/hdu-dn11/proxyScan/scan/socks5"
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

func ToClash(res *socks5.Result) *ClashSocks5Proxy {
	var (
		buf  bytes.Buffer
		name string
	)
	if err := clashTmpl.Execute(&buf, res); err != nil {
		name = fmt.Sprintf("[Unknown]%s", res.AddrPort.String())
	} else {
		name = buf.String()
	}

	return &ClashSocks5Proxy{
		Name:   name,
		Type:   "socks5",
		Server: res.AddrPort.Addr().String(),
		Port:   int(res.AddrPort.Port()),
		Udp:    res.UDP,
	}
}
