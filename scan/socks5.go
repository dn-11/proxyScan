package scan

import (
	"golang.org/x/net/proxy"
	"log"
	"net/http"
)

func (s *Scanner) scanSocks5(addrPort string) bool {
	dialer, err := proxy.SOCKS5("tcp", addrPort, nil, proxy.Direct)
	if err != nil {
		log.Println(err)
		return false
	}
	dialerCtx, ok := dialer.(proxy.ContextDialer)
	if !ok {
		log.Println("dialer is not a ContextDialer")
		return false
	}
	c := http.Client{
		Transport: &http.Transport{
			DialContext: dialerCtx.DialContext,
		},
		Timeout: s.TestTimeout,
	}
	resp, err := c.Get(s.TestUrl)

	defer c.CloseIdleConnections()
	return s.TestCallback(resp)
}
