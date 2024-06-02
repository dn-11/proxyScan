package tcpport

import (
	"net"
	"time"
)

type Common struct{}

func NewCommonScanner() *Common {
	return &Common{}
}

func CommonScan(addrPort string) bool {
	conn, err := net.DialTimeout("tcp", addrPort, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
