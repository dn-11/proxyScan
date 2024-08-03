package tcpscanner

import "net/netip"

type Scanner interface {
	Alive() chan netip.AddrPort
	Send(netip.AddrPort)
	End()
}
