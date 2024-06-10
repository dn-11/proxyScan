package tcpport

import (
	"context"
	"github.com/hdu-dn11/proxyScan/utils"
	"net"
	"net/netip"
)

type IPRawScanner struct {
	ctx     context.Context
	conn    *net.IPConn
	srcIP   net.Addr
	pending *utils.TTLSet[netip.AddrPort]
	Alive   chan netip.AddrPort

	cancelRead context.CancelFunc
}

func NewIPRawScanner(ctx context.Context, rate int) (*IPRawScanner, error) {
	panic("not supported on windows")
}

func (c *IPRawScanner) Send(addr netip.AddrPort) {
	panic("not supported on windows")
}

func (c *IPRawScanner) recLoop(ctx context.Context) {
	panic("not supported on windows")
}

func (c *IPRawScanner) Wait() {
	panic("not supported on windows")
}
