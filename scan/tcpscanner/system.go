package tcpscanner

import (
	"context"
	"github.com/hdu-dn11/proxyScan/utils"
	"golang.org/x/time/rate"
	"net"
	"net/netip"
	"sync"
	"time"
)

const WaitTimeout = 2 * time.Second

type SystemScanner struct {
	alive chan netip.AddrPort
	end   bool

	ctx     context.Context
	limiter *rate.Limiter
	wg      sync.WaitGroup
}

func (c *SystemScanner) Alive() chan netip.AddrPort {
	return c.alive
}

func (c *SystemScanner) Send(addrPort netip.AddrPort) {
	if c.end {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		conn, err := net.DialTimeout("tcp", addrPort.String(), WaitTimeout)
		if err != nil {
			return
		}
		conn.Close()
		c.alive <- addrPort
	}()
}

func (c *SystemScanner) End() {
	c.end = true
	c.wg.Wait()
	close(c.alive)
}

func NewSystemScanner(ctx context.Context, rate int) *SystemScanner {
	return &SystemScanner{
		alive:   make(chan netip.AddrPort, 1024),
		end:     false,
		limiter: utils.ParseLimiter(rate),
		ctx:     ctx,
	}
}

var _ Scanner = (*SystemScanner)(nil)
