package system

import (
	"context"
	"github.com/dn-11/proxyScan/scan/tcpscanner"
	"github.com/dn-11/proxyScan/utils"
	"golang.org/x/time/rate"
	"net"
	"net/netip"
	"sync"
	"time"
)

func init() {
	tcpscanner.Register("system", NewScanner)
}

const WaitTimeout = 2 * time.Second

type Scanner struct {
	alive chan netip.AddrPort
	end   bool

	ctx     context.Context
	limiter *rate.Limiter
	wg      sync.WaitGroup
}

func (c *Scanner) Alive() chan netip.AddrPort {
	return c.alive
}

func (c *Scanner) Send(addrPort netip.AddrPort) {
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

func (c *Scanner) End() {
	c.end = true
	c.wg.Wait()
	close(c.alive)
}

func NewScanner(ctx context.Context, rate int) (tcpscanner.Scanner, error) {
	return &Scanner{
		alive:   make(chan netip.AddrPort, 1024),
		end:     false,
		limiter: utils.ParseLimiter(rate),
		ctx:     ctx,
	}, nil
}

var _ tcpscanner.Scanner = (*Scanner)(nil)
