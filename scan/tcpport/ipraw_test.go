package tcpport

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestIPRaw(t *testing.T) {
	s, err := NewIPRawScanner(context.Background(), -1)
	if err != nil {
		t.Error(err)
	}
	ip := netip.MustParseAddr("60.176.40.0")
	go func() {
		for addrport := range s.Alive {
			t.Log(addrport.String())
		}
	}()
	for i := 0; i < 255*8; i++ {
		s.Send(netip.MustParseAddrPort(net.JoinHostPort(ip.String(), "7890")))
	}
	s.Wait()
}
