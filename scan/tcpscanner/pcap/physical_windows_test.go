//go:build windows

package pcap

import (
	"github.com/libp2p/go-netroute"
	"net"
	"testing"
)

func TestResolve(t *testing.T) {
	c, _ := netroute.New()
	iface, gw, _, err := c.Route(net.ParseIP("1.1.1.1"))
	if err != nil {
		t.Error(err)
		return
	}
	address, err := resolveHardwareAddress(iface, gw)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(address)
}

func TestOpenLive(t *testing.T) {
	c, _ := netroute.New()
	iface, _, _, err := c.Route(net.ParseIP("1.1.1.1"))
	if err != nil {
		t.Error(err)
		return
	}
	_, err = openLive(iface)
	if err != nil {
		t.Error(err)
		return
	}
}
