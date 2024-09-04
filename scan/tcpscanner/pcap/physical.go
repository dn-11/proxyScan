//go:build !windows

package pcap

import (
	"fmt"
	"github.com/mdlayher/arp"
	"github.com/yaklang/pcap"
	"net"
	"net/netip"
)

func resolveHardwareAddress(iface *net.Interface, addr net.IP) (net.HardwareAddr, error) {
	arpc, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("arp dial: %v", err)
	}
	dstmac, err := arpc.Resolve(netip.MustParseAddr(addr.String()))
	if err != nil {
		return nil, fmt.Errorf("arp resolve: %v", err)
	}
	return dstmac, nil
}

func openLive(iface *net.Interface) (*pcap.Handle, error) {
	fmt.Printf("open live: %v\n", iface.Name)
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open live: %v", err)
	}
	return handle, nil
}
