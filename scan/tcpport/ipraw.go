//go:build !windows

package tcpport

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hdu-dn11/proxyScan/utils"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"
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
	conn, err := net.DialIP("ip:6", nil, &net.IPAddr{})
	if err != nil {
		return nil, fmt.Errorf("dial ip: %v", err)
	}
	localIP, err := utils.LocalIP()
	if err != nil {
		return nil, fmt.Errorf("get local ip: %v", err)
	}

	ctx2, cancelRead := context.WithCancel(ctx)
	s := &IPRawScanner{
		Alive:      make(chan netip.AddrPort, 1024),
		pending:    utils.NewTTLSet[netip.AddrPort](time.Second * 10),
		cancelRead: cancelRead,
		conn:       conn,
		srcIP:      localIP,
	}
	go s.recLoop(ctx2)
	return s, nil
}

func (c *IPRawScanner) Send(addr netip.AddrPort) {
	networkLayer := &layers.IPv4{
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         uint16(rand.IntN(65535)),
		Flags:      0x2,
		FragOffset: 0,
		TTL:        128,
		Protocol:   layers.IPProtocolTCP,
		Checksum:   0,
		SrcIP:      c.srcIP.(*net.IPNet).IP,
		DstIP:      addr.Addr().AsSlice(),
		Options:    nil,
	}

	transportLayer := &layers.TCP{
		SrcPort:    layers.TCPPort(rand.IntN(55535) + 10000),
		DstPort:    layers.TCPPort(addr.Port()),
		Seq:        rand.Uint32(),
		Ack:        0,
		DataOffset: 0,
		Window:     uint16(rand.IntN(10000) + 10000),
		Checksum:   0,
		SYN:        true,
	}

	if err := transportLayer.SetNetworkLayerForChecksum(networkLayer); err != nil {
		log.Println("set network layer for checksum error: ", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		networkLayer, transportLayer); err != nil {
		log.Println("serialize layers error: ", err)
		return
	}
	ipaddr, err := net.ResolveIPAddr("ip4", addr.String())
	if err != nil {
		log.Printf("resolve ip addr: %v", err)
	}
	_, err = c.conn.WriteTo(buf.Bytes(), ipaddr)
	if err != nil {
		log.Fatalf("write ip conn: %v", err)
	}
	c.pending.Add(addr)
}

func (c *IPRawScanner) recLoop(ctx context.Context) {
	defer close(c.Alive)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buf := make([]byte, 1600)
			n, err := c.conn.Read(buf)
			if err != nil {
				log.Fatalf("read fail: %v", err)
			}
			// tcp syn-ack is short, skip big packet
			if n > 100 {
				continue
			}
			buf = buf[:n]

			pk := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
			nwLayer, ok := pk.NetworkLayer().(*layers.IPv4)
			if !ok {
				continue
			}
			ip := nwLayer.SrcIP
			tcpLayer, ok := pk.TransportLayer().(*layers.TCP)
			if !ok {
				continue
			}
			if !(tcpLayer.SYN && tcpLayer.ACK) {
				continue
			}
			netipip, ok := netip.AddrFromSlice(ip.To4())
			if !ok {
				continue
			}
			addrPort := netip.AddrPortFrom(netipip, uint16(tcpLayer.SrcPort))
			if c.pending.Take(addrPort) {
				c.Alive <- addrPort
			}
		}
	}
}

func (c *IPRawScanner) Wait() {
	c.pending.Wait()
	c.cancelRead()
}
