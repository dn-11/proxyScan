package pcap

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hdu-dn11/proxyScan/scan/tcpscanner"
	"github.com/hdu-dn11/proxyScan/utils"
	"github.com/yaklang/pcap"
	"github.com/yaklang/yaklang/common/pcapx"
	"github.com/yaklang/yaklang/common/pcapx/pcaputil"
	"golang.org/x/time/rate"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"
	_ "unsafe"
)

func init() {
	tcpscanner.Register("pcap", NewScanner)
}

type Scanner struct {
	ctx        context.Context
	cancelRead context.CancelFunc

	limiter *rate.Limiter
	handle  *pcap.Handle
	pending *utils.TTLSet[netip.AddrPort]
	end     bool

	srcIP net.IP
	alive chan netip.AddrPort
}

func (t *Scanner) Alive() chan netip.AddrPort {
	return t.alive
}

func (t *Scanner) End() {
	t.end = true
	t.pending.Wait()
	t.cancelRead()
}

var _ tcpscanner.Scanner = (*Scanner)(nil)

func NewScanner(ctx context.Context, r int) (tcpscanner.Scanner, error) {
	e, _, src, err := GetPublicRoute()
	if err != nil {
		return nil, err
	}
	eth, err := pcaputil.IfaceNameToPcapIfaceName(e.Name)
	if err != nil {
		return nil, fmt.Errorf("find pcap iface name: %v", err)
	}
	h, err := pcap.OpenLive(eth, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open live error: %v", err)
	}
	if err := h.SetBPFFilter("tcp and src host not " + src.String()); err != nil {
		return nil, fmt.Errorf("set bpf filter: %v", err)
	}
	ctxRead, cancelRead := context.WithCancel(ctx)
	scanner := &Scanner{
		alive:      make(chan netip.AddrPort, 1024),
		handle:     h,
		limiter:    utils.ParseLimiter(r),
		ctx:        ctx,
		pending:    utils.NewTTLSet[netip.AddrPort](time.Second * 5),
		srcIP:      src,
		cancelRead: cancelRead,
	}
	go scanner.recLoop(ctxRead)
	return scanner, nil
}

func (t *Scanner) Send(addr netip.AddrPort) {
	if t.end {
		log.Println("calling Send after ended is not allowed.")
		return
	}
	linkLayer, err := pcapx.GetPublicToServerLinkLayerIPv4()
	if err != nil {
		log.Printf("get link layer error: %v", err)
		return
	}

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
		SrcIP:      t.srcIP,
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
		linkLayer, networkLayer, transportLayer); err != nil {
		log.Println("serialize layers error: ", err)
		return
	}

	if err := t.limiter.Wait(t.ctx); err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			log.Printf("limiter: %v", err)
		}
		return
	}

	if err := t.handle.WritePacketData(buf.Bytes()); err != nil {
		log.Printf("write packet fail: %v", err)
		return
	}

	t.pending.Add(addr)
}

func (t *Scanner) recLoop(ctx context.Context) {
	defer close(t.alive)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			data, _, err := t.handle.ZeroCopyReadPacketData()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				log.Printf("read packet error: %v", err)
			}
			// tcp syn-ack is short, skip big packet
			if len(data) > 100 {
				continue
			}

			pk := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
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
			if t.pending.Take(addrPort) {
				t.alive <- addrPort
			}
		}
	}
}

//go:linkname GetPublicRoute github.com/yaklang/yaklang/common/pcapx.getPublicRoute
func GetPublicRoute() (*net.Interface, net.IP, net.IP, error)
