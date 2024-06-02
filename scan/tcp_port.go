package scan

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yaklang/pcap"
	"github.com/yaklang/yaklang/common/pcapx"
	"github.com/yaklang/yaklang/common/pcapx/pcaputil"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"proxyScan/utils"
	"time"
	_ "unsafe"
)

type TcpPort struct {
	Alive chan netip.AddrPort

	ctx        context.Context
	cancelSend context.CancelFunc
	cancelRead context.CancelFunc
	ticker     *time.Ticker
	pending    *utils.TTLSet[netip.AddrPort]

	handle    *pcap.Handle
	sendQueue chan []byte

	srcIP net.IP

	sendDone chan struct{}
}

//go:linkname GetPublicRoute github.com/yaklang/yaklang/common/pcapx.getPublicRoute
func GetPublicRoute() (*net.Interface, net.IP, net.IP, error)

func NewTcpPort(ctx context.Context, rate int) (*TcpPort, error) {
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
	ctxSend, cancelSend := context.WithCancel(ctx)
	ctxRead, cancelRead := context.WithCancel(ctx)
	scanner := &TcpPort{
		Alive:      make(chan netip.AddrPort, 1024),
		handle:     h,
		ticker:     time.NewTicker(time.Second / time.Duration(rate)),
		sendQueue:  make(chan []byte, 1024),
		ctx:        ctx,
		pending:    utils.NewTTLSet[netip.AddrPort](time.Second * 10),
		srcIP:      src,
		sendDone:   make(chan struct{}),
		cancelSend: cancelSend,
		cancelRead: cancelRead,
	}
	go scanner.sendLoop(ctxSend)
	go scanner.recLoop(ctxRead)
	return scanner, nil
}

func (t *TcpPort) Send(addr netip.AddrPort) {
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

	t.sendQueue <- buf.Bytes()
	t.pending.Add(addr)
}

func (t *TcpPort) Wait() {
	close(t.sendQueue)
	for len(t.sendQueue) != 0 {
		time.Sleep(time.Millisecond * 300)
	}
	t.cancelSend()
	<-t.sendDone
	t.handle.Close()
	t.pending.Wait()
	t.cancelRead()
}

func (t *TcpPort) sendLoop(ctx context.Context) {
	defer func() {
		t.sendDone <- struct{}{}
	}()
	for {
		select {
		case <-ctx.Done():
			t.ticker.Stop()
			return
		case <-t.ticker.C:
			select {
			case pk := <-t.sendQueue:
				// channel closed
				if pk == nil {
					return
				}
				err := t.handle.WritePacketData(pk)
				if err != nil {
					log.Printf("send packet error: %v", err)
				}
			default:
			}
		}
	}
}

func (t *TcpPort) recLoop(ctx context.Context) {
	defer close(t.Alive)
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
				t.Alive <- addrPort
			}
		}
	}
}
