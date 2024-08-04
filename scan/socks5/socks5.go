package socks5

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

var (
	TestURL         = "http://www.gstatic.com/generate_204"
	TestTimeout     = time.Second * 5
	TestUDPAddrPort = "1.1.1.1:53"
)

type Result struct {
	AddrPort netip.AddrPort
	Success  bool
	UDP      bool
}

func GetInfo(addrPort netip.AddrPort) *Result {
	res := &Result{
		AddrPort: addrPort,
		Success:  false,
		UDP:      false,
	}
	sc, err := socks5.NewClient(addrPort.String(), "", "", 15, 15)
	if err != nil {
		log.Printf("[-] new socks5 client failed (addr=%s): %v", addrPort, err)
		return res
	}

	c := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return sc.Dial(network, addr)
			},
		},
		Timeout: TestTimeout,
	}

	resp, err := c.Get(TestURL)
	defer c.CloseIdleConnections()
	if err != nil || resp == nil {
		return res
	}
	res.Success = true

	if err := testUDPByDNS(sc); err != nil {
		log.Printf("[-] test udp failed (addr=%s): %v", addrPort, err)
		return res
	}

	res.UDP = true
	return res
}

func testUDPByDNS(c *socks5.Client) error {
	conn, err := c.Dial("udp", TestUDPAddrPort)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(TestTimeout))

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	data, err := msg.Pack()
	n, err := conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("write length error, expect: " + strconv.Itoa(len(data)) + ", actual: " + strconv.Itoa(n))
	}

	var buf [1024]byte
	recLen, err := conn.Read(buf[:])
	if err != nil {
		return err
	}

	recMsg := &dns.Msg{}
	if err := recMsg.Unpack(buf[:recLen]); err != nil {
		return err
	}

	if len(recMsg.Answer) == 0 {
		return errors.New("no answer")
	}

	return nil
}
