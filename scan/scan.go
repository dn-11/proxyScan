package scan

import (
	"context"
	"github.com/hdu-dn11/proxyScan/pool"
	"github.com/hdu-dn11/proxyScan/scan/tcpscanner"
	"github.com/hdu-dn11/proxyScan/utils"
	"log"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type Scanner struct {
	UsePcap      bool
	TestUrl      string
	TestCallback func(resp *http.Response) bool
	TestTimeout  time.Duration
	PortScanRate int
}

func Default() *Scanner {
	return &Scanner{
		UsePcap: false,
		TestUrl: "http://www.gstatic.com/generate_204",
		TestCallback: func(resp *http.Response) bool {
			return resp != nil && resp.StatusCode/100 == 2
		},
		TestTimeout:  time.Second * 15,
		PortScanRate: 3000,
	}
}

func ipGenerator(prefixs []netip.Prefix) func(func(addr netip.Addr)) {
	return func(yield func(addr netip.Addr)) {
		t := time.NewTicker(3 * time.Second)
		all := 0
		current := 0
		for _, prefix := range prefixs {
			all += 1 << (32 - prefix.Bits())
		}
		for _, prefix := range prefixs {
			count := 1 << (32 - prefix.Bits())
			ip := prefix.Masked().Addr()
			for i := 0; i < count; i++ {
				yield(ip)
				ip = ip.Next()
				select {
				case <-t.C:
					log.Printf("Generator %f%%\n", float64(current)/float64(all)*100)
				default:
				}
				current++
			}
		}
	}
}

func (s *Scanner) ScanAll(prefixs []netip.Prefix, port []int) []netip.AddrPort {
	c := utils.NewCollector[netip.AddrPort]()

	addrCount := 0
	for _, prefix := range prefixs {
		addrCount += 1 << (32 - prefix.Bits())
	}

	var sc tcpscanner.Scanner

	if s.UsePcap {
		psc, err := tcpscanner.NewPcapScanner(context.Background(), s.PortScanRate)
		if err != nil {
			log.Fatal(err)
		}
		sc = psc
	} else {
		sc = tcpscanner.NewSystemScanner(context.Background(), s.PortScanRate)
	}

	go func() {
		for addrPort := range sc.Alive() {
			log.Println("[+]", addrPort.String())
			c.C <- addrPort
		}
	}()

	ipGenerator(prefixs)(func(addr netip.Addr) {
		for _, pt := range port {
			sc.Send(netip.AddrPortFrom(addr, uint16(pt)))
		}
	})
	log.Println("wait for tcp scan.")
	sc.End()

	log.Println("tcp scan done.")
	aliveTCPAddrs := c.Return()

	log.Println("start socks5 scan with 128 threads.")
	p := pool.Pool{Size: 128, Buffer: 128}
	p.Init()
	defer p.Close()
	c = utils.NewCollector[netip.AddrPort]()
	var wg sync.WaitGroup
	wg.Add(len(aliveTCPAddrs))
	for _, addrPort := range aliveTCPAddrs {
		p.Submit(func() {
			defer wg.Done()
			if s.scanSocks5(addrPort.String()) {
				c.C <- addrPort
				log.Printf("[+] socks5 %s", addrPort.String())
			}
		})
	}

	log.Println("wait for socks5 scan.")
	wg.Wait()
	log.Println("socks5 scan done.")
	return c.Return()
}
