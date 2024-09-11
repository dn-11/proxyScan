package scan

import (
	"context"
	"github.com/dn-11/proxyScan/pool"
	"github.com/dn-11/proxyScan/scan/socks5"
	"github.com/dn-11/proxyScan/scan/tcpscanner"
	_ "github.com/dn-11/proxyScan/scan/tcpscanner/system"
	"github.com/dn-11/proxyScan/utils"
	"log"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type Scanner struct {
	ScannerType  string
	TestUrl      string
	TestCallback func(resp *http.Response) bool
	TestTimeout  time.Duration
	PortScanRate int
}

func Default() *Scanner {
	return &Scanner{
		ScannerType:  "system",
		TestUrl:      "http://www.gstatic.com/generate_204",
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
					log.Printf("IP Generator %d/%d(%f%%)\n", current, all, float64(current)/float64(all)*100)
				default:
				}
				current++
			}
		}
	}
}

func (s *Scanner) ScanSocks5(prefixs []netip.Prefix, port []int) []*socks5.Result {
	c := utils.NewCollector[netip.AddrPort]()

	addrCount := 0
	for _, prefix := range prefixs {
		addrCount += 1 << (32 - prefix.Bits())
	}

	sc, err := tcpscanner.Get(s.ScannerType, context.Background(), s.PortScanRate)
	if err != nil {
		log.Fatalf("get scanner failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for addrPort := range sc.Alive() {
			log.Println("[+]", addrPort.String())
			c.C <- addrPort
		}
		done <- struct{}{}
	}()

	ipGenerator(prefixs)(func(addr netip.Addr) {
		for _, pt := range port {
			sc.Send(netip.AddrPortFrom(addr, uint16(pt)))
		}
	})
	log.Println("wait for tcp scan.")
	sc.End()
	<-done

	log.Println("tcp scan done.")
	aliveTCPAddrs := c.Return()

	log.Println("start socks5 scan with 128 threads.")
	p := pool.Pool{Size: 128, Buffer: 128}
	p.Init()
	defer p.Close()
	res := utils.NewCollector[*socks5.Result]()
	var wg sync.WaitGroup
	wg.Add(len(aliveTCPAddrs))
	for _, addrPort := range aliveTCPAddrs {
		p.Submit(func() {
			defer wg.Done()
			info := socks5.GetInfo(addrPort)
			if info.Success {
				res.C <- info
				log.Printf("[+] socks5 %s", addrPort.String())
			} else {
				log.Printf("[-] not socks5 or too slow %s", addrPort.String())
			}
		})
	}

	log.Println("wait for socks5 scan.")
	wg.Wait()
	log.Println("socks5 scan done.")
	return res.Return()
}
