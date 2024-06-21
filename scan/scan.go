package scan

import (
	"context"
	"fmt"
	"github.com/hdu-dn11/proxyScan/pool"
	"github.com/hdu-dn11/proxyScan/scan/tcpport"
	"github.com/hdu-dn11/proxyScan/utils"
	"golang.org/x/net/proxy"
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

	if s.UsePcap {
		portScanner, err := tcpport.NewPcapScanner(context.Background(), s.PortScanRate)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for addrPort := range portScanner.Alive {
				log.Println(addrPort.String(), " alive.")
				c.C <- addrPort
			}
		}()
		ipGenerator(prefixs)(func(addr netip.Addr) {
			for _, pt := range port {
				portScanner.Send(netip.AddrPortFrom(addr, uint16(pt)))
			}
		})
		log.Println("wait for tcp scan.")
		portScanner.Wait()
	} else {
		p := pool.Pool{Size: s.PortScanRate, Buffer: s.PortScanRate}
		p.Init()
		var wg sync.WaitGroup
		wg.Add(addrCount * len(port))
		ipGenerator(prefixs)(func(addr netip.Addr) {
			for _, pt := range port {
				p.Submit(func() {
					defer wg.Done()
					if tcpport.CommonScan(addr.String() + ":" + fmt.Sprint(pt)) {
						addrport := netip.AddrPortFrom(addr, uint16(pt))
						log.Println(addrport.String(), " alive.")
						c.C <- addrport
					}
				})
			}
		})
		log.Println("wait for tcp scan.")
		wg.Wait()
	}
	log.Println("tcp scan done.")
	aliveTCPAddrs := c.Return()

	log.Println("start socks5 scan with 128 threads.")
	p := pool.Pool{Size: 128, Buffer: 128}
	p.Init()
	c = utils.NewCollector[netip.AddrPort]()
	var wg sync.WaitGroup
	wg.Add(len(aliveTCPAddrs))
	for _, addrPort := range aliveTCPAddrs {
		p.Submit(func() {
			defer wg.Done()
			if s.scanSocks5(addrPort.String()) {
				c.C <- addrPort
				log.Printf("Found %s socks5 alive\n", addrPort.String())
			}
		})
	}

	log.Println("wait for socks5 scan.")
	wg.Wait()
	log.Println("socks5 scan done.")
	return c.Return()
}

func (s *Scanner) scanSocks5(addrPort string) bool {
	dialer, err := proxy.SOCKS5("tcp", addrPort, nil, proxy.Direct)
	if err != nil {
		log.Println(err)
		return false
	}
	dialerCtx, ok := dialer.(proxy.ContextDialer)
	if !ok {
		log.Println("dialer is not a ContextDialer")
		return false
	}
	c := http.Client{
		Transport: &http.Transport{
			DialContext: dialerCtx.DialContext,
		},
		Timeout: s.TestTimeout,
	}
	resp, err := c.Get(s.TestUrl)

	defer c.CloseIdleConnections()
	return s.TestCallback(resp)
}
