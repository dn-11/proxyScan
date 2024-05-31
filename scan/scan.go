package scan

import (
	"context"
	"fmt"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
	"net/netip"
	"proxyScan/pool"
	"proxyScan/utils"
	"sync"
	"time"
)

var (
	TestURL      = "http://www.gstatic.com/generate_204"
	TestCallback = func(resp *http.Response) bool {
		return resp != nil && resp.StatusCode/100 == 2
	}
	TestTimeout = time.Second * 15
)

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
					fmt.Printf("Generator %f%%\n", float64(current)/float64(all)*100)
				default:
				}
				current++
			}
		}
	}
}

func ScanAll(prefixs []netip.Prefix, port []int) []netip.AddrPort {
	c := utils.NewCollector[netip.AddrPort]()

	addrCount := 0
	for _, prefix := range prefixs {
		addrCount += 1 << (32 - prefix.Bits())
	}
	addrCount *= len(port)

	portScanner, err := NewTcpPort(context.Background(), 3000)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for addrPort := range portScanner.Alive {
			fmt.Println(addrPort.String(), " alive.")
			c.C <- addrPort
		}
	}()

	ipGenerator(prefixs)(func(addr netip.Addr) {
		for _, pt := range port {
			portScanner.Send(netip.AddrPortFrom(addr, uint16(pt)))
		}
	})

	fmt.Println("wait for tcp scan.")
	portScanner.Wait()
	aliveTCPAddrs := c.Return()
	fmt.Println("tcp scan done.")

	p := pool.Pool{Size: 32, Buffer: 16}
	p.Init()
	c = utils.NewCollector[netip.AddrPort]()
	var wg sync.WaitGroup
	wg.Add(len(aliveTCPAddrs))
	for _, addrPort := range aliveTCPAddrs {
		p.Submit(func() {
			defer wg.Done()
			if Socks5Scan(addrPort.String()) {
				c.C <- addrPort
				fmt.Printf("Found %s socks5 alive\n", addrPort.String())
			}
		})
	}

	wg.Wait()
	fmt.Println("socks5 scan done.")
	return c.Return()
}

//func TcpPortScan(addrPort string) bool {
//	conn, err := net.DialTimeout("tcp", addrPort, 2*time.Second)
//	if err != nil {
//		return false
//	}
//	conn.Close()
//	fmt.Printf("%s alive\n", addrPort)
//	return true
//}

func Socks5Scan(addrPort string) bool {
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
		Timeout: TestTimeout,
	}
	resp, err := c.Get(TestURL)

	defer c.CloseIdleConnections()
	return TestCallback(resp)
}
