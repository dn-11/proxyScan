package utils

import (
	"fmt"
	"log"
	"net"
)

func LocalIP() (net.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("get iface addrs: %v", err)
		}
		for _, addr := range addrs {
			if addr.String() != "127.0.0.1" {
				return addr, nil
			}
		}
	}
	return nil, fmt.Errorf("not found local ip")
}
