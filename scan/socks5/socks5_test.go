package socks5

import (
	"github.com/txthinking/socks5"
	"testing"
)

func TestGetInfo(t *testing.T) {
	res := GetInfo("172.16.4.6:18080")
	t.Log(*res)
}

func TestRawDNS(t *testing.T) {
	//ExampleServer()
	c, err := socks5.NewClient("127.0.0.1:7890", "", "", 10, 10)
	if err != nil {
		t.Error(err)
		return
	}
	err = testUDPByDNS(c)
	if err != nil {
		t.Error(err)
	}
}
