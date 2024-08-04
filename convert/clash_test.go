package convert

import (
	"bytes"
	"github.com/hdu-dn11/proxyScan/scan/socks5"
	"net/netip"
	"testing"
)

func TestClashTmpl(t *testing.T) {
	var buf bytes.Buffer
	err := clashTmpl.Execute(&buf, &socks5.Result{
		AddrPort: netip.MustParseAddrPort("127.0.0.1:7890"),
		Success:  true,
		UDP:      true,
	})
	if err != nil {
		t.Error(err)
	}
	t.Log(buf.String())
}

func TestClashTmpl2(t *testing.T) {
	var buf bytes.Buffer
	err := clashTmpl.Execute(&buf, &socks5.Result{
		AddrPort: netip.MustParseAddrPort("127.0.0.1:1"),
		Success:  true,
		UDP:      true,
	})
	if err != nil {
		t.Error(err)
	}
	t.Log(buf.String())
}
