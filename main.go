package main

import (
	"github.com/hdu-dn11/proxyScan/cmd/cli"

	// import scanner plugins
	_ "github.com/hdu-dn11/proxyScan/scan/tcpscanner/system"
)

func main() {
	cli.Cli()
}
