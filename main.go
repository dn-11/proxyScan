package main

import (
	"github.com/dn-11/proxyScan/cmd/cli"

	// import scanner plugins
	_ "github.com/dn-11/proxyScan/scan/tcpscanner/system"
)

func main() {
	cli.Cli()
}
