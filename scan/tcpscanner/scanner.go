package tcpscanner

import (
	"context"
	"errors"
	"net/netip"
)

var list = make(map[string]func(ctx context.Context, rate int) (Scanner, error))

func Register(name string, f func(ctx context.Context, rate int) (Scanner, error)) {
	list[name] = f
}

var ErrScannerNotFound = errors.New("scanner not found")

func Get(name string, ctx context.Context, rate int) (Scanner, error) {
	if f, ok := list[name]; ok {
		return f(ctx, rate)
	}
	return nil, ErrScannerNotFound
}

type Scanner interface {
	Alive() chan netip.AddrPort
	Send(netip.AddrPort)
	End()
}
