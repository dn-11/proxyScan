package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/yaklang/pcap"
	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"
	"net"
	"slices"
	"unsafe"
)

// because the ip we query is gw, so it must exist in the arp table normally
func resolveHardwareAddress(iface *net.Interface, addr net.IP) (net.HardwareAddr, error) {
	size := uint32(0)
	var buffer []byte

	// It may exist timing issues, so we retry 3 times
	retry := 0
	for {
		// get buffer size
		_ = getIpNetTable(nil, &size, false)
		buffer = make([]byte, size)
		if err := getIpNetTable(forceConvert[_MIB_IPNETTABLE, byte](&buffer[0]), &size, false); err != nil && !errors.Is(err, windows.ERROR_SUCCESS) {
			if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
				return nil, err
			}
			retry++
			if retry > 3 {
				return nil, err
			}
			continue
		}
		break
	}
	res := forceConvert[_MIB_IPNETTABLE, byte](&buffer[0])
	ipnettable := unsafe.Slice(&res.table[0], res.dwNumEntries)
	uintip := binary.LittleEndian.Uint32(addr.To4())
	for _, row := range ipnettable {
		if row.dwAddr == uintip {
			// in ethernet, the hardware address is 6 bytes
			return row.bPhysAddr[:6], nil
		}
	}

	return nil, errors.New("not found")
}

func openLive(iface *net.Interface) (*pcap.Handle, error) {
	var ifTable PMIB_IF_TABLE2
	if err := getIfTable2(&ifTable); err != nil {
		return nil, err
	}
	ifTableSlice := unsafe.Slice(&ifTable.Table[0], ifTable.NumEntries)
	idx := slices.IndexFunc(ifTableSlice, func(i _MIB_IF_ROW2) bool { return i.InterfaceIndex == uint32(iface.Index) })
	if idx == -1 {
		return nil, errors.New("interface not found")
	}
	found := ifTableSlice[idx]
	path := fmt.Sprintf("\\Device\\NPF_%s", found.InterfaceGuid.String())
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	idx = slices.IndexFunc(ifs, func(i pcap.Interface) bool { return i.Name == path })
	if idx == -1 {
		return nil, errors.New("interface not found")
	}
	name, err := wchar2string(&found.Alias)
	if err != nil {
		name = iface.Name
	}
	fmt.Printf("open live: %s\n", name)
	return pcap.OpenLive(ifs[idx].Name, 1600, true, 0)
}

func wchar2string[T any](wchar *T) (string, error) {
	bytes, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(wchar2bytes(wchar))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
