package pcap

import (
	"golang.org/x/sys/windows"
	"log"
	"reflect"
	"unsafe"
)

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetIpNetTable = modiphlpapi.NewProc("GetIpNetTable")
	procGetIfTable2   = modiphlpapi.NewProc("GetIfTable2")
	procFreeMibTable  = modiphlpapi.NewProc("FreeMibTable")
)

func getIpNetTable(ipNetTable PMIB_IPNETTABLE, sizePoint *uint32, order bool) error {
	r1, _, lastErr := procGetIpNetTable.Call(convertAddr(ipNetTable), convertAddr(sizePoint), convertAddr(&order))
	if r1 != 0 {
		return lastErr
	}
	return nil
}

func getIfTable2(ifTable *PMIB_IF_TABLE2) error {
	r1, _, lastErr := procGetIfTable2.Call(convertAddr(ifTable))
	if r1 != 0 {
		return lastErr
	}
	return nil
}

func freeMibTable(ifTable PMIB_IF_TABLE2) {
	call, _, err := procFreeMibTable.Call(convertAddr(ifTable))
	if call != 0 {
		log.Printf("free mib table failed: %v", err)
	}
}

func convertAddr[T any](in *T) uintptr {
	return uintptr(unsafe.Pointer(in))
}

func forceConvert[T any, V any](ptr *V) *T {
	return (*T)(unsafe.Pointer(ptr))
}

// convert wchar to []byte
// input MUST be point to sized byte Array
// example: *[111]byte
func wchar2bytes[T any](wchar *T) []byte {
	t := reflect.TypeFor[T]()
	if t.Kind() != reflect.Array || t.Elem().Kind() != reflect.Uint16 {
		panic("wchar2bytes: need array of uint16")
	}
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(wchar)),
		Len:  int(t.Size() * 2),
		Cap:  int(t.Size() * 2),
	}
	s := *(*[]byte)(unsafe.Pointer(&hdr))
	for i := 0; i < len(s); i += 2 {
		if s[i] == 0 && s[i+1] == 0 {
			return s[:i]
		}
	}
	return s
}
