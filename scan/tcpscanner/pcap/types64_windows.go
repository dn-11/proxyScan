//go:build windows && amd64

package pcap

import (
	"golang.org/x/sys/windows"
)

const IF_MAX_STRING_SIZE = 256

type _MIB_IPNETROW_LH struct {
	dwIndex       uint32
	dwPhysAddrLen uint32
	bPhysAddr     [windows.MAXLEN_PHYSADDR]byte
	dwAddr        uint32
	dwType        uint32
}

type _MIB_IPNETTABLE struct {
	dwNumEntries uint32
	table        [1]_MIB_IPNETROW_LH
}

type PMIB_IPNETTABLE *_MIB_IPNETTABLE

type PULONG *uint32

type _MIB_IF_ROW2 struct {
	InterfaceLuid               windows.LUID
	InterfaceIndex              uint32
	InterfaceGuid               windows.GUID
	Alias                       [IF_MAX_STRING_SIZE + 1]uint16
	Description                 [IF_MAX_STRING_SIZE + 1]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [windows.MAXLEN_PHYSADDR]uint8
	PermanentPhysicalAddress    [windows.MAXLEN_PHYSADDR]uint8
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint8
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 windows.GUID
	ConnectionType              uint32
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
	IDONTKNOWWHY                [48]byte
}

type _MIB_IF_TABLE2 struct {
	NumEntries uint32
	Table      [1]_MIB_IF_ROW2
}

type PMIB_IF_TABLE2 *_MIB_IF_TABLE2
