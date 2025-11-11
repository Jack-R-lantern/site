package tests

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type nodeKey struct {
	Saddr    uint32
	Daddr    uint32
	Protocol uint8
	_        [7]byte
}

type nodeVal struct {
	Bytes    uint64
	LastSeen uint64
}

type podKey struct {
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Protocol uint8
	_        [3]byte
}

type podVal struct {
	Bytes    uint64
	LastSeen uint64
}

type skbMetadata struct {
	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VlanPresent    uint32
	VlanTCI        uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
	TcIndex        uint32
	CB             [5]uint32
	Hash           uint32
	TcClassID      uint32
	Data           uint32
	DataEnd        uint32
	NapiID         uint32
}

func raiseMemlock(t *testing.T) {
	var rlim unix.Rlimit
	rlim.Cur = ^uint64(0)
	rlim.Max = ^uint64(0)
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
		t.Logf("warn: failed to raise RLIMIT_MEMLOCK: %v", err)
	}
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	// 서로 다른 커널/런타임에서 메시지가 조금씩 다름
	msg := strings.ToLower(err.Error())
	return errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "bpf: not permitted")
}

func clearMap(t *testing.T, m *ebpf.Map) {
	t.Helper()

	it := m.Iterate()
	var key nodeKey
	var val nodeVal
	for it.Next(&key, &val) {
		if err := m.Delete(&key); err != nil {
			t.Fatalf("failed to delete key from map: %v", err)
		}
	}
	if err := it.Err(); err != nil {
		t.Fatalf("map iteration failed: %v", err)
	}
}

func ipv4NodeKey(packet []byte, base int) nodeKey {
	key := nodeKey{}
	key.Saddr = binary.BigEndian.Uint32(packet[base+12 : base+16])
	key.Daddr = binary.BigEndian.Uint32(packet[base+16 : base+20])
	key.Protocol = packet[base+9]
	return key
}

func buildIPv4TCPSKB(t *testing.T, withVLAN bool) []byte {
	t.Helper()

	const (
		ethernetHeaderLen = 14
		vlanHeaderLen     = 4
		ipv4HeaderLen     = 20
		tcpHeaderLen      = 20
	)

	etherTypeIPv4 := uint16(0x0800)
	etherTypeVLAN := uint16(0x8100)

	l3Start := ethernetHeaderLen
	totalLen := ethernetHeaderLen + ipv4HeaderLen + tcpHeaderLen

	if withVLAN {
		totalLen += vlanHeaderLen
		l3Start += vlanHeaderLen
	}

	pkt := make([]byte, totalLen)

	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})

	if withVLAN {
		binary.BigEndian.PutUint16(pkt[12:14], etherTypeVLAN)
		binary.BigEndian.PutUint16(pkt[14:16], 1)
		binary.BigEndian.PutUint16(pkt[16:18], etherTypeIPv4)
	} else {
		binary.BigEndian.PutUint16(pkt[12:14], etherTypeIPv4)
	}

	ipStart := l3Start
	ipEnd := ipStart + ipv4HeaderLen
	ip := pkt[ipStart:ipEnd]
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], ipv4HeaderLen+tcpHeaderLen)
	binary.BigEndian.PutUint16(ip[4:6], 0)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = 6
	binary.BigEndian.PutUint16(ip[10:12], 0)
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})

	tcpStart := ipEnd
	tcpEnd := tcpStart + tcpHeaderLen
	tcp := pkt[tcpStart:tcpEnd]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	binary.BigEndian.PutUint32(tcp[4:8], 0x11223344)
	binary.BigEndian.PutUint32(tcp[8:12], 0)
	tcp[12] = (5 << 4)
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)

	return pkt
}
