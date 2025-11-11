package tests

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestNodeIngressUpdatesMap(t *testing.T) {
	coll, prog, ingressMap := loadNodeIngressObjects(t)
	defer coll.Close()

	t.Run("plain ethernet", func(t *testing.T) {
		clearMap(t, ingressMap)

		packet := []byte{
			// Ethernet header (dst/src/proto)
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0x08, 0x00,
			// IPv4 header (minimal 20bytes)
			0x45, 0x00, 0x00, 0x28,
			0x00, 0x01, 0x40, 0x00,
			0x40, unix.IPPROTO_TCP,
			0x00, 0x00,
			0x0a, 0x00, 0x00, 0x01,
			0x0a, 0x00, 0x00, 0x02,
			// minimal payload
			0xd2, 0xad, 0xbe, 0xef,
		}

		_, err := prog.Run(&ebpf.RunOptions{Data: packet})
		if err != nil {
			t.Fatalf("node_ingress run failed: %v", err)
		}

		key := ipv4NodeKey(packet, 14)
		var val nodeVal
		if err := ingressMap.Lookup(&key, &val); err != nil {
			t.Fatalf("failed to lookup key: %v", err)
		}

		if val.Bytes != uint64(len(packet)) {
			t.Fatalf("unexpected byte count: got %d want %d", val.Bytes, len(packet))
		}
		if val.LastSeen == 0 {
			t.Fatalf("last_seen was not updated")
		}

		// Ensure second run update the same entry.
		prev := val.LastSeen
		_, err = prog.Run(&ebpf.RunOptions{Data: packet})
		if err != nil {
			t.Fatalf("second run failed: %v", err)
		}

		if err := ingressMap.Lookup(&key, &val); err != nil {
			t.Fatalf("lookup after second run failed: %v", err)
		}
		expectedBytes := uint64(len(packet) * 2)
		if val.Bytes != expectedBytes {
			t.Fatalf("unexpected byte count: got %d want %d", val.Bytes, expectedBytes)
		}
		if val.LastSeen <= prev {
			t.Fatalf("last_seen did not advance: prev=%d now=%d", prev, val.LastSeen)
		}
	})
	t.Run("invalid ipv4 length", func(t *testing.T) {
		clearMap(t, ingressMap)

		packet := []byte{
			// Ethernet header (dst/src/proto)
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0x08, 0x00,
			// Truncated IP header
			0x45, 0x00, 0x00,
		}

		_, err := prog.Run(&ebpf.RunOptions{Data: packet})
		if err != nil {
			t.Fatalf("node_ingress run on invalid packet failed: %v", err)
		}

		it := ingressMap.Iterate()
		var key nodeKey
		var val nodeVal
		if it.Next(&key, &val) {
			t.Fatalf("map should be empty after invalid packet: %+v", key)
		}
		if err := it.Err(); err != nil {
			t.Fatalf("interation after invalid packet failed: %v", err)
		}
	})
}

func loadNodeIngressObjects(t *testing.T) (*ebpf.Collection, *ebpf.Program, *ebpf.Map) {
	t.Helper()

	elfPath := os.Getenv("BPF_ELF")
	if elfPath == "" {
		t.Skip("set BPF_ELF=<path to .o> to enable this test")
	}

	raiseMemlock(t)

	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     1,
			LogSizeStart: 128 * 1024,
		},
	})
	if isPermissionError(err) {
		t.Skipf("skip: kernel/namespace lacks capability to load BPF: %v", err)
	}
	if err != nil {
		t.Fatalf("failed to load node_ingress collection: %v", err)
	}

	prog, ok := coll.Programs["node_ingress"]
	if !ok {
		coll.Close()
		t.Fatalf("node_ingress program not found in collection")
	}

	m, ok := coll.Maps["node_ingress_map"]
	if !ok {
		coll.Close()
		t.Fatalf("node_ingress_map map not found in collection")
	}

	return coll, prog, m
}
