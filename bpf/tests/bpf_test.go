package tests

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBPFELFLoadIntoKernel(t *testing.T) {
	coll := loadCollection(t)
	t.Logf("collection ok: programs=%d maps=%d", len(coll.Programs), len(coll.Maps))
}

func loadCollection(t *testing.T) *ebpf.Collection {
	t.Helper()

	elfPath := os.Getenv("BPF_ELF")
	if elfPath == "" {
		t.Skip("set BPF_ELF=<pat to .o> to enable this test")
	}

	raiseMemlock(t)

	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}
	t.Logf("spec ok: programs=%d maps=%d", len(spec.Programs), len(spec.Maps))

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     1,
			LogSizeStart: 1024 * 1024,
		},
	})
	if isPermissionError(err) {
		t.Skipf("skip: kernel/namespace lacks capability to load BPF: %v", err)
	}
	if err != nil {
		t.Fatalf("failed to load collection (verifier?): %v", err)
	}

	t.Cleanup(func() {
		coll.Close()
	})

	return coll
}
