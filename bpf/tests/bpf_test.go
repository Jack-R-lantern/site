package tests

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

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

func TestBPFELFLoadIntoKernel(t *testing.T) {
	elfPath := os.Getenv("BPF_ELF")
	if elfPath == "" {
		t.Skip("set BPF_ELF=<pat to .o> to enable this test")
	}

	raiseMemlock(t)

	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}
	t.Logf("spec ok: prgrams=%d maps=%d", len(spec.Programs), len(spec.Maps))

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     1,
			LogSizeStart: 256 * 1024,
		},
	})
	if isPermissionError(err) {
		t.Skipf("skip: kernel/namespace lacks capability to load BPF: %v", err)
	}
	if err != nil {
		t.Fatalf("failed to load collection (verifier?): %v", err)
	}
	defer coll.Close()
}
