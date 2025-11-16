package spec

import (
	"github.com/cilium/ebpf"

	bpfError "github.com/Jack-R-lantern/site/internal/bpf/error"
)

func SetBPFProgramIfindex(programSpec *ebpf.ProgramSpec, Ifindex uint32) {
	programSpec.Ifindex = Ifindex
}

func SetBPFProgramName(programSpec *ebpf.ProgramSpec, programName string) error {
	if programSpec == nil {
		return &bpfError.BPFError{Action: "set program name", Reason: "map spec is empty"}
	}
	programSpec.Name = programName

	return nil
}
