package bpf

import "github.com/cilium/ebpf"

func SetBPFProgramIfindex(programSpec *ebpf.ProgramSpec, Ifindex uint32) {
	programSpec.Ifindex = Ifindex
}
