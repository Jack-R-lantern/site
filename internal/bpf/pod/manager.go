package pod

import "github.com/cilium/ebpf"

type PodBPFManager interface {
}

func NewPodBPFManager(path string) (PodBPFManager, error) {
	return &podBPFManager{}, nil
}

type podBPFManager struct {
	spec *ebpf.CollectionSpec
}
