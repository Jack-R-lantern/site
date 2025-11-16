package spec

import (
	"fmt"

	"github.com/cilium/ebpf"

	bpfError "github.com/Jack-R-lantern/site/internal/bpf/error"
)

type UpdateMapSpecField struct {
	Name       string
	MaxEntries uint32
	Type       string
}

func UpdateMapSpec(spec *ebpf.MapSpec, update *UpdateMapSpecField) error {
	if spec == nil && update == nil {
		return &bpfError.BPFError{Action: "update map spec", Reason: "spec is empty"}
	}
	updateBPFMapName(spec, update.Name)
	updateBPFMapMaxEntries(spec, update.MaxEntries)
	if err := updateBPFMapTypeHash(spec, update.Type); err != nil {
		return &bpfError.BPFError{Action: "update map spec", Reason: err.Error()}
	}

	return nil
}

func updateBPFMapName(mapSpec *ebpf.MapSpec, mapName string) {
	mapSpec.Name = mapName
}

func updateBPFMapMaxEntries(mapSpec *ebpf.MapSpec, maxEntries uint32) {
	mapSpec.MaxEntries = maxEntries
}

func updateBPFMapTypeHash(mapSpec *ebpf.MapSpec, typeName string) error {
	switch typeName {
	case ebpf.Hash.String():
		mapSpec.Type = ebpf.Hash
		return nil
	case ebpf.PerCPUHash.String():
		mapSpec.Type = ebpf.PerCPUHash
		return nil
	}

	return fmt.Errorf("map type not support")
}
