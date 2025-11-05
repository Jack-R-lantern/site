package bpf

import (
	"strconv"

	"github.com/cilium/ebpf"
)

func SetBPFMapName(mapSpec *ebpf.MapSpec, mapName string) error {
	if mapSpec == nil {
		return &BPFError{Action: "set map name", Value: mapName, Reason: "map spec is empty"}
	}
	mapSpec.Name = mapName

	return nil
}

func SetBPFMapMaxEntries(mapSpec *ebpf.MapSpec, maxEntries uint32) error {
	if mapSpec == nil {
		return &BPFError{Action: "set map max entries", Value: strconv.FormatUint(uint64(maxEntries), 10), Reason: "map spec is empty"}
	}
	mapSpec.MaxEntries = maxEntries

	return nil
}

func SetBPFMapTypeHash(mapSpec *ebpf.MapSpec, typeName string) error {
	if mapSpec == nil {
		return &BPFError{Action: "set map max entries", Value: typeName, Reason: "map spec is empty"}
	}

	switch typeName {
	case ebpf.Hash.String():
		mapSpec.Type = ebpf.Hash
		return nil
	case ebpf.PerCPUHash.String():
		mapSpec.Type = ebpf.PerCPUHash
		return nil
	}
	return &BPFError{Action: "set map type", Value: typeName, Reason: "map type not support"}
}
