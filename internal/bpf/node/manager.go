package node

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"

	"github.com/Jack-R-lantern/site/internal/bpf/spec"
)

const (
	// It must be updated to match the program name in bpf/node.c.
	NODE_INGRESS_PROG_NAME = "node_ingress"
	NODE_EGRESS_PROG_NAME  = "node_egress"

	// It must be updated to match the map name in bpf/node.c.
	NODE_INGRESS_MAP_NAME = "node_ingress_map"
	NODE_EGRESS_MAP_NAME  = "node_egress_map"

	// It must be updated to match the bpf/lib/node.h
	DEFAULT_MAP_MAX_ENTRIES uint32 = 8192
)

type NodeBPFManager interface {
	Init()
}

func NewNodeBPFManager(path string, cfg *NodeMonitorConfig) (NodeBPFManager, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}

	return &nodeBPFManager{
		spec: spec,
		cfg:  cfg,
	}, nil
}

type nodeBPFManager struct {
	spec *ebpf.CollectionSpec
	cfg  *NodeMonitorConfig

	ingressMap *ebpf.Map
	egressMap  *ebpf.Map

	ingressProg *ebpf.Program
	egressProg  *ebpf.Program
}

func (mgr *nodeBPFManager) Init() {
	if mgr.cfg.Enabled {
		err := mgr.updateSpec()
		if err != nil {
			// TODO: error handling
			log.Fatalf("updateSpec failed")
		}

		// err = mgr.loadMap()
		// if err != nil {
		// 	// TODO: error handling
		// 	log.Fatalf("load map failed")
		// }
		// filter := &nic.Filter{
		// 	IncludeIfaces:   mgr.cfg.IncludeIfaces,
		// 	IncludePrefixes: mgr.cfg.IncludePrefixes,
		// 	ExcludeIfaces:   mgr.cfg.ExcludeIfaces,
		// 	ExcludePrefixes: mgr.cfg.ExcludePrefixes,
		// 	LinkType:        nic.DeviceType,
		// }

		// interfaceInfos, err := nic.ListFilteredInterface(filter)
		// if err != nil {
		// 	// TODO: error handling
		// 	log.Fatalf("ListFilteredInterface failed")
		// }

	}
}

func (mgr *nodeBPFManager) updateSpec() error {
	programSpec := mgr.spec.Programs
	programMeta := mgr.cfg.Metadata.ProgMetadata
	mapSpec := mgr.spec.Maps
	mapMeta := mgr.cfg.Metadata.MapMetadata

	// program spec update
	err := spec.SetBPFProgramName(programSpec[NODE_INGRESS_PROG_NAME], programMeta.IngressProgNameOverride)
	if err != nil {
		return err
	}
	err = spec.SetBPFProgramName(programSpec[NODE_EGRESS_PROG_NAME], programMeta.EgressProgNameOverride)
	if err != nil {
		return err
	}

	// ingress map spec update
	ingressUpdateMapField := &spec.UpdateMapSpecField{
		Name:       mapMeta.IngressMapNameOverride,
		MaxEntries: mapMeta.MaxEntries,
		Type:       mapMeta.MapType,
	}
	if err = spec.UpdateMapSpec(mapSpec[NODE_INGRESS_MAP_NAME], ingressUpdateMapField); err != nil {
		return err
	}

	// egress map spec update
	egressUpdateMapField := &spec.UpdateMapSpecField{
		Name:       mapMeta.EgressMapNameOverride,
		MaxEntries: mapMeta.MaxEntries,
		Type:       mapMeta.MapType,
	}
	if err = spec.UpdateMapSpec(mapSpec[NODE_EGRESS_MAP_NAME], egressUpdateMapField); err != nil {
		return err
	}

	return nil
}

func (mgr *nodeBPFManager) loadMap() error {
	// Find map specs by their original keys in the CollectionSpec.
	// Note: we changed MapSpec.Name (kernel name) in updateSpec(),
	// but the map is still stored under the original key in mgr.spec.Maps.
	mapSpec := mgr.spec.Maps

	ingressSpec, ok := mapSpec[NODE_INGRESS_MAP_NAME]
	if !ok {
		// TODO: Error Handling
		return fmt.Errorf("ingress program sepc %q not found", NODE_INGRESS_MAP_NAME)
	}
	egressSpec, ok := mapSpec[NODE_EGRESS_MAP_NAME]
	if !ok {
		// TODO: Error Handling
		return fmt.Errorf("egress program sepc %q not found", NODE_EGRESS_MAP_NAME)
	}

	ingressMap, err := ebpf.NewMap(ingressSpec)
	if err != nil {
		// TODO: Error Handling
		return fmt.Errorf("load ingress map: %w", err)
	}
	egressMap, err := ebpf.NewMap(egressSpec)
	if err != nil {
		// TODO: Error Handling
		ingressMap.Clone()
		return fmt.Errorf("load egress map: %w", err)
	}

	mgr.ingressMap = ingressMap
	mgr.egressMap = egressMap
	return nil
}

func (mgr *nodeBPFManager) loadProgram() {
}
