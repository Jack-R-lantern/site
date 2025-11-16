package node

import (
	"fmt"

	"github.com/cilium/ebpf"
	"gopkg.in/yaml.v3"

	"github.com/Jack-R-lantern/site/internal/bpf/metadata"
)

type NodeMonitorConfig struct {
	Enabled bool `yaml:"enabled"`

	// Interface Select Option
	IncludeIfaces   []string `yaml:"includeIfaces"`
	ExcludeIfaces   []string `yaml:"excludeIfaces"`
	IncludePrefixes []string `yaml:"includePrefixex"`
	ExcludePrefixes []string `yaml:"excludePrefixes"`

	// Attach Driection
	AttachIngress bool `yaml:"attachIngress"`
	AttachEgress  bool `yaml:"attachEgress"`

	Metadata NodeBPFMetadata `yaml:"metadata"`
}

type NodeBPFMetadata struct {
	ProgMetadata metadata.BPFProgramMetadata `yaml:"progMetadata"`
	MapMetadata  metadata.BPFMapMetadata     `yaml:"mapMetadata"`
}

func (cfg *NodeMonitorConfig) UnmarshalYAML(value *yaml.Node) error {
	type raw NodeMonitorConfig
	tmp := raw{
		Enabled: true,
		// Interface Select Option
		IncludeIfaces:   make([]string, 0),
		ExcludeIfaces:   make([]string, 0),
		IncludePrefixes: make([]string, 0),
		ExcludePrefixes: make([]string, 0),
		// Attach Direction
		AttachIngress: true,
		AttachEgress:  true,

		// BPF Metadata
		Metadata: NodeBPFMetadata{
			ProgMetadata: metadata.BPFProgramMetadata{
				IngressProgNameOverride: NODE_INGRESS_PROG_NAME,
				EgressProgNameOverride:  NODE_EGRESS_PROG_NAME,
			},
			MapMetadata: metadata.BPFMapMetadata{
				IngressMapNameOverride: NODE_INGRESS_MAP_NAME,
				EgressMapNameOverride:  NODE_EGRESS_MAP_NAME,
				MapType:                ebpf.Hash.String(),
				MaxEntries:             DEFAULT_MAP_MAX_ENTRIES,
			},
		},
	}

	if err := value.Decode(&tmp); err != nil {
		return err
	}

	if err := validateMapType(tmp.Metadata.MapMetadata.MapType); err != nil {
		return err
	}

	*cfg = NodeMonitorConfig(tmp)

	return nil
}

func validateMapType(mapType string) error {
	switch mapType {
	case ebpf.Hash.String():
		return nil
	case ebpf.PerCPUHash.String():
		return nil
	}
	return fmt.Errorf("bpf %s map type not support", mapType)
}
