package metadata

type BPFProgramMetadata struct {
	// BPF Program Metadata
	IngressProgNameOverride string `yaml:"ingressProgNameOverride"`
	EgressProgNameOverride  string `yaml:"egressProgNameOverride"`
}

type BPFMapMetadata struct {
	// BPF Map Metadata
	IngressMapNameOverride string `yaml:"ingressMapNameOverride"`
	EgressMapNameOverride  string `yaml:"egressMapNameOverride"`
	MapType                string `yaml:"mapType"` // Hash, PerCPUHash
	MaxEntries             uint32 `yaml:"maxEntries"`
}
