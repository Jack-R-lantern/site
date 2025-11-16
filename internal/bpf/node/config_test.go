package node_test

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/Jack-R-lantern/site/internal/bpf/node"
)

func TestNodeMonitorConfig(t *testing.T) {
	data := `{}`
	t.Run("default config", func(t *testing.T) {
		config := &node.NodeMonitorConfig{}
		err := yaml.Unmarshal([]byte(data), config)
		require.NoError(t, err)

		assert.Equal(t, true, config.Enabled)
		// Ifaces
		assert.Equal(t, []string{}, config.IncludeIfaces)
		assert.Len(t, config.IncludeIfaces, 0)
		assert.Equal(t, []string{}, config.ExcludeIfaces)
		assert.Len(t, config.ExcludeIfaces, 0)
		// Prefixes
		assert.Equal(t, []string{}, config.IncludePrefixes)
		assert.Len(t, config.IncludePrefixes, 0)
		assert.Equal(t, []string{}, config.ExcludePrefixes)
		assert.Len(t, config.ExcludePrefixes, 0)

		// Attach Direction
		assert.Equal(t, true, config.AttachIngress)
		assert.Equal(t, true, config.AttachEgress)

		// BPF Program Metadata
		assert.Equal(t, node.NODE_INGRESS_PROG_NAME, config.Metadata.ProgMetadata.IngressProgNameOverride)
		assert.Equal(t, node.NODE_EGRESS_PROG_NAME, config.Metadata.ProgMetadata.EgressProgNameOverride)
		// BPF Map Metadata
		assert.Equal(t, node.NODE_INGRESS_MAP_NAME, config.Metadata.MapMetadata.IngressMapNameOverride)
		assert.Equal(t, node.NODE_EGRESS_MAP_NAME, config.Metadata.MapMetadata.EgressMapNameOverride)
		assert.Equal(t, ebpf.Hash.String(), config.Metadata.MapMetadata.MapType)
		assert.Equal(t, node.DEFAULT_MAP_MAX_ENTRIES, config.Metadata.MapMetadata.MaxEntries)
	})

	t.Run("invalid config mapType", func(t *testing.T) {
		data := `metadata:
  mapMetadata:
    mapType: Array`
		config := &node.NodeMonitorConfig{}
		err := yaml.Unmarshal([]byte(data), config)
		require.Error(t, err)
		require.EqualErrorf(t, err, "bpf Array map type not support", "bpf %s map type not support", "Array")
	})
}
