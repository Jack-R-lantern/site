package spec_test

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Jack-R-lantern/site/internal/bpf/spec"
)

func TestUpdateMapSpec(t *testing.T) {
	t.Run("valid input", func(t *testing.T) {
		// Arrange
		mapSpec := &ebpf.MapSpec{
			Name:       "testMap",
			MaxEntries: 8192,
			Type:       ebpf.Hash,
		}
		var newMapName string = "newMap"
		var newMapType string = ebpf.PerCPUHash.String()
		var newMaxEntries uint32 = 1024

		updateField := &spec.UpdateMapSpecField{
			Name:       newMapName,
			Type:       newMapType,
			MaxEntries: newMaxEntries,
		}

		err := spec.UpdateMapSpec(mapSpec, updateField)
		require.NoError(t, err)

		assert.Equal(t, mapSpec.Name, newMapName)
		assert.Equal(t, mapSpec.Type, ebpf.PerCPUHash)
		assert.Equal(t, mapSpec.MaxEntries, newMaxEntries)
	})

	t.Run("invalid input - map type", func(t *testing.T) {
		// Arrange
		mapSpec := &ebpf.MapSpec{
			Name:       "testMap",
			MaxEntries: 8192,
			Type:       ebpf.Hash,
		}
		var newMapName string = "newMap"
		var newMapType string = ebpf.Array.String()
		var newMaxEntries uint32 = 1024

		updateField := &spec.UpdateMapSpecField{
			Name:       newMapName,
			Type:       newMapType,
			MaxEntries: newMaxEntries,
		}

		err := spec.UpdateMapSpec(mapSpec, updateField)
		require.Error(t, err)

		assert.Equal(t, mapSpec.Name, newMapName)
		assert.Equal(t, mapSpec.Type, ebpf.Hash)
		assert.Equal(t, mapSpec.MaxEntries, newMaxEntries)
	})
}
