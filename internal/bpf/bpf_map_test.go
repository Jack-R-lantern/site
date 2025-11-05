package bpf_test

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"

	"github.com/Jack-R-lantern/site/internal/bpf"
)

func TestSetBPFMapName(t *testing.T) {
	// Arrange
	mapSpec := &ebpf.MapSpec{
		Name:       "testMap",
		MaxEntries: 8192,
		Type:       ebpf.Hash,
	}
	var newMapName string = "newMap"

	bpf.SetBPFMapName(mapSpec, newMapName)

	assert.Equal(t, mapSpec.Name, newMapName)
}

func TestSetBPFMapMaxEntries(t *testing.T) {
	// Arrange
	mapSpec := &ebpf.MapSpec{
		Name:       "testMap",
		MaxEntries: 8192,
	}
	var newMaxEntries uint32 = 1024

	// Act
	bpf.SetBPFMapMaxEntries(mapSpec, newMaxEntries)

	// Assert
	assert.Equal(t, mapSpec.MaxEntries, newMaxEntries)
}

func TestSetBPFMapTypeHash(t *testing.T) {
	// Arrange
	mapSpec := &ebpf.MapSpec{
		Name: "testMap",
		Type: ebpf.Hash,
	}

	t.Run("set_hash_success", func(t *testing.T) {
		// Act
		err := bpf.SetBPFMapTypeHash(mapSpec, ebpf.Hash.String())

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, mapSpec.Type, ebpf.Hash)
	})

	t.Run("set_percpuhash_success", func(t *testing.T) {
		// Act
		err := bpf.SetBPFMapTypeHash(mapSpec, ebpf.PerCPUHash.String())

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, mapSpec.Type, ebpf.PerCPUHash)
	})

	t.Run("set_array_failed", func(t *testing.T) {
		// Act
		err := bpf.SetBPFMapTypeHash(mapSpec, ebpf.Array.String())

		// Assert
		assert.Error(t, err)
		assert.EqualErrorf(t, err, err.Error(), "action: %s, value: %s, Reason: %s", "set map type", ebpf.Array.String(), "map type not support")
	})
}
