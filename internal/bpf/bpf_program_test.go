package bpf_test

import (
	"testing"

	"github.com/Jack-R-lantern/site/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestSetBPFProgramIfindex(t *testing.T) {
	// Arrange
	programSpec := &ebpf.ProgramSpec{
		Ifindex: 1,
	}
	var newIfindex uint32 = 2

	// Act
	bpf.SetBPFProgramIfindex(programSpec, newIfindex)

	// Assert
	assert.Equal(t, programSpec.Ifindex, newIfindex)
}
