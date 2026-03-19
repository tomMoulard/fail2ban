package swift

import (
	"io"

	"github.com/blacktop/go-macho/types"
)

// Flags for anonymous type context descriptors. These values are used as the
// kindSpecificFlags of the ContextDescriptorFlags for the anonymous context.
type AnonymousContextDescriptorFlags uint16

const (
	// Whether this anonymous context descriptor is followed by its
	// mangled name, which can be used to match the descriptor at runtime.
	HasMangledName = 0
)

func (f AnonymousContextDescriptorFlags) HasMangledName() bool {
	return types.ExtractBits(uint64(f), HasMangledName, 1) != 0
}

type Anonymous struct {
	TargetAnonymousContextDescriptor
	GenericContext     *GenericContext
	MangledContextName string
}

type TargetAnonymousContextDescriptor struct {
	TargetContextDescriptor
}

func (tacd TargetAnonymousContextDescriptor) HasMangledName() bool {
	return AnonymousContextDescriptorFlags(tacd.Flags.KindSpecific()).HasMangledName()
}

func (tacd TargetAnonymousContextDescriptor) Size() int64 {
	return tacd.TargetContextDescriptor.Size()
}

func (tacd *TargetAnonymousContextDescriptor) Read(r io.Reader, addr uint64) error {
	if err := tacd.TargetContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	return nil
}
