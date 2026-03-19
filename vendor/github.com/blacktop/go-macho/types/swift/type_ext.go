package swift

import (
	"encoding/binary"
	"io"
)

type Extension struct {
	TargetExtensionContextDescriptor
	GenericContext *GenericContext
}

type TargetExtensionContextDescriptor struct {
	TargetContextDescriptor
	// A mangling of the `Self` type context that the extension extends.
	// The mangled name represents the type in the generic context encoded by
	// this descriptor. For example, a nongeneric nominal type extension will
	// encode the nominal type name. A generic nominal type extension will encode
	// the instance of the type with any generic arguments bound.
	//
	// Note that the Parent of the extension will be the module context the
	// extension is declared inside.
	ExtendedContext RelativeDirectPointer
}

func (e TargetExtensionContextDescriptor) Size() int64 {
	return int64(int(e.TargetContextDescriptor.Size()) + binary.Size(e.ExtendedContext.RelOff))
}

func (tmcd *TargetExtensionContextDescriptor) Read(r io.Reader, addr uint64) error {
	if err := tmcd.TargetContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	addr += uint64(tmcd.TargetContextDescriptor.Size())
	tmcd.ExtendedContext.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &tmcd.ExtendedContext.RelOff); err != nil {
		return err
	}
	return nil
}
