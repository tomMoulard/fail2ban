package swift

import (
	"encoding/binary"
	"fmt"
	"io"
)

// __TEXT.__swift5_builtin
// This section contains an array of builtin type descriptors.
// A builtin type descriptor describes the basic layout information about any builtin types referenced from other sections.

const MaxNumExtraInhabitants = 0x7FFFFFFF

// BuiltinType builtin swift type
type BuiltinType struct {
	BuiltinTypeDescriptor
	Name string
}

func (b BuiltinType) String() string {
	return b.dump(false)
}
func (b BuiltinType) Verbose() string {
	return b.dump(true)
}
func (b BuiltinType) dump(verbose bool) string {
	var numExtraInhabitants string
	if b.NumExtraInhabitants == MaxNumExtraInhabitants {
		numExtraInhabitants = "max"
	} else {
		numExtraInhabitants = fmt.Sprintf("%d", b.NumExtraInhabitants)
	}
	var addr string
	if verbose {
		addr = fmt.Sprintf("// %#x\n", b.TypeName.GetAddress())
	}
	return fmt.Sprintf(
		"%s"+
			"%s /* (size: %d"+
			", align: %d"+
			", bitwise-takable: %t"+
			", stride: %d"+
			", extra-inhabitants: %s) */",
		addr,
		b.Name,
		b.Size,
		b.AlignmentAndFlags.Alignment(),
		b.AlignmentAndFlags.IsBitwiseTakable(),
		b.Stride,
		numExtraInhabitants,
	)
}

// BuiltinTypeDescriptor type records describe basic layout information about any builtin types referenced from the other sections.
// ref: include/swift/RemoteInspection/Records.h
type BuiltinTypeDescriptor struct {
	TypeName            RelativeDirectPointer
	Size                uint32
	AlignmentAndFlags   builtinTypeFlag
	Stride              uint32
	NumExtraInhabitants uint32
}

func (b *BuiltinTypeDescriptor) Read(r io.Reader, addr uint64) error {
	b.TypeName.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &b.TypeName.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &b.Size); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &b.AlignmentAndFlags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &b.Stride); err != nil {
		return err
	}
	return binary.Read(r, binary.LittleEndian, &b.NumExtraInhabitants)
}

type builtinTypeFlag uint32

func (f builtinTypeFlag) IsBitwiseTakable() bool {
	return ((f >> 16) & 1) != 0
}
func (f builtinTypeFlag) Alignment() uint16 {
	return uint16(f & 0xffff)
}
