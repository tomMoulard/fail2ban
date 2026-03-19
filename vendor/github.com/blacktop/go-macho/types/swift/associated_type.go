package swift

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// __TEXT.__swift5_assocty
// This section contains an array of associated type descriptors.
// An associated type descriptor contains a collection of associated type records for a conformance.
// An associated type records describe the mapping from an associated type to the type witness of a conformance.

type AssociatedType struct {
	AssociatedTypeDescriptor
	Address            uint64
	ConformingTypeAddr uint64
	ConformingTypeName string
	ProtocolTypeName   string
	TypeRecords        []ATRecordType
}

func (a AssociatedType) String() string {
	return a.dump(false)
}
func (a AssociatedType) Verbose() string {
	return a.dump(true)
}
func (a AssociatedType) dump(verbose bool) string {
	var addr string
	var vars []string
	for _, v := range a.TypeRecords {
		if verbose {
			addr = fmt.Sprintf("/* %#x */ ", v.NameOffset.GetAddress())
		}
		vars = append(vars, fmt.Sprintf("    %stypealias %s = %s", addr, v.Name, v.SubstitutedTypeName))
	}
	if verbose {
		addr = fmt.Sprintf("// %#x\n", a.Address)
	}
	return fmt.Sprintf(
		"%s"+
			"extension %s: %s {\n"+
			"%s\n"+
			"}",
		addr,
		a.ConformingTypeName,
		a.ProtocolTypeName,
		strings.Join(vars, "\n"),
	)
}

// AssociatedTypeDescriptor an associated type descriptor contains a collection of associated type records for a conformance.
// ref: include/swift/RemoteInspection/Records.h
type AssociatedTypeDescriptor struct {
	ConformingTypeNameOffset RelativeDirectPointer
	ProtocolTypeNameOffset   RelativeDirectPointer
	NumAssociatedTypes       uint32
	AssociatedTypeRecordSize uint32
}

func (a AssociatedTypeDescriptor) Size() int64 {
	return int64(
		binary.Size(a.ConformingTypeNameOffset.RelOff) +
			binary.Size(a.ProtocolTypeNameOffset.RelOff) +
			binary.Size(a.NumAssociatedTypes) +
			binary.Size(a.AssociatedTypeRecordSize),
	)
}

func (a *AssociatedTypeDescriptor) Read(r io.Reader, addr uint64) error {
	a.ConformingTypeNameOffset.Address = addr
	a.ProtocolTypeNameOffset.Address = addr + uint64(binary.Size(RelativeDirectPointer{}.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &a.ConformingTypeNameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &a.ProtocolTypeNameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &a.NumAssociatedTypes); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &a.AssociatedTypeRecordSize); err != nil {
		return err
	}
	return nil
}

type ATRecordType struct {
	AssociatedTypeRecord
	Name                string
	SubstitutedTypeName string
}

// AssociatedTypeRecord type records describe the mapping from an associated type to the type witness of a conformance.
// ref: include/swift/RemoteInspection/Records.h
type AssociatedTypeRecord struct {
	NameOffset                RelativeDirectPointer
	SubstitutedTypeNameOffset RelativeDirectPointer
}

func (a AssociatedTypeRecord) Size() int64 {
	return int64(
		binary.Size(a.NameOffset.RelOff) +
			binary.Size(a.SubstitutedTypeNameOffset.RelOff),
	)
}

func (a *AssociatedTypeRecord) Read(r io.Reader, addr uint64) error {
	a.NameOffset.Address = addr
	a.SubstitutedTypeNameOffset.Address = addr + uint64(binary.Size(RelativeDirectPointer{}.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &a.NameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &a.SubstitutedTypeNameOffset.RelOff); err != nil {
		return err
	}
	return nil
}
