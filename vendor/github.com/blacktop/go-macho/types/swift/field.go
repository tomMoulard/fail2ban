package swift

import (
	"encoding/binary"
	"fmt"
	"io"
)

//go:generate stringer -type=FieldDescriptorKind -linecomment -output field_string.go

// __TEXT.__swift5_fieldmd
// This section contains an array of field descriptors.
// A field descriptor contains a collection of field records for a single class,
// struct or enum declaration. Each field descriptor can be a different length depending on how many field records the type contains.

const SWIFT_REFLECTION_METADATA_VERSION = 3 // superclass field

type Field struct {
	FieldDescriptor
	Address    uint64
	Type       string
	SuperClass string
	Records    []FieldRecord
}

func (f Field) IsEnum() bool {
	return f.Kind == FDKindEnum || f.Kind == FDKindMultiPayloadEnum
}
func (f Field) IsClass() bool {
	return f.Kind == FDKindClass || f.Kind == FDKindObjCClass
}
func (f Field) IsProtocol() bool {
	return f.Kind == FDKindProtocol || f.Kind == FDKindClassProtocol || f.Kind == FDKindObjCProtocol
}
func (f Field) IsStruct() bool {
	return f.Kind == FDKindStruct
}
func (f Field) String() string {
	return f.dump(false)
}
func (f Field) Verbose() string {
	return f.dump(true)
}
func (f Field) dump(verbose bool) string {
	var recs string
	if len(f.Records) > 0 {
		recs = "\n"
	}
	for _, r := range f.Records {
		var flags string
		var hasType string
		if f.Kind == FDKindEnum || f.Kind == FDKindMultiPayloadEnum {
			flags = "case"
		} else {
			if r.Flags.String() == "IsVar" {
				flags = "var"
			} else {
				flags = "let"
			}
		}
		if len(r.MangledType) > 0 {
			hasType = ": "
		}
		recs += fmt.Sprintf("        %s %s%s%s\n", flags, r.Name, hasType, r.MangledType)
	}
	var addr string
	if verbose {
		addr = fmt.Sprintf("// %#x\n", f.Address)
	}
	if len(f.SuperClass) > 0 {
		return fmt.Sprintf("%s%s %s: %s {%s}\n", addr, f.Kind, f.Type, f.SuperClass, recs)
	}
	return fmt.Sprintf("%s%s %s {%s}\n", addr, f.Kind, f.Type, recs)
}

type FieldDescriptorKind uint16

const (
	// Swift nominal types.
	FDKindStruct FieldDescriptorKind = iota // struct
	FDKindClass                             // class
	FDKindEnum                              // enum

	// Fixed-size multi-payload enums have a special descriptor format that
	// encodes spare bits.
	//
	// FIXME: Actually implement this. For now, a descriptor with this kind
	// just means we also have a builtin descriptor from which we get the
	// size and alignment.
	FDKindMultiPayloadEnum // multi-payload enum

	// A Swift opaque protocol. There are no fields, just a record for the
	// type itself.
	FDKindProtocol // protocol

	// A Swift class-bound protocol.
	FDKindClassProtocol // class protocol

	// An Objective-C protocol, which may be imported or defined in Swift.
	FDKindObjCProtocol // objc protocol

	// An Objective-C class, which may be imported or defined in Swift.
	// In the former case, field type metadata is not emitted, and
	// must be obtained from the Objective-C runtime.
	FDKindObjCClass // objc class
)

// FieldDescriptor contain a collection of field records for a single class, struct or enum declaration.
// ref: swift/include/swift/Reflection/Records.h
type FieldDescriptor struct {
	MangledTypeNameOffset RelativeDirectPointer
	SuperclassOffset      RelativeDirectPointer
	Kind                  FieldDescriptorKind
	FieldRecordSize       uint16
	NumFields             uint32
}

func (fd FieldDescriptor) Size() uint64 {
	return uint64(
		binary.Size(fd.MangledTypeNameOffset.RelOff) +
			binary.Size(fd.SuperclassOffset.RelOff) +
			binary.Size(fd.Kind) +
			binary.Size(fd.FieldRecordSize) +
			binary.Size(fd.NumFields))
}

func (fd *FieldDescriptor) Read(r io.Reader, addr uint64) error {
	fd.MangledTypeNameOffset.Address = addr
	fd.SuperclassOffset.Address = addr + uint64(binary.Size(RelativeDirectPointer{}.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &fd.MangledTypeNameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &fd.SuperclassOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &fd.Kind); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &fd.FieldRecordSize); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &fd.NumFields); err != nil {
		return err
	}
	return nil
}

type FieldRecord struct {
	FieldRecordDescriptor
	Name        string
	MangledType string
}

type FieldRecordDescriptor struct {
	Flags                 FieldRecordFlags
	MangledTypeNameOffset RelativeDirectPointer
	FieldNameOffset       RelativeDirectPointer
}

func (fd FieldRecordDescriptor) Size() uint64 {
	return uint64(
		binary.Size(fd.Flags) +
			binary.Size(fd.MangledTypeNameOffset.RelOff) +
			binary.Size(fd.FieldNameOffset.RelOff))
}

func (frd *FieldRecordDescriptor) Read(r io.Reader, addr uint64) error {
	frd.MangledTypeNameOffset.Address = addr + uint64(binary.Size(FieldRecordDescriptor{}.Flags))
	frd.FieldNameOffset.Address = addr +
		uint64(
			binary.Size(FieldRecordDescriptor{}.Flags)+
				binary.Size(RelativeDirectPointer{}.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &frd.Flags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &frd.MangledTypeNameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &frd.FieldNameOffset.RelOff); err != nil {
		return err
	}
	return nil
}

type FieldRecordFlags uint32

const (
	// IsIndirectCase is this an indirect enum case?
	IsIndirectCase FieldRecordFlags = 0x1
	// IsVar is this a mutable `var` property?
	IsVar FieldRecordFlags = 0x2
	// IsArtificial is this an artificial field?
	IsArtificial FieldRecordFlags = 0x4
)

func (f FieldRecordFlags) IsIndirectCase() bool {
	return (f & IsIndirectCase) == IsIndirectCase
}
func (f FieldRecordFlags) IsVar() bool {
	return (f & IsVar) == IsVar
}
func (f FieldRecordFlags) IsArtificial() bool {
	return (f & IsArtificial) == IsArtificial
}

func (f FieldRecordFlags) String() string { // TODO: this is dumb (does ind or anon ever happen?)
	var out string
	if f.IsIndirectCase() {
		out = "indirect case"
	}
	if f.IsArtificial() {
		if len(out) > 0 {
			out += " | "
		}
		out += "artificial"
	}
	if f.IsVar() {
		out = "var"
	} else {
		out = "let"
	}
	return out
}
