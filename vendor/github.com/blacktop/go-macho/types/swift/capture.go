package swift

import (
	"encoding/binary"
	"fmt"
	"io"
)

//go:generate stringer -type NecessaryBindingsKind -output capture_string.go

// __TEXT.__swift5_capture
// Capture descriptors describe the layout of a closure context object.
// Unlike nominal types, the generic substitutions for a closure context come from the object, and not the metadata.

type Capture struct {
	CaptureDescriptor
	Address         uint64
	CaptureTypes    []CaptureType
	MetadataSources []MetadataSource
	Bindings        []NecessaryBindings
}

func (c Capture) String() string {
	var captureTypes string
	if len(c.CaptureTypes) > 0 {
		captureTypes += "  /* capture types */\n"
		for _, t := range c.CaptureTypes {
			captureTypes += fmt.Sprintf("    %s\n", t.TypeName)
		}
	}
	var metadataSources string
	if len(c.MetadataSources) > 0 {
		metadataSources += "  /* metadata sources */\n"
		for _, m := range c.MetadataSources {
			metadataSources += fmt.Sprintf("    %s: %s\n", m.MangledType, m.MangledMetadataSource)
		}
	}
	var bindings string
	if len(c.Bindings) > 0 {
		bindings += "  /* necessary bindings */\n"
		for _, b := range c.Bindings {
			bindings += fmt.Sprintf("    // Kind: %d, RequirementsSet: %d, RequirementsVector: %d, Conformances: %d\n", b.Kind, b.RequirementsSet, b.RequirementsVector, b.Conformances)
		}
	}
	return fmt.Sprintf(
		"block /* %#x */ {\n"+
			"%s"+
			"%s"+
			"%s"+
			"}",
		c.Address,
		captureTypes,
		metadataSources,
		bindings,
	)
}

// CaptureDescriptor describe the layout of a closure context
// object. Unlike nominal types, the generic substitutions for a
// closure context come from the object, and not the metadata.
// ref: include/swift/RemoteInspection/Records.h - CaptureDescriptor
type CaptureDescriptor struct {
	NumCaptureTypes    uint32 // The number of captures in the closure and the number of typerefs that immediately follow this struct.
	NumMetadataSources uint32 // The number of sources of metadata available in the MetadataSourceMap directly following the list of capture's typerefs.
	NumBindings        uint32 // The number of items in the NecessaryBindings structure at the head of the closure.
}

type CaptureType struct {
	CaptureTypeRecord
	TypeName string
}

type CaptureTypeRecord struct {
	MangledTypeName RelativeDirectPointer
}

func (ctr CaptureTypeRecord) Size() int64 {
	return int64(binary.Size(ctr.MangledTypeName.RelOff))
}

func (ctr *CaptureTypeRecord) Read(r io.Reader, addr uint64) error {
	ctr.MangledTypeName.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &ctr.MangledTypeName.RelOff); err != nil {
		return err
	}
	return nil
}

type MetadataSourceRecord struct {
	MangledTypeNameOff       RelativeDirectPointer
	MangledMetadataSourceOff RelativeDirectPointer
}

func (msr MetadataSourceRecord) Size() int64 {
	return int64(binary.Size(msr.MangledTypeNameOff.RelOff) + binary.Size(msr.MangledMetadataSourceOff.RelOff))
}

func (msr *MetadataSourceRecord) Read(r io.Reader, addr uint64) error {
	msr.MangledTypeNameOff.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &msr.MangledTypeNameOff.RelOff); err != nil {
		return err
	}
	addr += uint64(binary.Size(msr.MangledTypeNameOff.RelOff))
	msr.MangledMetadataSourceOff.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &msr.MangledMetadataSourceOff.RelOff); err != nil {
		return err
	}
	return nil
}

type MetadataSource struct {
	MetadataSourceRecord
	MangledType           string
	MangledMetadataSource string
}

type NecessaryBindingsKind uint32

const (
	PartialApply NecessaryBindingsKind = iota
	AsyncFunction
)

type NecessaryBindings struct {
	Kind               NecessaryBindingsKind
	RequirementsSet    RelativeDirectPointer
	RequirementsVector RelativeDirectPointer
	Conformances       RelativeDirectPointer
}

func (nb NecessaryBindings) Size() int64 {
	return int64(binary.Size(nb.RequirementsSet.RelOff) + binary.Size(nb.RequirementsVector.RelOff) + binary.Size(nb.Conformances.RelOff))
}

func (nb *NecessaryBindings) Read(r io.Reader, addr uint64) error {
	nb.RequirementsSet.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &nb.RequirementsSet.RelOff); err != nil {
		return err
	}
	addr += uint64(binary.Size(nb.RequirementsSet.RelOff))
	nb.RequirementsVector.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &nb.RequirementsVector.RelOff); err != nil {
		return err
	}
	addr += uint64(binary.Size(nb.RequirementsVector.RelOff))
	nb.Conformances.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &nb.Conformances.RelOff); err != nil {
		return err
	}
	return nil
}
