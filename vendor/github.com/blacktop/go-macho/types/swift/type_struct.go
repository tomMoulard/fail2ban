package swift

import (
	"encoding/binary"
	"io"
)

type Struct struct {
	TargetStructDescriptor
	GenericContext    *TypeGenericContext
	ForeignMetadata   *TargetForeignMetadataInitialization
	SingletonMetadata *TargetSingletonMetadataInitialization
	Metadatas         []Metadata
	CachingOnceToken  *TargetCanonicalSpecializedMetadatasCachingOnceToken
}

type TargetStructDescriptor struct {
	TargetTypeContextDescriptor
	// The number of stored properties in the struct.
	// If there is a field offset vector, this is its length.
	NumFields uint32
	// The offset of the field offset vector for this struct's stored
	// properties in its metadata, if any. 0 means there is no field offset vector.
	FieldOffsetVectorOffset uint32
}

func (s TargetStructDescriptor) Size() int64 {
	return int64(
		int(s.TargetTypeContextDescriptor.Size()) +
			binary.Size(s.NumFields) +
			binary.Size(s.FieldOffsetVectorOffset))
}

func (s *TargetStructDescriptor) Read(r io.Reader, addr uint64) error {
	if err := s.TargetTypeContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &s.NumFields); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &s.FieldOffsetVectorOffset); err != nil {
		return err
	}
	return nil
}
