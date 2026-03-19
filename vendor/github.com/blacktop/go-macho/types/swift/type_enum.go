package swift

import (
	"encoding/binary"
	"fmt"
	"io"
)

type Enum struct {
	TargetEnumDescriptor
	GenericContext    *TypeGenericContext
	ForeignMetadata   *TargetForeignMetadataInitialization
	SingletonMetadata *TargetSingletonMetadataInitialization
	Metadatas         []Metadata
	CachingOnceToken  *TargetCanonicalSpecializedMetadatasCachingOnceToken
}

type TargetEnumDescriptor struct {
	TargetTypeContextDescriptor
	NumPayloadCasesAndPayloadSizeOffset uint32
	NumEmptyCases                       uint32
}

func (e TargetEnumDescriptor) Size() int64 {
	return int64(
		int(e.TargetTypeContextDescriptor.Size()) +
			binary.Size(e.NumPayloadCasesAndPayloadSizeOffset) +
			binary.Size(e.NumEmptyCases))
}

func (e *TargetEnumDescriptor) Read(r io.Reader, addr uint64) error {
	if err := e.TargetTypeContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &e.NumPayloadCasesAndPayloadSizeOffset); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &e.NumEmptyCases); err != nil {
		return err
	}
	return nil
}

func (e TargetEnumDescriptor) GetNumPayloadCases() uint32 {
	return e.NumPayloadCasesAndPayloadSizeOffset & 0x00FFFFFF
}
func (e TargetEnumDescriptor) GetNumCases() uint32 {
	return e.GetNumPayloadCases() + e.NumEmptyCases
}
func (e TargetEnumDescriptor) GetPayloadSizeOffset() uint32 {
	return (e.NumPayloadCasesAndPayloadSizeOffset & 0xFF000000) >> 24
}
func (e TargetEnumDescriptor) String() string {
	return fmt.Sprintf("num_payload_cases %d, num_cases %d, num_empty_cases %d, payload_size_offset %d",
		e.GetNumPayloadCases(),
		e.GetNumCases(),
		e.NumEmptyCases,
		e.GetPayloadSizeOffset())
}
