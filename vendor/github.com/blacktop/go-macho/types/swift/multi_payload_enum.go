package swift

import "fmt"

type MultiPayloadEnum struct {
	Address  uint64
	Type     string
	Contents []uint32
}

func (e MultiPayloadEnum) String() string {
	return fmt.Sprintf("// %#x (multi-payload)\nenum %s {}", e.Address, e.Type)
}

// ref: include/swift/RemoteInspection/Records.h
type MultiPayloadEnumDescriptor struct {
	TypeName int32
	Contents []uint32
}

type MultiPayloadEnumSizeAndFlags uint32

func (f MultiPayloadEnumSizeAndFlags) Size() uint16 {
	return uint16(f >> 16)
}
func (f MultiPayloadEnumSizeAndFlags) Flags() uint16 {
	return uint16(f & 0xffff)
}
func (f MultiPayloadEnumSizeAndFlags) UsesPayloadSpareBits() bool {
	return (f.Flags() & 1) != 0
}
func (f MultiPayloadEnumSizeAndFlags) String() string {
	return fmt.Sprintf("size: %d, flags: %d, uses_payload_spare_bits: %t", f.Size(), f.Flags(), f.UsesPayloadSpareBits())
}

type MultiPayloadEnumPayloadSpareBitMaskByteCount uint32

func (f MultiPayloadEnumPayloadSpareBitMaskByteCount) ByteOffset() uint16 {
	return uint16(f >> 16)
}
func (f MultiPayloadEnumPayloadSpareBitMaskByteCount) ByteCount() uint16 {
	return uint16(f & 0xffff)
}
func (f MultiPayloadEnumPayloadSpareBitMaskByteCount) String() string {
	return fmt.Sprintf("byte_offset: %d, byte_count: %d", f.ByteOffset(), f.ByteCount())
}
