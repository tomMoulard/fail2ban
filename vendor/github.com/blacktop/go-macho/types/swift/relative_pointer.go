package swift

import (
	"encoding/binary"
	"fmt"
	"io"
)

type RelativeString struct {
	RelativeDirectPointer
	Name string
}

type RelativeDirectPointer struct {
	Address uint64
	RelOff  int32
}

func (r RelativeDirectPointer) GetAddress() uint64 {
	return uint64(int64(r.Address) + int64(r.RelOff))
}
func (r RelativeDirectPointer) IsSet() bool {
	return r.RelOff != 0
}
func (p *RelativeDirectPointer) Read(r io.Reader, addr uint64) error {
	p.Address = addr
	return binary.Read(r, binary.LittleEndian, &p.RelOff)
}

type TargetRelativeDirectPointer struct {
	Address uint64
	RelOff  int32
}

func (tr TargetRelativeDirectPointer) IsSet() bool {
	return tr.RelOff != 0
}
func (tr TargetRelativeDirectPointer) GetRelPtrAddress() uint64 {
	return uint64(int64(tr.Address) + int64(tr.RelOff))
}
func (tr TargetRelativeDirectPointer) GetAddress(r io.Reader) (uint64, error) {
	var pointerRelOff int32
	if err := binary.Read(r, binary.LittleEndian, &pointerRelOff); err != nil {
		return 0, err
	}
	return uint64(int64(tr.Address) + int64(tr.RelOff) + int64(pointerRelOff)), nil
}

type RelativeIndirectablePointer struct {
	Address uint64
	RelOff  int32
}

func (ri RelativeIndirectablePointer) IsSet() bool {
	return ri.RelOff != 0
}
func (ri RelativeIndirectablePointer) GetRelPtrAddress() uint64 {
	return uint64(int64(ri.Address) + int64(ri.RelOff))
}
func (ri RelativeIndirectablePointer) GetAddress(readPtr func(uint64) (uint64, error)) (uint64, error) {
	addr := ri.GetRelPtrAddress()
	if (addr & 1) == 1 {
		addr = addr &^ 1
		return readPtr(addr)
	} else {
		return addr, nil
	}
}

type RelativeTargetProtocolDescriptorPointer struct {
	Address uint64
	RelOff  int32
}

func (r RelativeTargetProtocolDescriptorPointer) IsSet() bool {
	return r.RelOff != 0
}
func (r RelativeTargetProtocolDescriptorPointer) mask() uint64 {
	return uint64(4-1) &^ 1
}
func (r RelativeTargetProtocolDescriptorPointer) IsObjC() bool {
	return uint64(int64(r.Address)+int64(r.RelOff))&r.mask()>>1 == 1
}
func (r RelativeTargetProtocolDescriptorPointer) GetRelPtrAddress() uint64 {
	return uint64(int64(r.Address)+int64(r.RelOff)) &^ r.mask()
}
func (r RelativeTargetProtocolDescriptorPointer) GetAddress(readPtr func(uint64) (uint64, error)) (uint64, error) {
	addr := r.GetRelPtrAddress()
	if (addr & 1) == 1 {
		addr = addr &^ 1
		return readPtr(addr)
	} else {
		return addr, nil
	}
}
func (r RelativeTargetProtocolDescriptorPointer) String() string {
	return fmt.Sprintf("addr: %#x, off: %d, mask: %#x, objc: %t -> %#x", r.Address, r.RelOff, r.mask(), r.IsObjC(), r.GetRelPtrAddress())
}
