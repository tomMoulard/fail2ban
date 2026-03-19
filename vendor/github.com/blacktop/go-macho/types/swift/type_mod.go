package swift

import (
	"encoding/binary"
	"io"
)

type TargetModuleContext struct {
	TargetModuleContextDescriptor
	Name   string
	Parent string
}

type TargetModuleContextDescriptor struct {
	TargetContextDescriptor
	NameOffset RelativeDirectPointer
}

func (tmc TargetModuleContextDescriptor) Size() int64 {
	return int64(int(tmc.TargetContextDescriptor.Size()) + binary.Size(tmc.NameOffset.RelOff))
}

func (tmcd *TargetModuleContextDescriptor) Read(r io.Reader, addr uint64) error {
	if err := tmcd.TargetContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	addr += uint64(tmcd.TargetContextDescriptor.Size())
	tmcd.NameOffset.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &tmcd.NameOffset.RelOff); err != nil {
		return err
	}
	return nil
}
