package swift

import (
	"encoding/binary"
	"fmt"
	"io"
)

// __swift5_acfuncs

type AccessibleFunctionsSection struct {
	Begin uint64 // AccessibleFunctionRecord
	End   uint64 // AccessibleFunctionRecord
}

type AccessibleFunctionFlags uint32

const (
	Distributed AccessibleFunctionFlags = 0
)

type TargetAccessibleFunctionRecord struct {
	Name               RelativeDirectPointer // char *
	GenericEnvironment RelativeDirectPointer // TargetGenericEnvironment
	FunctionType       RelativeDirectPointer // mangled name
	Function           RelativeDirectPointer // void *
	Flags              AccessibleFunctionFlags
}

func (r TargetAccessibleFunctionRecord) Size() int64 {
	return int64(
		binary.Size(r.Name.RelOff) +
			binary.Size(r.GenericEnvironment.RelOff) +
			binary.Size(r.FunctionType.RelOff) +
			binary.Size(r.Function.RelOff) +
			binary.Size(r.Flags),
	)
}

func (f *TargetAccessibleFunctionRecord) Read(r io.Reader, addr uint64) error {
	f.Name.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &f.Name.RelOff); err != nil {
		return err
	}
	f.GenericEnvironment.Address = addr + uint64(binary.Size(f.Name.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &f.GenericEnvironment.RelOff); err != nil {
		return err
	}
	f.FunctionType.Address = addr + uint64(binary.Size(f.Name.RelOff)) + uint64(binary.Size(f.GenericEnvironment.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &f.FunctionType.RelOff); err != nil {
		return err
	}
	f.Function.Address = addr + uint64(binary.Size(f.Name.RelOff)) + uint64(binary.Size(f.GenericEnvironment.RelOff)) + uint64(binary.Size(f.FunctionType.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &f.Function.RelOff); err != nil {
		return err
	}
	return binary.Read(r, binary.LittleEndian, &f.Flags)
}

type AccessibleFunctionCacheEntry struct {
	Name    string
	NameLen uint32
	R       uint64 // AccessibleFunctionRecord

}

type AccessibleFunctionsState struct {
	Cache          AccessibleFunctionCacheEntry
	SectionsToScan AccessibleFunctionsSection
}

type AccessibleFunction struct {
	Name               string
	FunctionType       string
	FunctionAddress    uint64
	GenericEnvironment uint64
	Flags              AccessibleFunctionFlags
}

func (af AccessibleFunction) String() string {
	return fmt.Sprintf("%s : %s (fn: %#x, env: %#x, flags: %#x)", af.Name, af.FunctionType, af.FunctionAddress, af.GenericEnvironment, uint32(af.Flags))
}
