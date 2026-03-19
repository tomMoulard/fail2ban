package swift

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types"
)

type Class struct {
	TargetClassDescriptor
	SuperClass                 string
	GenericContext             *TypeGenericContext
	ForeignMetadata            *TargetForeignMetadataInitialization
	SingletonMetadata          *TargetSingletonMetadataInitialization
	VTable                     *VTable
	ResilientSuperclass        *ResilientSuperclass
	MethodOverrides            []TargetMethodOverrideDescriptor
	ObjCResilientClassStubInfo *TargetObjCResilientClassStubInfo
	Metadatas                  []Metadata
	MetadataAccessors          []TargetCanonicalSpecializedMetadataAccessorsListEntry
	CachingOnceToken           *TargetCanonicalSpecializedMetadatasCachingOnceToken
}

type TargetClassDescriptor struct {
	TargetTypeContextDescriptor
	// The type of the superclass, expressed as a mangled type name that can
	// refer to the generic arguments of the subclass type.
	SuperclassType RelativeDirectPointer
	// [MetadataNegativeSizeInWords] (uint32)
	//   If this descriptor does not have a resilient superclass, this is the
	//   negative size of metadata objects of this class (in words).
	// [ResilientMetadataBounds] (TargetRelativeDirectPointer)
	//   If this descriptor has a resilient superclass, this is a reference
	//   to a cache holding the metadata's extents.
	MetadataNegativeSizeInWordsORResilientMetadataBounds uint32 // UNION
	// [MetadataPositiveSizeInWords] (uint32)
	//   If this descriptor does not have a resilient superclass, this is the
	//   positive size of metadata objects of this class (in words).
	// [ExtraClassFlags] (ExtraClassDescriptorFlags)
	//   Otherwise, these flags are used to do things like indicating
	//   the presence of an Objective-C resilient class stub.
	MetadataPositiveSizeInWordsORExtraClassFlags uint32 // UNION
	// The number of additional members added by this class to the class
	// metadata.  This data is opaque by default to the runtime, other than
	// as exposed in other members; it's really just
	// NumImmediateMembers * sizeof(void*) bytes of data.
	//
	// Whether those bytes are added before or after the address point
	// depends on areImmediateMembersNegative().
	NumImmediateMembers uint32
	// The number of stored properties in the class, not including its
	// superclasses. If there is a field offset vector, this is its length.
	NumFields uint32
	// The offset of the field offset vector for this class's stored
	// properties in its metadata, in words. 0 means there is no field offset vector.
	//
	// If this class has a resilient superclass, this offset is relative to
	// the size of the resilient superclass metadata. Otherwise, it is absolute.
	FieldOffsetVectorOffset uint32
}

func (tcd TargetClassDescriptor) Size() int64 {
	return int64(
		int(tcd.TargetTypeContextDescriptor.Size()) +
			binary.Size(tcd.SuperclassType.RelOff) +
			binary.Size(tcd.MetadataNegativeSizeInWordsORResilientMetadataBounds) +
			binary.Size(tcd.MetadataPositiveSizeInWordsORExtraClassFlags) +
			binary.Size(tcd.NumImmediateMembers) +
			binary.Size(tcd.NumFields) +
			binary.Size(tcd.FieldOffsetVectorOffset))
}

func (c *TargetClassDescriptor) Read(r io.Reader, addr uint64) error {
	if err := c.TargetTypeContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	c.SuperclassType.Address = addr + uint64(c.TargetTypeContextDescriptor.Size())
	if err := binary.Read(r, binary.LittleEndian, &c.SuperclassType.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.MetadataNegativeSizeInWordsORResilientMetadataBounds); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.MetadataPositiveSizeInWordsORExtraClassFlags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.NumImmediateMembers); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.NumFields); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.FieldOffsetVectorOffset); err != nil {
		return err
	}
	return nil
}

func (c TargetClassDescriptor) HasObjCResilientClassStub() bool {
	if !c.Flags.KindSpecific().HasResilientSuperclass() {
		return false
	}
	return ExtraClassDescriptorFlags(c.MetadataPositiveSizeInWordsORExtraClassFlags).HasObjCResilientClassStub()
}

// Extra flags for resilient classes, since we need more than 16 bits of flags there.
type ExtraClassDescriptorFlags uint32

const (
	// Set if the context descriptor includes a pointer to an Objective-C
	// resilient class stub structure. See the description of
	// TargetObjCResilientClassStubInfo in Metadata.h for details.
	//
	// Only meaningful for class descriptors when Objective-C interop is
	// enabled.
	HasObjCResilientClassStub = 0
)

func (f ExtraClassDescriptorFlags) HasObjCResilientClassStub() bool {
	return types.ExtractBits(uint64(f), HasObjCResilientClassStub, 1) != 0
}

type ResilientSuperclass struct {
	TargetResilientSuperclass
	Type *Type
}

type TargetResilientSuperclass struct {
	// The superclass of this class.  This pointer can be interpreted
	// using the superclass reference kind stored in the type context
	// descriptor flags.  It is null if the class has no formal superclass.
	//
	// Note that SwiftObject, the implicit superclass of all Swift root
	// classes when building with ObjC compatibility, does not appear here.
	Superclass RelativeDirectPointer
}

func (t TargetResilientSuperclass) Size() int64 {
	return int64(binary.Size(t.Superclass.RelOff))
}

func (t *TargetResilientSuperclass) Read(r io.Reader, addr uint64) error {
	t.Superclass.Address = addr
	return binary.Read(r, binary.LittleEndian, &t.Superclass.RelOff)
}

type VTable struct {
	TargetVTableDescriptorHeader
	Methods []Method
}

type TargetVTableDescriptorHeader struct {
	VTableOffset uint32
	VTableSize   uint32
}

type Method struct {
	TargetMethodDescriptor
	Address uint64
	Symbol  string
}

type TargetMethodDescriptor struct {
	Flags MethodDescriptorFlags
	Impl  TargetRelativeDirectPointer
}

func (md TargetMethodDescriptor) Size() int64 {
	return int64(binary.Size(md.Flags) + binary.Size(md.Impl.RelOff))
}

func (md *TargetMethodDescriptor) Read(r io.Reader, addr uint64) error {
	md.Impl.Address = addr + uint64(binary.Size(md.Flags))
	if err := binary.Read(r, binary.LittleEndian, &md.Flags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &md.Impl.RelOff); err != nil {
		return err
	}
	return nil
}

type MDKind uint8

const (
	MDKMethod MDKind = iota
	MDKInit
	MDKGetter
	MDKSetter
	MDKModifyCoroutine
	MDKReadCoroutine
	MDKMax
)

func (md MDKind) String() string {
	switch md {
	case MDKMethod:
		return "method"
	case MDKInit:
		return "init"
	case MDKGetter:
		return "getter"
	case MDKSetter:
		return "setter"
	case MDKModifyCoroutine:
		return "modify"
	case MDKReadCoroutine:
		return "read"
	default:
		return fmt.Sprintf("unknown kind %d", md)
	}
}

type MethodDescriptorFlags uint32

const (
	KindMask                = 0x0F // 16 kinds should be enough for anybody
	IsInstanceMask          = 0x10
	IsDynamicMask           = 0x20
	IsAsyncMask             = 0x40
	ExtraDiscriminatorShift = 16
	ExtraDiscriminatorMask  = 0xFFFF0000
)

func (f MethodDescriptorFlags) Kind() MDKind {
	return MDKind(f & KindMask)
}
func (f MethodDescriptorFlags) IsInstance() bool {
	return (f & IsInstanceMask) != 0
}
func (f MethodDescriptorFlags) IsDynamic() bool {
	return (f & IsDynamicMask) != 0
}
func (f MethodDescriptorFlags) IsAsync() bool {
	return (f & IsAsyncMask) != 0
}
func (f MethodDescriptorFlags) ExtraDiscriminator() uint16 {
	return uint16(f >> ExtraDiscriminatorShift)
}
func (f MethodDescriptorFlags) String() string {
	var flags []string
	if f.IsDynamic() {
		flags = append(flags, "dynamic")
	}
	if f.IsAsync() {
		flags = append(flags, "async")
	}
	var extra string
	if f.ExtraDiscriminator() != 0 {
		extra = fmt.Sprintf("__ptrauth(%04x)", f.ExtraDiscriminator())
	}
	if len(flags) == 0 {
		return extra
	}
	return fmt.Sprintf("%s (%s)", extra, strings.Join(flags, "|"))
}
func (f MethodDescriptorFlags) Verbose() string {
	var flags []string
	if f.IsInstance() {
		flags = append(flags, "instance")
	}
	if f.IsDynamic() {
		flags = append(flags, "dynamic")
	}
	if f.IsAsync() {
		flags = append(flags, "async")
	}
	var extra string
	if f.ExtraDiscriminator() != 0 {
		extra = fmt.Sprintf(" __ptrauth(%04x)", f.ExtraDiscriminator())
	}
	if len(flags) == 0 {
		return fmt.Sprintf("%s%s", f.Kind(), extra)
	}
	return fmt.Sprintf("%s%s (%s)", f.Kind(), extra, strings.Join(flags, "|"))
}

// Header for a class vtable override descriptor. This is a variable-sized
// structure that provides implementations for overrides of methods defined
// in superclasses.
type TargetOverrideTableHeader struct {
	// The number of MethodOverrideDescriptor records following the vtable
	// override header in the class's nominal type descriptor.
	NumEntries uint32
}

// An entry in the method override table, referencing a method from one of our
// ancestor classes, together with an implementation.
type TargetMethodOverrideDescriptor struct {
	// The class containing the base method.
	Class RelativeDirectPointer
	// The base method.
	Method RelativeDirectPointer
	// The implementation of the override.
	Impl RelativeDirectPointer // UNION
}

func (mod TargetMethodOverrideDescriptor) String() string {
	return fmt.Sprintf("class %#x method %#x impl %#x", mod.Class.GetAddress(), mod.Method.GetAddress(), mod.Impl.GetAddress())
}

func (mod TargetMethodOverrideDescriptor) Size() int64 {
	return int64(
		binary.Size(mod.Class.RelOff) +
			binary.Size(mod.Method.RelOff) +
			binary.Size(mod.Impl.RelOff))
}

func (mod *TargetMethodOverrideDescriptor) Read(r io.Reader, addr uint64) error {
	mod.Class.Address = addr
	mod.Method.Address = addr + uint64(binary.Size(mod.Class.RelOff))
	mod.Impl.Address = addr + uint64(binary.Size(mod.Class.RelOff)+binary.Size(mod.Method.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &mod.Class.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &mod.Method.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &mod.Impl.RelOff); err != nil {
		return err
	}
	return nil
}

// TargetObjCResilientClassStubInfo structure that stores a reference to an Objective-C class stub.
//
// This is not the class stub itself; it is part of a class context descriptor.
type TargetObjCResilientClassStubInfo struct {
	// A relative pointer to an Objective-C resilient class stub.
	//
	// We do not declare a struct type for class stubs since the Swift runtime
	// does not need to interpret them. The class stub struct is part of
	// the Objective-C ABI, and is laid out as follows:
	// - isa pointer, always 1
	// - an update callback, of type 'Class (*)(Class *, objc_class_stub *)'
	//
	// Class stubs are used for two purposes:
	//
	// - Objective-C can reference class stubs when calling static methods.
	// - Objective-C and Swift can reference class stubs when emitting
	//   categories (in Swift, extensions with @objc members).
	Stub TargetRelativeDirectPointer
}

func (t TargetObjCResilientClassStubInfo) Size() int64 {
	return int64(binary.Size(t.Stub.RelOff))
}

func (t *TargetObjCResilientClassStubInfo) Read(r io.Reader, addr uint64) error {
	t.Stub.Address = addr
	return binary.Read(r, binary.LittleEndian, &t.Stub.RelOff)
}
