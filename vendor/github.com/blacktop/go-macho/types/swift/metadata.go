package swift

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/go-macho/types"
)

//go:generate stringer -type MetadataKind -linecomment -output metadata_string.go

const (
	// Non-type metadata kinds have this bit set.
	MetadataKindIsNonType = 0x400
	// Non-heap metadata kinds have this bit set.
	MetadataKindIsNonHeap = 0x200
	// The above two flags are negative because the "class" kind has to be zero,
	// and class metadata is both type and heap metadata.
	// Runtime-private metadata has this bit set. The compiler must not statically
	// generate metadata objects with these kinds, and external tools should not
	// rely on the stability of these values or the precise binary layout of
	// their associated data structures.
	MetadataKindIsRuntimePrivate = 0x100
)

type MetadataKind uint32

const (
	ClassMetadataKind                    MetadataKind = 0                                                        // class
	StructMetadataKind                   MetadataKind = 0 | MetadataKindIsNonHeap                                // struct
	EnumMetadataKind                     MetadataKind = 1 | MetadataKindIsNonHeap                                // enum
	OptionalMetadataKind                 MetadataKind = 2 | MetadataKindIsNonHeap                                // optional
	ForeignClassMetadataKind             MetadataKind = 3 | MetadataKindIsNonHeap                                // foreign class
	ForeignReferenceTypeMetadataKind     MetadataKind = 4 | MetadataKindIsNonHeap                                // foreign reference type
	OpaqueMetadataKind                   MetadataKind = 0 | MetadataKindIsRuntimePrivate | MetadataKindIsNonHeap // opaque
	TupleMetadataKind                    MetadataKind = 1 | MetadataKindIsRuntimePrivate | MetadataKindIsNonHeap // tuple
	FunctionMetadataKind                 MetadataKind = 2 | MetadataKindIsRuntimePrivate | MetadataKindIsNonHeap // function
	ExistentialMetadataKind              MetadataKind = 3 | MetadataKindIsRuntimePrivate | MetadataKindIsNonHeap // existential
	MetatypeMetadataKind                 MetadataKind = 4 | MetadataKindIsRuntimePrivate | MetadataKindIsNonHeap // metatype
	ObjCClassWrapperMetadataKind         MetadataKind = 5 | MetadataKindIsRuntimePrivate | MetadataKindIsNonHeap // objc class wrapper
	ExistentialMetatypeMetadataKind      MetadataKind = 6 | MetadataKindIsRuntimePrivate | MetadataKindIsNonHeap // existential metatype
	ExtendedExistentialMetadataKind      MetadataKind = 7 | MetadataKindIsRuntimePrivate | MetadataKindIsNonHeap // extended existential type
	HeapLocalVariableMetadataKind        MetadataKind = 0 | MetadataKindIsNonType                                // heap local variable
	HeapGenericLocalVariableMetadataKind MetadataKind = 0 | MetadataKindIsNonType | MetadataKindIsRuntimePrivate // heap generic local variable
	ErrorObjectMetadataKind              MetadataKind = 1 | MetadataKindIsNonType | MetadataKindIsRuntimePrivate // error object
	TaskMetadataKind                     MetadataKind = 2 | MetadataKindIsNonType | MetadataKindIsRuntimePrivate // task
	JobMetadataKind                      MetadataKind = 3 | MetadataKindIsNonType | MetadataKindIsRuntimePrivate // job
	// The largest possible non-isa-pointer metadata kind value.
	LastEnumerated = 0x7FF
	// This is included in the enumeration to prevent against attempts to
	// exhaustively match metadata kinds. Future Swift runtimes or compilers
	// may introduce new metadata kinds, so for forward compatibility, the
	// runtime must tolerate metadata with unknown kinds.
	// This specific value is not mapped to a valid metadata kind at this time,
	// however.
)

type Metadata struct {
	TargetCanonicalSpecializedMetadatasListEntry
	TargetMetadata
}

type TargetCanonicalSpecializedMetadatasListCount struct {
	Count uint32
}

type TargetCanonicalSpecializedMetadatasListEntry struct {
	Metadata RelativeDirectPointer // TargetMetadata
}

func (f TargetCanonicalSpecializedMetadatasListEntry) Size() int64 {
	return int64(binary.Size(f.Metadata.RelOff))
}

func (f *TargetCanonicalSpecializedMetadatasListEntry) Read(r io.Reader, addr uint64) error {
	f.Metadata.Address = addr
	return binary.Read(r, binary.LittleEndian, &f.Metadata.RelOff)
}

type TargetCanonicalSpecializedMetadataAccessorsListEntry struct {
	Accessor RelativeDirectPointer
}

func (f TargetCanonicalSpecializedMetadataAccessorsListEntry) Size() int64 {
	return int64(binary.Size(f.Accessor.RelOff))
}

func (f *TargetCanonicalSpecializedMetadataAccessorsListEntry) Read(r io.Reader, addr uint64) error {
	f.Accessor.Address = addr
	return binary.Read(r, binary.LittleEndian, &f.Accessor.RelOff)
}

type TargetCanonicalSpecializedMetadatasCachingOnceToken struct {
	Token TargetRelativeDirectPointer
}

func (f TargetCanonicalSpecializedMetadatasCachingOnceToken) Size() int64 {
	return int64(binary.Size(f.Token.RelOff))
}

func (f *TargetCanonicalSpecializedMetadatasCachingOnceToken) Read(r io.Reader, addr uint64) error {
	f.Token.Address = addr
	return binary.Read(r, binary.LittleEndian, &f.Token.RelOff)
}

// The instantiation cache for generic metadata.  This must be guaranteed
// to zero-initialized before it is first accessed.  Its contents are private
// to the runtime.
type TargetGenericMetadataInstantiationCache struct {
	// Data that the runtime can use for its own purposes.  It is guaranteed
	// to be zero-filled by the compiler. Might be null when building with
	// -disable-preallocated-instantiation-caches.
	PrivateData [16]byte
}

type GenericMetadataPattern struct {
	TargetGenericMetadataPattern
	ValueWitnessTable *ValueWitnessTable
	ExtraDataPattern  *TargetGenericMetadataPartialPattern
}

type TargetGenericMetadataPattern struct {
	InstantiationFunction RelativeDirectPointer
	CompletionFunction    RelativeDirectPointer
	PatternFlags          GenericMetadataPatternFlags
}

func (p *TargetGenericMetadataPattern) Read(r io.Reader, addr uint64) error {
	p.InstantiationFunction.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &p.InstantiationFunction.RelOff); err != nil {
		return err
	}
	p.CompletionFunction.Address = addr + uint64(binary.Size(p.InstantiationFunction.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &p.CompletionFunction.RelOff); err != nil {
		return err
	}
	return binary.Read(r, binary.LittleEndian, &p.PatternFlags)
}

type GenericMetadataPatternFlags uint32

const (
	// All of these values are bit offsets or widths.
	// General flags build up from 0.
	// Kind-specific flags build down from 31.

	/// Does this pattern have an extra-data pattern?
	HasExtraDataPattern = 0

	/// Do instances of this pattern have a bitset of flags that occur at the
	/// end of the metadata, after the extra data if there is any?
	HasTrailingFlags = 1

	// Class-specific flags.

	/// Does this pattern have an immediate-members pattern?
	Class_HasImmediateMembersPattern = 31

	// Value-specific flags.

	/// For value metadata: the metadata kind of the type.
	Value_MetadataKind       = 21
	Value_MetadataKind_width = 11
)

func (f GenericMetadataPatternFlags) HasExtraDataPattern() bool {
	return types.ExtractBits(uint64(f), HasExtraDataPattern, 1) != 0
}
func (f GenericMetadataPatternFlags) HasTrailingFlags() bool {
	return types.ExtractBits(uint64(f), HasTrailingFlags, 1) != 0
}
func (f GenericMetadataPatternFlags) HasClassImmediateMembersPattern() bool {
	return types.ExtractBits(uint64(f), Class_HasImmediateMembersPattern, 1) != 0
}
func (f GenericMetadataPatternFlags) MetadataKind() MetadataKind {
	return MetadataKind(types.ExtractBits(uint64(f), Value_MetadataKind, Value_MetadataKind_width))
}
func (f GenericMetadataPatternFlags) String() string {
	return fmt.Sprintf("HasExtraDataPattern: %t, HasTrailingFlags: %t, HasClassImmediateMembersPattern: %t, MetadataKind: %s",
		f.HasExtraDataPattern(), f.HasTrailingFlags(), f.HasClassImmediateMembersPattern(), f.MetadataKind())
}

// TargetGenericMetadataPartialPattern part of a generic metadata instantiation pattern.
type TargetGenericMetadataPartialPattern struct {
	Pattern       TargetRelativeDirectPointer // A reference to the pattern.  The pattern must always be at least word-aligned.
	OffsetInWords uint16                      // The offset into the section into which to copy this pattern, in words.
	SizeInWords   uint16                      // The size of the pattern in words.
}

func (p *TargetGenericMetadataPartialPattern) Read(r io.Reader, addr uint64) error {
	p.Pattern.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &p.Pattern.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.OffsetInWords); err != nil {
		return err
	}
	return binary.Read(r, binary.LittleEndian, &p.SizeInWords)
}

// An instantiation pattern for generic class metadata.
type TargetGenericClassMetadataPattern struct {
	Destroy       int32      // The heap-destructor function.
	IVarDestroyer int32      // The ivar-destructor function.
	Flags         ClassFlags // The class flags.
	// The following fields are only present in ObjC interop.
	ClassRODataOffset     uint16 // The offset of the class RO-data within the extra data pattern, in words.
	MetaclassObjectOffset uint16 // The offset of the metaclass object within the extra data pattern, in words.
	MetaclassRODataOffset uint16 // The offset of the metaclass RO-data within the extra data pattern, in words.
	Reserved              uint16
}

type ClassFlags uint32

const (
	/// Is this a Swift class from the Darwin pre-stable ABI?
	/// This bit is clear in stable ABI Swift classes.
	/// The Objective-C runtime also reads this bit.
	IsSwiftPreStableABI ClassFlags = 0x1
	/// Does this class use Swift refcounting?
	UsesSwiftRefcounting ClassFlags = 0x2
	/// Has this class a custom name, specified with the @objc attribute?
	HasCustomObjCName ClassFlags = 0x4
	/// Whether this metadata is a specialization of a generic metadata pattern
	/// which was created during compilation.
	IsStaticSpecialization ClassFlags = 0x8
	/// Whether this metadata is a specialization of a generic metadata pattern
	/// which was created during compilation and made to be canonical by
	/// modifying the metadata accessor.
	IsCanonicalStaticSpecialization ClassFlags = 0x10
)

// An instantiation pattern for generic value metadata.
type TargetGenericValueMetadataPattern struct {
	/// The value-witness table.  Indirectable so that we can re-use tables
	/// from other libraries if that seems wise.
	ValueWitnesses RelativeIndirectablePointer
}

type TargetTypeMetadataHeader struct {
	LayoutString   uint64
	ValueWitnesses uint64
}

// TargetMetadata the common structure of all type metadata.
type TargetMetadata struct {
	Kind                uint64
	TypeDescriptor      uint64
	TypeMetadataAddress uint64
}

func (m TargetMetadata) GetKind() MetadataKind {
	if m.Kind > LastEnumerated {
		return ClassMetadataKind
	}
	return MetadataKind(m.Kind)
}

type TargetValueMetadata struct {
	Description uint64 // An out-of-line description of the type. (signed pointer to TargetValueTypeDescriptor)
}

type TargetValueTypeDescriptor TargetTypeContextDescriptor

type TargetSingletonMetadataInitialization struct {
	InitializationCacheOffset TargetRelativeDirectPointer // The initialization cache. Out-of-line because mutable.
	IncompleteMetadata        TargetRelativeDirectPointer // UNION: The incomplete metadata, for structs, enums and classes without resilient ancestry.
	// ResilientPattern
	// If the class descriptor's hasResilientSuperclass() flag is set,
	// this field instead points at a pattern used to allocate and
	// initialize metadata for this class, since it's size and contents
	// is not known at compile time.
	CompletionFunction TargetRelativeDirectPointer // The completion function. The pattern will always be null, even for a resilient class.
}

func (s TargetSingletonMetadataInitialization) Size() int64 {
	return int64(
		binary.Size(s.InitializationCacheOffset.RelOff) +
			binary.Size(s.IncompleteMetadata.RelOff) +
			binary.Size(s.CompletionFunction.RelOff))
}

func (s *TargetSingletonMetadataInitialization) Read(r io.Reader, addr uint64) error {
	s.InitializationCacheOffset.Address = addr
	s.IncompleteMetadata.Address = addr + uint64(binary.Size(s.InitializationCacheOffset.RelOff))
	s.CompletionFunction.Address = addr + uint64(binary.Size(s.InitializationCacheOffset.RelOff)*2)
	if err := binary.Read(r, binary.LittleEndian, &s.InitializationCacheOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &s.IncompleteMetadata.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &s.CompletionFunction.RelOff); err != nil {
		return err
	}
	return nil
}

// TargetForeignMetadataInitialization is the control structure for performing non-trivial initialization of
// singleton foreign metadata.
type TargetForeignMetadataInitialization struct {
	CompletionFunction RelativeDirectPointer // The completion function. The pattern will always be null.
}

func (f TargetForeignMetadataInitialization) Size() int64 {
	return int64(binary.Size(f.CompletionFunction.RelOff))
}

func (f *TargetForeignMetadataInitialization) Read(r io.Reader, addr uint64) error {
	f.CompletionFunction.Address = addr
	return binary.Read(r, binary.LittleEndian, &f.CompletionFunction.RelOff)
}

// An instantiation pattern for non-generic resilient class metadata.
//
// Used for classes with resilient ancestry, that is, where at least one
// ancestor is defined in a different resilience domain.
//
// The hasResilientSuperclass() flag in the class context descriptor is
// set in this case, and hasSingletonMetadataInitialization() must be
// set as well.
//
// The pattern is referenced from the SingletonMetadataInitialization
// record in the class context descriptor.
type TargetResilientClassMetadataPattern struct {
	/// A function that allocates metadata with the correct size at runtime.
	///
	/// If this is null, the runtime instead calls swift_relocateClassMetadata(),
	/// passing in the class descriptor and this pattern.
	RelocationFunction int32
	/// The heap-destructor function.
	Destroy int32
	/// The ivar-destructor function.
	IVarDestroyer int32
	// The class flags.
	Flags ClassFlags
	// The following fields are only present in ObjC interop.

	/// Our ClassROData.
	Data int32
	/// Our metaclass.
	Metaclass int32
}
