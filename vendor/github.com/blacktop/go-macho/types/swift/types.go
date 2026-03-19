package swift

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/blacktop/go-macho/types"
)

//go:generate stringer -type ContextDescriptorKind,TypeReferenceKind,MetadataInitializationKind,SpecialKind,GenericParamKind,GenericRequirementLayoutKind -linecomment -output types_string.go

// __TEXT.__swift5_types
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a nominal type descriptor in the __TEXT.__const section.

type Type struct {
	Address        uint64
	Parent         *Type
	Name           string
	ImportInfo     string
	Kind           ContextDescriptorKind
	AccessFunction uint64
	Fields         *Field
	Type           any
	Size           int64
}

func (t Type) IsCImportedModuleName() bool {
	if t.Kind == CDKindModule {
		return t.Name == MANGLING_MODULE_OBJC
	}
	return false
}

func (t Type) String() string {
	return t.dump(false)
}
func (t Type) Verbose() string {
	return t.dump(true)
}
func (t Type) dump(verbose bool) string {
	var addr string
	switch t.Kind {
	case CDKindModule:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s", addr, t.Kind, t.Name)
	case CDKindExtension:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		var parent string
		if t.Parent != nil && (t.Parent.Name != "" || t.Parent.Parent.Name != "") {
			if t.Parent.Parent.Name != "" {
				parent += t.Parent.Parent.Name + "."
			}
			if t.Parent.Name != "" {
				parent += t.Parent.Name + "."
			}
		}
		return fmt.Sprintf("%s%s %s%s", addr, t.Kind, parent, t.Name)
	case CDKindAnonymous:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s", addr, t.Kind, t.Name)
	case CDKindProtocol:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s", addr, t.Kind, t.Name)
	case CDKindOpaqueType:
		var typargs []string
		if len(t.Type.(OpaqueType).TypeArgs) > 0 {
			typargs = append(typargs, "")
			typargs = append(typargs, "  /* type args */")
			for _, a := range t.Type.(OpaqueType).TypeArgs {
				if verbose {
					addr = fmt.Sprintf("/* %#x */ ", a.GetAddress())
				}
				typargs = append(typargs, fmt.Sprintf("    %s%s", addr, a.Name))
			}
			typargs = append(typargs, "")
		}
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s {%s}", addr, t.Kind, strings.Join(typargs, "\n"))
	case CDKindClass:
		var fields []string
		if t.Fields != nil {
			var faddr string
			for _, r := range t.Fields.Records {
				var typ string
				if len(r.MangledType) > 0 {
					if strings.Contains(r.MangledType, "()") {
						typ = " = " + r.MangledType
						typ = strings.Replace(typ, "() ?", "()?", 1)
					} else {
						typ = ": " + r.MangledType
					}
				}
				if verbose {
					faddr = fmt.Sprintf("/* %#x */ ", r.FieldNameOffset.Address)
				}
				fields = append(fields, fmt.Sprintf("    %s%s %s%s", faddr, r.Flags, strings.Replace(r.Name, "$__lazy_storage_$_", "lazy ", 1), typ))
			}
		}
		var meths []string
		if t.Type.(Class).VTable != nil {
			var maddr string
			for _, m := range t.Type.(Class).VTable.Methods {
				var static string
				if !m.Flags.IsInstance() {
					static = "static "
				}
				sym := m.Symbol
				if m.Impl.IsSet() {
					if m.Symbol == "" {
						sym = fmt.Sprintf("%sfunc sub_%x // %s", static, m.Address, m.Flags.Verbose())
					} else {
						sym = fmt.Sprintf("%sfunc %s", static, sym)
						if len(m.Flags.String()) > 0 {
							sym += " // " + m.Flags.String()
						}
					}
				} else {
					if m.Symbol == "" {
						sym = fmt.Sprintf("// <stripped> %sfunc %s", static, m.Flags.Verbose())
					} else {
						sym = fmt.Sprintf("// <stripped> %sfunc %s %s", static, sym, m.Flags)
					}
				}
				if verbose && m.Address != 0 {
					maddr = fmt.Sprintf("/* %#x */ ", m.Impl.Address-4) // minus 4 to get to the start of the TargetMethodDescriptor
				}
				meths = append(meths, fmt.Sprintf("    %s%s", maddr, sym))
			}
		}
		var accessor string
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
			if t.Type.(Class).AccessFunctionPtr.IsSet() {
				accessor = fmt.Sprintf(" // accessor %#x", t.Type.(Class).AccessFunctionPtr.GetAddress())
			}
		}
		var parent string
		if t.Parent != nil && (t.Parent.Name != "" || t.Parent.Parent.Name != "") {
			if t.Parent.Parent.Name != "" {
				parent += t.Parent.Parent.Name + "."
			}
			if t.Parent.Name != "" {
				parent += t.Parent.Name + "."
			}
		}
		var superClass string
		if t.Type.(Class).SuperClass != "" {
			superClass = fmt.Sprintf(": %s", t.Type.(Class).SuperClass)
		}
		if t.Type.(Class).Flags.KindSpecific().HasResilientSuperclass() {
			superClass = t.Type.(Class).ResilientSuperclass.Type.Name
			if t.Type.(Class).ResilientSuperclass.Type.Parent.Name != "" {
				superClass += t.Type.(Class).ResilientSuperclass.Type.Parent.Name + "." + superClass
			}
		}
		var impinf string
		if t.ImportInfo != "" {
			impinf = fmt.Sprintf("typealias %s %s\n", t.ImportInfo, t.Name)
			t.Name = t.ImportInfo
		}
		var ctx string
		var size string
		if t.Type.(Class).GenericContext != nil {
			if len(t.Type.(Class).GenericContext.Requirements) > 0 {
				var keyargs []string
				var where []string
				for _, req := range t.Type.(Class).GenericContext.Requirements {
					if req.Flags.HasKeyArgument() {
						keyargs = append(keyargs, fmt.Sprintf("%s: %s", req.Param, req.Kind))
					} else {
						switch req.Flags.Kind() {
						case GRKindBaseClass:
							keyargs = append(keyargs, fmt.Sprintf("%s: %s, B", req.Param, req.Kind))
						case GRKindSameType:
							where = append(where, fmt.Sprintf("%s %s", req.Param, req.Kind))
						default:
							fmt.Println(req.Flags.String())
						}
					}
				}
				if len(keyargs) > 0 {
					ctx = fmt.Sprintf("<%s>", strings.Join(keyargs, ", "))
				}
				if len(where) > 0 {
					ctx += fmt.Sprintf("\n  where %s", strings.Join(where, ", "))
				}
			}
			if t.Type.(Class).GenericContext.GenericMetadataPattern != nil && t.Type.(Class).GenericContext.GenericMetadataPattern.ValueWitnessTable != nil {
				if t.Type.(Class).GenericContext.GenericMetadataPattern.ValueWitnessTable.Size > 0 {
					size = fmt.Sprintf(", size: %d", t.Type.(Class).GenericContext.GenericMetadataPattern.ValueWitnessTable.Size)
				}
			}
		}
		if len(fields) == 0 && len(meths) == 0 {
			return fmt.Sprintf("%s%s%s %s%s%s%s {}%s%s", addr, impinf, t.Kind, parent, t.Name, superClass, ctx, accessor, size)
		}
		if len(fields) > 0 {
			fields = append([]string{"  /* fields */"}, fields...)
		}
		if len(meths) > 0 {
			if len(fields) > 0 {
				meths = append([]string{"\n  /* methods */"}, meths...)
			} else {
				meths = append([]string{"  /* methods */"}, meths...)
			}
		}
		return fmt.Sprintf("%s%s%s %s%s%s%s {%s%s\n%s%s\n}", addr, impinf, t.Kind, parent, t.Name, superClass, ctx, accessor, size, strings.Join(fields, "\n"), strings.Join(meths, "\n"))
	case CDKindStruct:
		var fields []string
		if t.Fields != nil {
			var faddr string
			for _, r := range t.Fields.Records {
				var typ string
				if len(r.MangledType) > 0 {
					if strings.Contains(r.MangledType, "()") {
						typ = fmt.Sprintf(" = %s", r.MangledType)
					} else {
						typ = fmt.Sprintf(": %s", r.MangledType)
					}
				}
				if verbose {
					faddr = fmt.Sprintf("/* %#x */ ", r.FieldNameOffset.Address)
				}
				fields = append(fields, fmt.Sprintf("    %s%s %s%s", faddr, r.Flags, r.Name, typ))
			}
		}
		var accessor string
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
			if t.Type.(Struct).AccessFunctionPtr.IsSet() {
				accessor = fmt.Sprintf(" // accessor %#x", t.Type.(Struct).AccessFunctionPtr.GetAddress())
			}
		}
		var parent string
		if t.Parent != nil && (t.Parent.Name != "" || t.Parent.Parent.Name != "") {
			if t.Parent.Parent.Name != "" {
				parent += t.Parent.Parent.Name + "."
			}
			if t.Parent.Name != "" {
				parent += t.Parent.Name + "."
			}
		}
		var impinf string
		if t.ImportInfo != "" {
			impinf = fmt.Sprintf("typealias %s %s\n", t.ImportInfo, t.Name)
			t.Name = t.ImportInfo
		}
		var ctx string
		var size string
		if t.Type.(Struct).GenericContext != nil {
			if len(t.Type.(Struct).GenericContext.Requirements) > 0 {
				var keyargs []string
				var where []string
				for _, req := range t.Type.(Struct).GenericContext.Requirements {
					if req.Flags.HasKeyArgument() {
						keyargs = append(keyargs, fmt.Sprintf("%s: %s", req.Param, req.Kind))
					} else {
						switch req.Flags.Kind() {
						case GRKindBaseClass:
							keyargs = append(keyargs, fmt.Sprintf("%s: %s, B", req.Param, req.Kind))
						case GRKindSameType:
							where = append(where, fmt.Sprintf("%s %s", req.Param, req.Kind))
						case GRKindProtocol, GRKindLayout:
							keyargs = append(keyargs, fmt.Sprintf("%s: %s", req.Param, req.Kind))
						default:
							fmt.Println(req.Flags.String())
						}
					}
				}
				if len(keyargs) > 0 {
					ctx = fmt.Sprintf("<%s>", strings.Join(keyargs, ", "))
				}
				if len(where) > 0 {
					ctx += fmt.Sprintf("\n  where %s", strings.Join(where, ", "))
				}
			}
			if t.Type.(Struct).GenericContext.GenericMetadataPattern != nil && t.Type.(Struct).GenericContext.GenericMetadataPattern.ValueWitnessTable != nil {
				if t.Type.(Struct).GenericContext.GenericMetadataPattern.ValueWitnessTable.Size > 0 {
					size = fmt.Sprintf(", size: %d", t.Type.(Struct).GenericContext.GenericMetadataPattern.ValueWitnessTable.Size)
				}
			}
		}
		if len(fields) == 0 {
			return fmt.Sprintf("%s%s%s %s%s%s {}%s%s", addr, impinf, t.Kind, parent, t.Name, ctx, accessor, size)
		}
		return fmt.Sprintf("%s%s%s %s%s%s {%s%s\n%s\n}", addr, impinf, t.Kind, parent, t.Name, ctx, accessor, size, strings.Join(fields, "\n"))
	case CDKindEnum:
		var fields []string
		if t.Fields != nil {
			var faddr string
			for _, r := range t.Fields.Records {
				cs := "case"
				if r.Flags.String() == "indirect case" {
					cs = "indirect case"
				}
				var typ string
				if len(r.MangledType) > 0 {
					typ = fmt.Sprintf(": %s", r.MangledType)
				}
				if verbose {
					faddr = fmt.Sprintf("/* %#x */ ", r.FieldNameOffset.Address)
				}
				fields = append(fields, fmt.Sprintf("    %s%s %s%s", faddr, cs, r.Name, typ))
			}
		}
		var parent string
		if t.Parent != nil && (t.Parent.Name != "" || t.Parent.Parent.Name != "") {
			if t.Parent.Parent.Name != "" {
				parent += t.Parent.Parent.Name + "."
			}
			if t.Parent.Name != "" {
				parent += t.Parent.Name + "."
			}
		}
		var impinf string
		if t.ImportInfo != "" {
			impinf = fmt.Sprintf("typealias %s %s\n", t.ImportInfo, t.Name)
			t.Name = t.ImportInfo
		}
		var accessor string
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
			if t.Type.(Enum).AccessFunctionPtr.IsSet() {
				accessor = fmt.Sprintf(" // accessor %#x", t.Type.(Enum).AccessFunctionPtr.GetAddress())
			}
		}
		var ctx string
		var size string
		if t.Type.(Enum).GenericContext != nil {
			if len(t.Type.(Enum).GenericContext.Requirements) > 0 {
				var parts []string
				for _, req := range t.Type.(Enum).GenericContext.Requirements {
					parts = append(parts, fmt.Sprintf("%s: %s", req.Param, req.Kind))
				}
				if len(parts) > 0 {
					ctx = fmt.Sprintf("<%s>", strings.Join(parts, ", "))
				}
			}
			if t.Type.(Enum).GenericContext.GenericMetadataPattern != nil && t.Type.(Enum).GenericContext.GenericMetadataPattern.ValueWitnessTable != nil {
				if t.Type.(Enum).GenericContext.GenericMetadataPattern.ValueWitnessTable.Size > 0 {
					size = fmt.Sprintf(", size: %d", t.Type.(Enum).GenericContext.GenericMetadataPattern.ValueWitnessTable.Size)
				}
			}
		}
		if len(fields) == 0 {
			return fmt.Sprintf("%s%s%s %s%s%s {}%s%s", addr, impinf, t.Kind, parent, t.Name, ctx, accessor, size)
		}
		return fmt.Sprintf("%s%s%s %s%s%s {%s%s\n%s\n}", addr, impinf, t.Kind, parent, t.Name, ctx, accessor, size, strings.Join(fields, "\n"))
	default:
		return fmt.Sprintf("unknown type %s", t.Name)
	}
}

type ContextDescriptorKind uint8

const (
	// This context descriptor represents a module.
	CDKindModule ContextDescriptorKind = 0 // module

	/// This context descriptor represents an extension.
	CDKindExtension ContextDescriptorKind = 1 // extension

	/// This context descriptor represents an anonymous possibly-generic context
	/// such as a function body.
	CDKindAnonymous ContextDescriptorKind = 2 // anonymous

	/// This context descriptor represents a protocol context.
	CDKindProtocol ContextDescriptorKind = 3 // protocol

	/// This context descriptor represents an opaque type alias.
	CDKindOpaqueType ContextDescriptorKind = 4 // opaque_type

	/// First kind that represents a type of any sort.
	CDKindTypeFirst = 16 // type_first

	/// This context descriptor represents a class.
	CDKindClass ContextDescriptorKind = CDKindTypeFirst // class

	/// This context descriptor represents a struct.
	CDKindStruct ContextDescriptorKind = CDKindTypeFirst + 1 // struct

	/// This context descriptor represents an enum.
	CDKindEnum ContextDescriptorKind = CDKindTypeFirst + 2 // enum

	/// Last kind that represents a type of any sort.
	CDKindTypeLast = 31 // type_last
)

// TypeReferenceKind kinds of type metadata/protocol conformance records.
type TypeReferenceKind uint8

const (
	//The conformance is for a nominal type referenced directly; getTypeDescriptor() points to the type context descriptor.
	DirectTypeDescriptor TypeReferenceKind = 0x00 // direct
	// The conformance is for a nominal type referenced indirectly; getTypeDescriptor() points to the type context descriptor.
	IndirectTypeDescriptor TypeReferenceKind = 0x01 // indirect
	// The conformance is for an Objective-C class that should be looked up by class name.
	DirectObjCClassName TypeReferenceKind = 0x02 // direct_objc_class
	// The conformance is for an Objective-C class that has no nominal type descriptor.
	// getIndirectObjCClass() points to a variable that contains the pointer to
	// the class object, which then requires a runtime call to get metadata.
	//
	// On platforms without Objective-C interoperability, this case is unused.
	IndirectObjCClass TypeReferenceKind = 0x03 // indirect_objc_class
	// We only reserve three bits for this in the various places we store it.
	FirstKind = DirectTypeDescriptor
	LastKind  = IndirectObjCClass
)

type MetadataInitializationKind uint8

const (
	// There are either no special rules for initializing the metadata or the metadata is generic.
	// (Genericity is set in the non-kind-specific descriptor flags.)
	MetadataInitNone MetadataInitializationKind = 0 // none
	//The type requires non-trivial singleton initialization using the "in-place" code pattern.
	MetadataInitSingleton MetadataInitializationKind = 1 // singleton
	// The type requires non-trivial singleton initialization using the "foreign" code pattern.
	MetadataInitForeign MetadataInitializationKind = 2 // foreign
	// We only have two bits here, so if you add a third special kind, include more flag bits in its out-of-line storage.
)

func (k MetadataInitializationKind) None() bool {
	return k == MetadataInitNone
}
func (k MetadataInitializationKind) Singleton() bool {
	return k == MetadataInitSingleton
}
func (k MetadataInitializationKind) Foreign() bool {
	return k == MetadataInitForeign
}

type TypeContextDescriptorFlags uint16

const (
	// All of these values are bit offsets or widths.
	// Generic flags build upwards from 0.
	// Type-specific flags build downwards from 15.

	/// Whether there's something unusual about how the metadata is
	/// initialized.
	///
	/// Meaningful for all type-descriptor kinds.
	MetadataInitialization       = 0
	MetadataInitialization_width = 2

	/// Set if the type has extended import information.
	///
	/// If true, a sequence of strings follow the null terminator in the
	/// descriptor, terminated by an empty string (i.e. by two null
	/// terminators in a row).  See TypeImportInfo for the details of
	/// these strings and the order in which they appear.
	///
	/// Meaningful for all type-descriptor kinds.
	HasImportInfo = 2

	/// Set if the type descriptor has a pointer to a list of canonical
	/// prespecializations.
	HasCanonicalMetadataPrespecializations = 3

	/// Set if the metadata contains a pointer to a layout string
	HasLayoutString = 4

	// Type-specific flags:

	/// Set if the class is an actor.
	///
	/// Only meaningful for class descriptors.
	Class_IsActor = 7

	/// Set if the class is a default actor class.  Note that this is
	/// based on the best knowledge available to the class; actor
	/// classes with resilient superclassess might be default actors
	/// without knowing it.
	///
	/// Only meaningful for class descriptors.
	Class_IsDefaultActor = 8

	/// The kind of reference that this class makes to its resilient superclass
	/// descriptor.  A TypeReferenceKind.
	///
	/// Only meaningful for class descriptors.
	Class_ResilientSuperclassReferenceKind       = 9
	Class_ResilientSuperclassReferenceKind_width = 3

	/// Whether the immediate class members in this metadata are allocated
	/// at negative offsets.  For now, we don't use this.
	Class_AreImmediateMembersNegative = 12

	/// Set if the context descriptor is for a class with resilient ancestry.
	///
	/// Only meaningful for class descriptors.
	Class_HasResilientSuperclass = 13

	/// Set if the context descriptor includes metadata for dynamically
	/// installing method overrides at metadata instantiation time.
	Class_HasOverrideTable = 14

	/// Set if the context descriptor includes metadata for dynamically
	/// constructing a class's vtables at metadata instantiation time.
	///
	/// Only meaningful for class descriptors.
	Class_HasVTable = 15
)

func (f TypeContextDescriptorFlags) MetadataInitialization() MetadataInitializationKind {
	return MetadataInitializationKind(types.ExtractBits(uint64(f), MetadataInitialization, MetadataInitialization_width))
}
func (f TypeContextDescriptorFlags) HasImportInfo() bool {
	return types.ExtractBits(uint64(f), HasImportInfo, 1) != 0
}
func (f TypeContextDescriptorFlags) HasCanonicalMetadataPrespecializations() bool {
	return types.ExtractBits(uint64(f), HasCanonicalMetadataPrespecializations, 1) != 0
}
func (f TypeContextDescriptorFlags) HasLayoutString() bool {
	return types.ExtractBits(uint64(f), HasLayoutString, 1) != 0
}
func (f TypeContextDescriptorFlags) IsActor() bool {
	return types.ExtractBits(uint64(f), Class_IsActor, 1) != 0
}
func (f TypeContextDescriptorFlags) IsDefaultActor() bool {
	return types.ExtractBits(uint64(f), Class_IsDefaultActor, 1) != 0
}
func (f TypeContextDescriptorFlags) ResilientSuperclassReferenceKind() TypeReferenceKind {
	return TypeReferenceKind(types.ExtractBits(uint64(f), Class_ResilientSuperclassReferenceKind, Class_ResilientSuperclassReferenceKind_width))
}
func (f TypeContextDescriptorFlags) AreImmediateMembersNegative() bool {
	return types.ExtractBits(uint64(f), Class_AreImmediateMembersNegative, 1) != 0
}
func (f TypeContextDescriptorFlags) HasResilientSuperclass() bool {
	return types.ExtractBits(uint64(f), Class_HasResilientSuperclass, 1) != 0
}
func (f TypeContextDescriptorFlags) HasOverrideTable() bool {
	return types.ExtractBits(uint64(f), Class_HasOverrideTable, 1) != 0
}
func (f TypeContextDescriptorFlags) HasVTable() bool {
	return types.ExtractBits(uint64(f), Class_HasVTable, 1) != 0
}
func (f TypeContextDescriptorFlags) String() string {
	var flags []string
	if !f.MetadataInitialization().None() {
		flags = append(flags, fmt.Sprintf("metadata_init:%s", f.MetadataInitialization()))
	}
	if f.HasImportInfo() {
		flags = append(flags, "import_info")
	}
	if f.HasCanonicalMetadataPrespecializations() {
		flags = append(flags, "canonical_metadata_prespecializations")
	}
	if f.HasLayoutString() {
		flags = append(flags, "layout_string")
	}
	if f.IsActor() {
		flags = append(flags, "actor")
	}
	if f.IsDefaultActor() {
		flags = append(flags, "default_actor")
	}
	if f.AreImmediateMembersNegative() {
		flags = append(flags, "negative_immediate_members")
	}
	if f.HasResilientSuperclass() {
		flags = append(flags, "resilient_superclass")
		flags = append(flags, fmt.Sprintf("resilient_superclass_ref:%s", f.ResilientSuperclassReferenceKind()))
	}
	if f.HasOverrideTable() {
		flags = append(flags, "override_table")
	}
	if f.HasVTable() {
		flags = append(flags, "vtable")
	}
	return strings.Join(flags, "|")
}

type ContextDescriptorFlags uint32

func (f ContextDescriptorFlags) Kind() ContextDescriptorKind {
	return ContextDescriptorKind(f & 0x1F)
}
func (f ContextDescriptorFlags) IsGeneric() bool {
	return (f & 0x80) != 0
}
func (f ContextDescriptorFlags) IsUnique() bool {
	return (f & 0x40) != 0
}
func (f ContextDescriptorFlags) Version() uint8 {
	return uint8(f >> 8 & 0xFF)
}
func (f ContextDescriptorFlags) KindSpecific() TypeContextDescriptorFlags {
	return TypeContextDescriptorFlags((f >> 16) & 0xFFFF)
}
func (f ContextDescriptorFlags) String() string {
	var kindFlags string
	if len(f.KindSpecific().String()) > 0 {
		if f.Kind() == CDKindProtocol {
			kindFlags = fmt.Sprintf(", proto_flags: %s", ProtocolContextDescriptorFlags(f.KindSpecific()))
		} else {
			kindFlags = fmt.Sprintf(", kind_flags: %s", f.KindSpecific())
		}
	}
	return fmt.Sprintf("kind: %-11s generic: %t, unique: %t, version: %d%s",
		f.Kind(),
		f.IsGeneric(),
		f.IsUnique(),
		f.Version(),
		kindFlags)
}

// TargetContextDescriptor base class for all context descriptors.
type TargetContextDescriptor struct {
	Flags        ContextDescriptorFlags // Flags describing the context, including its kind and format version.
	ParentOffset RelativeDirectPointer  // The parent context, or null if this is a top-level context.
}

func (cd TargetContextDescriptor) Size() int64 {
	return int64(binary.Size(cd.Flags) + binary.Size(cd.ParentOffset.RelOff))
}

func (cd *TargetContextDescriptor) Read(r io.Reader, addr uint64) error {
	cd.ParentOffset.Address = addr + uint64(binary.Size(uint32(0)))
	if err := binary.Read(r, binary.LittleEndian, &cd.Flags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &cd.ParentOffset.RelOff); err != nil {
		return err
	}
	return nil
}

// TargetTypeContextDescriptor object
type TargetTypeContextDescriptor struct {
	TargetContextDescriptor
	NameOffset        RelativeDirectPointer // The name of the type.
	AccessFunctionPtr RelativeDirectPointer // A pointer to the metadata access function for this type.
	FieldsOffset      RelativeDirectPointer // A pointer to the field descriptor for the type, if any.
}

func (tcd TargetTypeContextDescriptor) Size() int64 {
	return tcd.TargetContextDescriptor.Size() +
		int64(binary.Size(tcd.NameOffset.RelOff)) +
		int64(binary.Size(tcd.AccessFunctionPtr.RelOff)) +
		int64(binary.Size(tcd.FieldsOffset.RelOff))
}

func (tcd *TargetTypeContextDescriptor) Read(r io.Reader, addr uint64) error {
	if err := tcd.TargetContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	addr += uint64(tcd.TargetContextDescriptor.Size())
	tcd.NameOffset.Address = addr
	tcd.AccessFunctionPtr.Address = addr + uint64(unsafe.Sizeof(RelativeDirectPointer{}.RelOff))
	tcd.FieldsOffset.Address = addr + uint64(unsafe.Sizeof(RelativeDirectPointer{}.RelOff))*2
	if err := binary.Read(r, binary.LittleEndian, &tcd.NameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &tcd.AccessFunctionPtr.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &tcd.FieldsOffset.RelOff); err != nil {
		return err
	}
	return nil
}

type TargetMangledContextName struct {
	Name RelativeDirectPointer
}

func (m TargetMangledContextName) Size() int64 {
	return int64(binary.Size(m.Name.RelOff))
}
func (m *TargetMangledContextName) Read(r io.Reader, addr uint64) error {
	m.Name.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &m.Name.RelOff); err != nil {
		return err
	}
	return nil
}

type OpaqueType struct {
	TargetOpaqueTypeDescriptor
	GenericContext *GenericContext
	TypeArgs       []RelativeString
}

// TargetOpaqueTypeDescriptor the descriptor for an opaque type.
type TargetOpaqueTypeDescriptor struct {
	TargetContextDescriptor
}

func (otd TargetOpaqueTypeDescriptor) Size() int64 {
	return otd.TargetContextDescriptor.Size()
}

func (otd *TargetOpaqueTypeDescriptor) Read(r io.Reader, addr uint64) error {
	return otd.TargetContextDescriptor.Read(r, addr)
}

type GenericContext struct {
	TargetGenericContextDescriptorHeader
	Parameters   []GenericParamDescriptor
	Requirements []TargetGenericRequirementDescriptor
	TypePacks    []GenericPackShapeDescriptor
}

type TypeGenericContext struct {
	TargetTypeGenericContextDescriptorHeader
	GenericMetadataPattern *GenericMetadataPattern
	Parameters             []GenericParamDescriptor
	Requirements           []TargetGenericRequirement
	TypePacks              []GenericPackShapeDescriptor
}

type TargetTypeGenericContextDescriptorHeader struct {
	InstantiationCache          RelativeDirectPointer
	DefaultInstantiationPattern RelativeDirectPointer
	Base                        TargetGenericContextDescriptorHeader
}

func (h TargetTypeGenericContextDescriptorHeader) Size() int64 {
	return int64(
		binary.Size(h.InstantiationCache.RelOff) +
			binary.Size(h.DefaultInstantiationPattern.RelOff) +
			binary.Size(h.Base),
	)
}

func (h *TargetTypeGenericContextDescriptorHeader) Read(r io.Reader, addr uint64) error {
	h.InstantiationCache.Address = addr
	h.DefaultInstantiationPattern.Address = addr + uint64(binary.Size(h.InstantiationCache.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &h.InstantiationCache.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &h.DefaultInstantiationPattern.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Base); err != nil {
		return err
	}
	return nil
}

type GenericContextDescriptorFlags uint16

// HasTypePacks is whether this generic context has at least one type parameter
// pack, in which case the generic context will have a trailing
// GenericPackShapeHeader.
func (f GenericContextDescriptorFlags) HasTypePacks() bool {
	return (f & 0x01) != 0
}

// ref: include/swift/ABI/GenericContext.h
type TargetGenericContextDescriptorHeader struct {
	// The number of (source-written) generic parameters, and thus
	// the number of GenericParamDescriptors associated with this
	// context.  The parameter descriptors appear in the order in
	// which they were given in the source.
	//
	// A GenericParamDescriptor corresponds to a type metadata pointer
	// in the arguments layout when isKeyArgument() is true.
	// isKeyArgument() will be false if the parameter has been made
	// equivalent to a different parameter or a concrete type.
	NumParams uint16
	// The number of GenericRequirementDescriptors in this generic
	// signature.
	//
	// A GenericRequirementDescriptor of kind Protocol corresponds
	// to a witness table pointer in the arguments layout when
	// isKeyArgument() is true.  isKeyArgument() will be false if
	// the protocol is an Objective-C protocol.  (Unlike generic
	// parameters, redundant conformance requirements can simply be
	// eliminated, and so that case is not impossible.)
	NumRequirements uint16
	// The size of the "key" area of the argument layout, in words.
	// Key arguments include shape classes, generic parameters and
	// conformance requirements which are part of the identity of
	// the context.
	//
	// The key area of the argument layout consists of:
	//
	// - a sequence of pack lengths, in the same order as the parameter
	//   descriptors which satisfy getKind() == GenericParamKind::TypePack
	//   and hasKeyArgument();
	//
	// - a sequence of metadata or metadata pack pointers, in the same
	//   order as the parameter descriptors which satisfy hasKeyArgument();
	//
	// - a sequence of witness table or witness table pack pointers, in the
	//   same order as the requirement descriptors which satisfy
	//   hasKeyArgument().
	//
	// The elements above which are packs are precisely those appearing
	// in the sequence of trailing GenericPackShapeDescriptors.
	NumKeyArguments uint16
	// Originally this was the size of the "extra" area of the argument
	// layout, in words.  The idea was that extra arguments would
	// include generic parameters and conformances that are not part
	// of the identity of the context; however, it's unclear why we
	// would ever want such a thing.  As a result, in pre-5.8 runtimes
	// this field is always zero.  New flags can only be added as long
	// as they remains zero in code which must be compatible with
	// older Swift runtimes.
	Flags GenericContextDescriptorFlags
}

func (g TargetGenericContextDescriptorHeader) GetNumArguments() uint16 {
	return g.NumKeyArguments
}
func (g TargetGenericContextDescriptorHeader) HasArguments() bool {
	return g.GetNumArguments() > 0
}

type GenericParamKind uint8

const (
	// A type parameter.
	GPKType GenericParamKind = 0 // type
	// A type parameter pack.
	GPKTypePack GenericParamKind = 1    // type_pack
	GPKMax      GenericParamKind = 0x3F // max
)

// Don't set 0x40 for compatibility with pre-Swift 5.8 runtimes (4 byte align)
type GenericParamDescriptor uint8

func (g GenericParamDescriptor) HasKeyArgument() bool {
	return (g & 0x80) != 0
}
func (g GenericParamDescriptor) GetKind() GenericParamKind {
	return GenericParamKind(g & 0x3F)
}
func (g GenericParamDescriptor) String() string {
	return fmt.Sprintf("has_key_arg: %t, kind: %s", g.HasKeyArgument(), g.GetKind())
}

type GenericEnvironmentFlags uint32

func (f GenericEnvironmentFlags) GetNumGenericParameterLevels() uint32 {
	return uint32(f & 0xFFF)
}
func (f GenericEnvironmentFlags) GetNumGenericRequirements() uint32 {
	return uint32((f & (0xFFFF << 12)) >> 12)
}

type TargetGenericEnvironment struct {
	Flags GenericEnvironmentFlags
}

// TargetNonUniqueExtendedExistentialTypeShape a descriptor for an extended existential type descriptor which
// needs to be uniqued at runtime.
type TargetNonUniqueExtendedExistentialTypeShape struct {
	// A reference to memory that can be used to cache a globally-unique
	// descriptor for this existential shape.
	UniqueCache RelativeDirectPointer // TargetExtendedExistentialTypeShape
	// The local copy of the existential shape descriptor.
	LocalCopy TargetExtendedExistentialTypeShape // TargetExtendedExistentialTypeShape
}

func (t TargetNonUniqueExtendedExistentialTypeShape) Size() int64 {
	return int64(binary.Size(t.UniqueCache.RelOff)) + int64(binary.Size(t.LocalCopy))
}

func (t *TargetNonUniqueExtendedExistentialTypeShape) Read(r io.Reader, addr uint64) error {
	t.UniqueCache.Address = addr
	if err := binary.Read(r, binary.LittleEndian, &t.UniqueCache.RelOff); err != nil {
		return err
	}
	if err := t.LocalCopy.Read(r, addr+uint64(binary.Size(t.UniqueCache.RelOff))); err != nil {
		return err
	}
	return nil
}

type SpecialKind uint32

const (
	SKNone SpecialKind = 0 // none
	// The existential has a class constraint.
	// The inline storage is sizeof(void*) / alignof(void*),
	// the value is always stored inline, the value is reference-
	// counted (using unknown reference counting), and the
	// type metadata for the requirement generic parameters are
	// not stored in the existential container because they can
	// be recovered from the instance type of the class.
	SKClass SpecialKind = 1 // class
	// The existential has a metatype constraint.
	// The inline storage is sizeof(void*) / alignof(void*),
	// the value is always stored inline, the value is a Metadata*,
	// and the type metadata for the requirement generic parameters
	// are not stored in the existential container because they can
	// be recovered from the stored metatype.
	SKMetatype SpecialKind = 2 // metatype
	// The inline value storage has a non-storage layout.  The shape
	// must include a value witness table.  Type metadata for the
	// requirement generic parameters are still stored in the existential
	// container.
	SKExplicitLayout SpecialKind = 3 // explicit layout
	// 255 is the maximum
)

type ExtendedExistentialTypeShapeFlags uint32

const (
	SpecialKindMask            = 0x000000FF
	SpecialKindShift           = 0
	HasGeneralizationSignature = 0x00000100
	HasTypeExpression          = 0x00000200
	HasSuggestedValueWitnesses = 0x00000400
	HasImplicitReqSigParams    = 0x00000800
	HasImplicitGenSigParams    = 0x00001000
	HasTypePacks               = 0x00002000
)

func (f ExtendedExistentialTypeShapeFlags) GetSpecialKind() SpecialKind {
	return SpecialKind((f & SpecialKindMask) >> SpecialKindShift)
}
func (f ExtendedExistentialTypeShapeFlags) IsOpaque() bool {
	return f.GetSpecialKind() == SKNone
}
func (f ExtendedExistentialTypeShapeFlags) IsClassConstrained() bool {
	return f.GetSpecialKind() == SKClass
}
func (f ExtendedExistentialTypeShapeFlags) IsMetatypeConstrained() bool {
	return f.GetSpecialKind() == SKMetatype
}
func (f ExtendedExistentialTypeShapeFlags) HasGeneralizationSignature() bool {
	return (f & HasGeneralizationSignature) != 0
}
func (f ExtendedExistentialTypeShapeFlags) HasTypeExpression() bool {
	return (f & HasTypeExpression) != 0
}
func (f ExtendedExistentialTypeShapeFlags) HasSuggestedValueWitnesses() bool {
	return (f & HasSuggestedValueWitnesses) != 0
}

// The parameters of the requirement signature are not stored
// explicitly in the shape.
//
// In order to enable this, there must be no more than
// MaxNumImplicitGenericParamDescriptors generic parameters, and
// they must match GenericParamDescriptor::implicit().
func (f ExtendedExistentialTypeShapeFlags) HasImplicitReqSigParams() bool {
	return (f & HasImplicitReqSigParams) != 0
}

// The parameters of the generalization signature are not stored
// explicitly in the shape.
//
// In order to enable this, there must be no more than
// MaxNumImplicitGenericParamDescriptors generic parameters, and
// they must match GenericParamDescriptor::implicit().
func (f ExtendedExistentialTypeShapeFlags) HasImplicitGenSigParams() bool {
	return (f & HasImplicitGenSigParams) != 0
}

// Whether the generic context has type parameter packs. This
// occurs when the existential has a superclass requirement
// whose class declaration has a type parameter pack, eg
// `any P & C<...>` with `class C<each T> {}`.
func (f ExtendedExistentialTypeShapeFlags) HasTypePacks() bool {
	return (f & HasTypePacks) != 0
}
func (f ExtendedExistentialTypeShapeFlags) String() string {
	var out []string
	out = append(out, fmt.Sprintf("kind:%s", f.GetSpecialKind()))
	if f.IsOpaque() {
		out = append(out, "opaque")
	}
	if f.IsClassConstrained() {
		out = append(out, "class_constrained")
	}
	if f.IsMetatypeConstrained() {
		out = append(out, "metatype_constrained")
	}
	if f.HasGeneralizationSignature() {
		out = append(out, "has_generalization_signature")
	}
	if f.HasTypeExpression() {
		out = append(out, "has_type_expression")
	}
	if f.HasSuggestedValueWitnesses() {
		out = append(out, "has_suggested_value_witnesses")
	}
	if f.HasImplicitReqSigParams() {
		out = append(out, "has_implicit_req_sig_params")
	}
	if f.HasImplicitGenSigParams() {
		out = append(out, "has_implicit_gen_sig_params")
	}
	if f.HasTypePacks() {
		out = append(out, "has_type_packs")
	}
	return strings.Join(out, "|")
}

// TargetExtendedExistentialTypeShape a description of the shape of an existential type.
type TargetExtendedExistentialTypeShape struct {
	// Flags for the existential shape.
	Flags ExtendedExistentialTypeShapeFlags
	// The mangling of the generalized existential type, expressed
	// (if necessary) in terms of the type parameters of the
	// generalization signature.
	//
	// If this shape is non-unique, this is always a flat string, not a
	// "symbolic" mangling which can contain relative references.  This
	// allows uniquing to simply compare the string content.
	//
	// In principle, the content of the requirement signature and type
	// expression are derivable from this type.  We store them separately
	// so that code which only needs to work with the logical content of
	// the type doesn't have to break down the existential type string.
	// This both (1) allows those operations to work substantially more
	// efficiently (and without needing code to produce a requirement
	// signature from an existential type to exist in the runtime) and
	// (2) potentially allows old runtimes to support new existential
	// types without as much invasive code.
	//
	// The content of this string is *not* necessarily derivable from
	// the requirement signature.  This is because there may be multiple
	// existential types that have equivalent logical content but which
	// we nonetheless distinguish at compile time.  Storing this also
	// allows us to far more easily produce a formal type from this
	// shape reflectively.
	ExistentialType RelativeDirectPointer
	// The header describing the requirement signature of the existential.
	ReqSigHeader RelativeDirectPointer // TargetGenericContextDescriptorHeader
}

func (t TargetExtendedExistentialTypeShape) String() string {
	return fmt.Sprintf("flags:%s, existential_type:%#x, req_sig_header:%#x", t.Flags, t.ExistentialType.GetAddress(), t.ReqSigHeader.GetAddress())
}

func (t TargetExtendedExistentialTypeShape) Size() int64 {
	return int64(binary.Size(t.Flags)) +
		int64(binary.Size(t.ExistentialType.RelOff)) +
		int64(binary.Size(t.ReqSigHeader.RelOff))
}

func (t *TargetExtendedExistentialTypeShape) Read(r io.Reader, addr uint64) error {
	t.ExistentialType.Address = addr + uint64(binary.Size(t.Flags))
	t.ReqSigHeader.Address = addr + uint64(binary.Size(t.Flags)) + uint64(binary.Size(t.ExistentialType.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &t.Flags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &t.ExistentialType.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &t.ReqSigHeader.RelOff); err != nil {
		return err
	}
	return nil
}

type ValueWitnessTable struct {
	RelativeDirectPointer
	TargetValueWitnessTable
	EnumWitnessTable *TargetEnumValueWitnessTable
}

// TargetValueWitnessTable a value-witness table.  A value witness table is built around the
// requirements of some specific type.  The information in a value-witness table is intended
// to be sufficient to lay out and manipulate values of an arbitrary type.
type TargetValueWitnessTable struct {
	InitializeBufferWithCopyOfBufferFn uint64
	DestroyFn                          uint64
	InitializeWithCopyFn               uint64
	AssignWithCopyFn                   uint64
	InitializeWithTakeFn               uint64
	AssignWithTakeFn                   uint64
	GetEnumTagSinglePayloadFn          uint64
	StoreEnumTagSinglePayloadFn        uint64
	Size                               uint64 // the size of this type.  Unlike in C, this has not been padded up to the alignment; that value is maintained as 'stride'.
	Stride                             uint64 //  This is the size rounded up to be a multiple of the alignment.
	WitnessFlags                       TargetValueWitnessFlags
	ExtraInhabitantCount               uint32 // The number of extra inhabitants, that is, bit patterns that do not form valid values of the type, in this type's binary representation.
}

func (t *TargetValueWitnessTable) Fixup(fix func(uint64) uint64) {
	t.InitializeBufferWithCopyOfBufferFn = fix(t.InitializeBufferWithCopyOfBufferFn)
	t.DestroyFn = fix(t.DestroyFn)
	t.InitializeWithCopyFn = fix(t.InitializeWithCopyFn)
	t.AssignWithCopyFn = fix(t.AssignWithCopyFn)
	t.InitializeWithTakeFn = fix(t.InitializeWithTakeFn)
	t.AssignWithTakeFn = fix(t.AssignWithTakeFn)
	t.GetEnumTagSinglePayloadFn = fix(t.GetEnumTagSinglePayloadFn)
	t.StoreEnumTagSinglePayloadFn = fix(t.StoreEnumTagSinglePayloadFn)
}

func (t TargetValueWitnessTable) IsIncomplete() bool {
	return (t.WitnessFlags & Incomplete) != 0
}
func (t TargetValueWitnessTable) HasEnumWitnesses() bool {
	return (t.WitnessFlags & HasEnumWitnesses) != 0
}
func (t TargetValueWitnessTable) IsValueInline() bool {
	return (t.WitnessFlags & HasEnumWitnesses) != 0
}
func (t TargetValueWitnessTable) IsInlineStorage() bool {
	return (t.WitnessFlags & IsNonInline) != 1
}
func (t TargetValueWitnessTable) IsPOD() bool {
	return (t.WitnessFlags & IsNonPOD) != 1
}
func (t TargetValueWitnessTable) IsCopyable() bool {
	return (t.WitnessFlags & IsNonCopyable) != 1
}
func (t TargetValueWitnessTable) IsBitwiseTakable() bool {
	return (t.WitnessFlags & IsNonBitwiseTakable) != 0
}
func (t TargetValueWitnessTable) GetAlignment() uint32 {
	return uint32((t.WitnessFlags & AlignmentMask) + 1)
}
func (t TargetValueWitnessTable) Flags() string {
	return fmt.Sprintf("alignment:%d, is_pod:%t, is_inline_storage:%t, is_value_inline:%t, has_enum_witnesses:%t, is_incomplete:%t, is_bitwise_takable:%t, is_copyable:%t",
		t.GetAlignment(),
		t.IsPOD(),
		t.IsInlineStorage(),
		t.IsValueInline(),
		t.HasEnumWitnesses(),
		t.IsIncomplete(),
		t.IsBitwiseTakable(),
		t.IsCopyable(),
	)
}

// TargetValueWitnessFlags flags stored in the value-witness table.
type TargetValueWitnessFlags uint32

// The polarity of these bits is chosen so that, when doing struct layout, the
// flags of the field types can be mostly bitwise-or'ed together to derive the
// flags for the struct. (The "non-inline" and "has-extra-inhabitants" bits
// still require additional fixup.)
const (
	AlignmentMask TargetValueWitnessFlags = 0x000000FF
	// unused             0x0000FF00
	IsNonPOD    TargetValueWitnessFlags = 0x00010000
	IsNonInline TargetValueWitnessFlags = 0x00020000
	// unused             0x00040000
	HasSpareBits        TargetValueWitnessFlags = 0x00080000
	IsNonBitwiseTakable TargetValueWitnessFlags = 0x00100000
	HasEnumWitnesses    TargetValueWitnessFlags = 0x00200000
	Incomplete          TargetValueWitnessFlags = 0x00400000
	IsNonCopyable       TargetValueWitnessFlags = 0x00800000
	// unused             0xFF000000
	TVWFMaxNumExtraInhabitants = 0x7FFFFFFF
)

type TargetEnumValueWitnessTable struct {
	GetEnumTagFn                 uint64
	DestructiveProjectEnumDataFn uint64
	DestructiveInjectEnumTagFn   uint64
}

func (ew *TargetEnumValueWitnessTable) Fixup(fix func(uint64) uint64) {
	ew.GetEnumTagFn = fix(ew.GetEnumTagFn)
	ew.DestructiveProjectEnumDataFn = fix(ew.DestructiveProjectEnumDataFn)
	ew.DestructiveInjectEnumTagFn = fix(ew.DestructiveInjectEnumTagFn)
}

type GenericRequirementLayoutKind uint32

const (
	// A class constraint.
	GRLKClass GenericRequirementLayoutKind = 0 // class
)
