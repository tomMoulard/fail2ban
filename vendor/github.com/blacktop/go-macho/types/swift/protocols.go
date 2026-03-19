package swift

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types"
)

//go:generate stringer -type GenericRequirementKind,ProtocolRequirementKind,GenericPackKind,SpecialProtocol -linecomment -output protocols_string.go

// ConformanceDescriptor in __TEXT.__swift5_proto
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol conformance descriptor in the __TEXT.__const section.

// Protocol swift protocol object
type Protocol struct {
	TargetProtocolDescriptor
	Address               uint64
	Name                  string
	Parent                *TargetModuleContext
	AssociatedTypes       []string
	SignatureRequirements []TargetGenericRequirement
	Requirements          []TargetProtocolRequirement
}

func (p Protocol) String() string {
	return p.dump(false)
}
func (p Protocol) Verbose() string {
	return p.dump(true)
}
func (p Protocol) dump(verbose bool) string {
	var addr string
	var sigReqs string
	if len(p.SignatureRequirements) > 0 {
		sigReqs = "  /* signature requirements */\n"
		for _, req := range p.SignatureRequirements {
			sigReqs += fmt.Sprintf("    %s: %s // %s\n", req.Param, req.Kind, req.Flags)
		}
	}
	var reqs string
	var atyps string
	if len(p.Requirements) > 0 {
		var raddr string
		reqs = "  /* requirements */\n"
		for _, req := range p.Requirements {
			var static string
			if !req.Flags.IsInstance() {
				static = "static "
			}
			var sym string
			switch req.Flags.Kind() {
			case PRKindMethod, PRKindInit, PRKindGetter, PRKindSetter, PRKindReadCoroutine, PRKindModifyCoroutine:
				if req.DefaultImplementation.IsSet() {
					sym = fmt.Sprintf("%sfunc sub_%x // %s", static, req.DefaultImplementation.GetAddress(), req.Flags)
				} else {
					sym = fmt.Sprintf("// <stripped> %sfunc %s", static, req.Flags.Verbose())
				}
			default:
				if req.DefaultImplementation.IsSet() {
					sym = fmt.Sprintf("%s // %s", req.Flags.Kind(), req.Flags.Verbose())
				} else {
					sym = fmt.Sprintf("// <stripped> %s", req.Flags.Verbose())
				}
			}
			if verbose && req.DefaultImplementation.IsSet() {
				raddr = fmt.Sprintf("/* %#x */ ", req.DefaultImplementation.GetAddress())
			}
			reqs += fmt.Sprintf("    %s%s\n", raddr, sym)
		}
	}
	if verbose {
		addr = fmt.Sprintf("// %#x\n", p.Address)
	}
	var parent string
	if p.Parent != nil && len(p.Parent.Name) > 0 {
		parent = p.Parent.Name + "."
	}
	if len(p.AssociatedTypes) > 0 {
		atyps = ": " + strings.Join(p.AssociatedTypes, ", ")
	}
	if sigReqs == "" && reqs == "" {
		return fmt.Sprintf("%sprotocol %s%s%s {}", addr, parent, p.Name, atyps)
	}
	return fmt.Sprintf(
		"%s"+
			"protocol %s%s%s {\n%s%s}",
		addr,
		parent,
		p.Name,
		atyps,
		sigReqs,
		reqs,
	)
}

// TargetProtocolDescriptor
// ref: include/swift/ABI/MetadataValues.h
type TargetProtocolDescriptor struct {
	TargetContextDescriptor
	NameOffset                 RelativeDirectPointer // The name of the protocol.
	NumRequirementsInSignature uint32                // The number of generic requirements in the requirement signature of the protocol.
	NumRequirements            uint32                /* The number of requirements in the protocol. If any requirements beyond MinimumWitnessTableSizeInWords are present
	 * in the witness table template, they will be not be overwritten with defaults. */
	AssociatedTypeNamesOffset RelativeDirectPointer // Associated type names, as a space-separated list in the same order as the requirements.
}

func (d TargetProtocolDescriptor) Size() int64 {
	return int64(
		int(d.TargetContextDescriptor.Size()) +
			binary.Size(d.NameOffset.RelOff) +
			binary.Size(d.NumRequirementsInSignature) +
			binary.Size(d.NumRequirements) +
			binary.Size(d.AssociatedTypeNamesOffset.RelOff))
}

func (d *TargetProtocolDescriptor) Read(r io.Reader, addr uint64) error {
	if err := d.TargetContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	d.NameOffset.Address = addr + uint64(d.TargetContextDescriptor.Size())
	d.AssociatedTypeNamesOffset.Address = addr +
		uint64(d.TargetContextDescriptor.Size()) +
		uint64(binary.Size(d.NameOffset.RelOff)+
			binary.Size(d.NumRequirementsInSignature)+
			binary.Size(d.NumRequirements))
	if err := binary.Read(r, binary.LittleEndian, &d.NameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.NumRequirementsInSignature); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.NumRequirements); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.AssociatedTypeNamesOffset.RelOff); err != nil {
		return err
	}
	return nil
}

// / Identifiers for protocols with special meaning to the Swift runtime.
type SpecialProtocol uint8

const (
	/// Not a special protocol.
	///
	/// This must be 0 for ABI compatibility with Objective-C protocol_t records.
	None SpecialProtocol = 0 // none
	/// The Error protocol.
	Error SpecialProtocol = 1 // error
)

// ProtocolContextDescriptorFlags flags for protocol context descriptors.
// These values are used as the kindSpecificFlags of the ContextDescriptorFlags for the protocol.
type ProtocolContextDescriptorFlags uint16

const (
	/// Whether this protocol is class-constrained.
	HasClassConstraint       = 0
	HasClassConstraint_width = 1
	/// Whether this protocol is resilient.
	IsResilient = 1
	/// Special protocol value.
	SpecialProtocolKind       = 2
	SpecialProtocolKind_width = 6
)

func (f ProtocolContextDescriptorFlags) IsClassConstrained() bool {
	return types.ExtractBits(uint64(f), HasClassConstraint, HasClassConstraint_width) != 0
}
func (f ProtocolContextDescriptorFlags) IsResilient() bool {
	return types.ExtractBits(uint64(f), IsResilient, 1) != 0
}
func (f ProtocolContextDescriptorFlags) SpecialProtocol() SpecialProtocol {
	return SpecialProtocol(types.ExtractBits(uint64(f), SpecialProtocolKind, SpecialProtocolKind_width))
}
func (f ProtocolContextDescriptorFlags) String() string {
	var flags []string
	if f.IsClassConstrained() {
		flags = append(flags, "class_constrained")
	}
	if f.IsResilient() {
		flags = append(flags, "resilient")
	}
	if f.SpecialProtocol() != None {
		flags = append(flags, fmt.Sprintf("special_protocol: %s", f.SpecialProtocol()))
	}
	if len(flags) == 0 {
		return "none"
	}
	return strings.Join(flags, "|")
}

type GenericRequirementKind uint8

const (
	// A protocol requirement.
	GRKindProtocol GenericRequirementKind = 0 // protocol
	// A same-type requirement.
	GRKindSameType GenericRequirementKind = 1 // same-type
	// A base class requirement.
	GRKindBaseClass GenericRequirementKind = 2 // base-class
	// A "same-conformance" requirement, implied by a same-type or base-class constraint that binds a parameter with protocol requirements.
	GRKindSameConformance GenericRequirementKind = 3 // same-conformance
	// A same-shape requirement between generic parameter packs.
	GRKSameShape GenericRequirementKind = 4 // same-shape
	// A layout requirement.
	GRKindLayout GenericRequirementKind = 0x1F // layout
)

type GenericRequirementFlags uint32

func (f GenericRequirementFlags) HasKeyArgument() bool {
	return (f & 0x80) != 0
}
func (f GenericRequirementFlags) HasExtraArgument() bool {
	return (f & 0x40) != 0
}
func (f GenericRequirementFlags) Kind() GenericRequirementKind {
	return GenericRequirementKind(f & 0x1F)
}
func (f GenericRequirementFlags) String() string {
	return fmt.Sprintf("key_arg: %t, extra_arg: %t, kind: %s", f.HasKeyArgument(), f.HasExtraArgument(), f.Kind())
}

type TargetGenericRequirement struct {
	TargetGenericRequirementDescriptor
	Param string
	Kind  string
}

// ref: swift/ABI/Metadata.h - TargetGenericRequirementDescriptor
type TargetGenericRequirementDescriptor struct {
	Flags                                  GenericRequirementFlags
	ParamOff                               RelativeDirectPointer       // The type that's constrained, described as a mangled name.
	TypeOrProtocolOrConformanceOrLayoutOff RelativeIndirectablePointer // UNION: flags determine type
}

func (d TargetGenericRequirementDescriptor) Size() int64 {
	return int64(binary.Size(d.Flags) + binary.Size(d.ParamOff.RelOff) + binary.Size(d.TypeOrProtocolOrConformanceOrLayoutOff.RelOff))
}

func (d *TargetGenericRequirementDescriptor) Read(r io.Reader, addr uint64) error {
	d.ParamOff.Address = addr + uint64(binary.Size(d.Flags))
	d.TypeOrProtocolOrConformanceOrLayoutOff.Address = addr + uint64(binary.Size(d.Flags)) + uint64(binary.Size(d.ParamOff.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &d.Flags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.ParamOff.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.TypeOrProtocolOrConformanceOrLayoutOff.RelOff); err != nil {
		return err
	}
	return nil
}

// GenericPackShapeHeader object
// ref: swift/ABI/GenericContext.h - GenericPackShapeHeader
type GenericPackShapeHeader struct {
	NumPacks        uint16 // The number of generic parameters and conformance requirements which are packs.
	NumShapeClasses uint16 // The number of equivalence classes in the same-shape relation.
}

type GenericPackKind uint16

const (
	GPKMetadata     GenericPackKind = 0 // metadata
	GPKWitnessTable GenericPackKind = 1 // witness-table
)

// GenericPackShapeDescriptor the GenericPackShapeHeader is followed by an array of these descriptors,
// whose length is given by the header's NumPacks field.
//
// The invariant is that all pack descriptors with GenericPackKind::Metadata
// must precede those with GenericPackKind::WitnessTable, and for each kind,
// the pack descriptors are ordered by their Index.
//
// This allows us to iterate over the generic arguments array in parallel
// with the array of pack shape descriptors. We know we have a metadata
// or witness table when we reach the generic argument whose index is
// stored in the next descriptor; we increment the descriptor pointer in this case.
//
// ref: swift/ABI/GenericContext.h - GenericPackShapeDescriptor
type GenericPackShapeDescriptor struct {
	Kind       GenericPackKind
	Index      uint16 // The index of this metadata pack or witness table pack in the generic arguments array.
	ShapeClass uint16 // The equivalence class of this pack under the same-shape relation.
	_          uint16 // Unused
}

const (
	// Bit used to indicate that an associated type witness is a pointer to a mangled name (vs. a pointer to metadata).
	AssociatedTypeMangledNameBit uint32 = 0x01
	// Prefix byte used to identify an associated type whose mangled name is relative to the protocol's context rather than the conforming type's context.
	AssociatedTypeInProtocolContextByte uint8 = 0xFF
)

type ProtocolRequirementKind uint8

const (
	PRKindBaseProtocol                        ProtocolRequirementKind = iota // base protocol
	PRKindMethod                                                             // method
	PRKindInit                                                               // initializer
	PRKindGetter                                                             // getter
	PRKindSetter                                                             // setter
	PRKindReadCoroutine                                                      // read coroutine
	PRKindModifyCoroutine                                                    // modify coroutine
	PRKindAssociatedTypeAccessFunction                                       // associated type access function
	PRKindAssociatedConformanceAccessFunction                                // associated conformance access function
)

type ProtocolRequirementFlags uint32

func (f ProtocolRequirementFlags) Kind() ProtocolRequirementKind {
	return ProtocolRequirementKind(f & 0x0F)
}
func (f ProtocolRequirementFlags) IsInstance() bool {
	return (f & 0x10) != 0
}
func (f ProtocolRequirementFlags) IsAsync() bool {
	return (f & 0x20) != 0
}
func (f ProtocolRequirementFlags) IsSignedWithAddress() bool {
	return f.Kind() != PRKindBaseProtocol
}
func (f ProtocolRequirementFlags) ExtraDiscriminator() uint16 {
	return uint16(f >> 16)
}
func (f ProtocolRequirementFlags) IsFunctionImpl() bool {
	switch f.Kind() {
	case PRKindMethod, PRKindInit, PRKindGetter, PRKindSetter, PRKindReadCoroutine, PRKindModifyCoroutine:
		return !f.IsAsync()
	default:
		return false
	}
}
func (f ProtocolRequirementFlags) String() string {
	var flags []string
	if f.IsAsync() {
		flags = append(flags, "async")
	}
	if f.IsFunctionImpl() {
		flags = append(flags, "func_impl")
	}
	var extra string
	if f.IsSignedWithAddress() && f.ExtraDiscriminator() != 0 {
		extra = fmt.Sprintf("__ptrauth(%04x)", f.ExtraDiscriminator())
	}
	if len(flags) == 0 {
		return extra
	}
	return fmt.Sprintf("%s (%s)", extra, strings.Join(flags, "|"))
}
func (f ProtocolRequirementFlags) Verbose() string {
	var flags []string
	if f.IsInstance() {
		flags = append(flags, "instance")
	}
	if f.IsAsync() {
		flags = append(flags, "async")
	}
	if f.IsFunctionImpl() {
		flags = append(flags, "func_impl")
	}
	var extra string
	if f.IsSignedWithAddress() && f.ExtraDiscriminator() != 0 {
		extra = fmt.Sprintf(" __ptrauth(%04x)", f.ExtraDiscriminator())
	}
	if len(flags) == 0 {
		return fmt.Sprintf("%s%s", f.Kind(), extra)
	}
	return fmt.Sprintf("%s%s (%s)", f.Kind(), extra, strings.Join(flags, "|"))
}

// TargetProtocolRequirement protocol requirement descriptor. This describes a single protocol requirement in a protocol descriptor.
// The index of the requirement in the descriptor determines the offset of the witness in a witness table for this protocol.
// ref: swift/ABI/Metadata.h - TargetProtocolRequirement
type TargetProtocolRequirement struct {
	Flags                 ProtocolRequirementFlags
	DefaultImplementation RelativeDirectPointer // The optional default implementation of the protocol.
}

func (pr TargetProtocolRequirement) Size() int64 {
	return int64(binary.Size(pr.Flags) + binary.Size(pr.DefaultImplementation.RelOff))
}

func (pr *TargetProtocolRequirement) Read(r io.Reader, addr uint64) error {
	pr.DefaultImplementation.Address = addr + uint64(binary.Size(pr.Flags))
	if err := binary.Read(r, binary.LittleEndian, &pr.Flags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &pr.DefaultImplementation.RelOff); err != nil {
		return err
	}
	return nil
}

// Descriptor in __TEXT.__swift5_protos
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol descriptor in the __TEXT.__const section.

type ConformanceDescriptor struct {
	TargetProtocolConformanceDescriptor
	Address                 uint64
	Protocol                string
	TypeRef                 *Type
	Retroactive             *RelativeString // context of a retroactive conformance
	ConditionalRequirements []TargetGenericRequirement
	ConditionalPackShapes   []GenericPackShapeDescriptor
	ResilientWitnesses      []ResilientWitnesses
	GenericWitnessTable     *TargetGenericWitnessTable
	WitnessTablePattern     *PCDWitnessTable
}

func (c ConformanceDescriptor) String() string {
	return c.dump(false)
}
func (c ConformanceDescriptor) Verbose() string {
	return c.dump(true)
}
func (c ConformanceDescriptor) dump(verbose bool) string {
	var addr string
	var retroactive string
	if c.Flags.IsRetroactive() {
		retroactive = fmt.Sprintf(": %s", c.Retroactive.Name)
	}
	var reqs string
	if len(c.ConditionalRequirements) > 0 {
		reqs = "  /* conditional requirements */\n"
		var conds []string
		for _, req := range c.ConditionalRequirements {
			conds = append(conds, fmt.Sprintf("%s: %s", req.Param, req.Kind))
		}
		reqs += fmt.Sprintf("   < where %s >", strings.Join(conds, ", "))
	}
	var packShapes string
	if len(c.ConditionalPackShapes) > 0 {
		if reqs != "" {
			packShapes = "\n"
		}
		packShapes += "  /* conditional pack shapes */\n"
		for _, shape := range c.ConditionalPackShapes {
			packShapes += fmt.Sprintf("    %s: %d\n", shape.Kind, shape.ShapeClass)
		}
	}
	var resilientWitnesses string
	if len(c.ResilientWitnesses) > 0 {
		var raddr string
		if reqs != "" || packShapes != "" {
			resilientWitnesses = "\n"
		}
		resilientWitnesses += "  /* resilient witnesses */\n"
		for _, witness := range c.ResilientWitnesses {
			var static string
			if !witness.Requirement.Flags.IsInstance() {
				static = "static "
			}
			sym := witness.Symbol
			switch witness.Requirement.Flags.Kind() {
			case PRKindMethod, PRKindInit, PRKindGetter, PRKindSetter, PRKindReadCoroutine, PRKindModifyCoroutine:
				if witness.ImplOff.IsSet() {
					if sym == "" {
						sym = fmt.Sprintf("%sfunc sub_%x // %s", static, witness.ImplOff.GetAddress(), witness.Requirement.Flags.Verbose())
					}
				} else {
					sym = fmt.Sprintf("// <stripped> %sfunc %s", static, witness.Requirement.Flags.Verbose())
				}
			default:
				if witness.ImplOff.IsSet() {
					if sym == "" {
						sym = fmt.Sprintf("%s // %s", witness.Requirement.Flags.Kind(), witness.Requirement.Flags.Verbose())
					}
				} else {
					sym = fmt.Sprintf("// <stripped> %s", witness.Requirement.Flags.Verbose())
				}
			}
			if verbose && witness.ImplOff.IsSet() {
				raddr = fmt.Sprintf("/* %#x */ ", witness.ImplOff.GetAddress())
			}
			resilientWitnesses += fmt.Sprintf("    %s%s\n", raddr, sym)
		}
	}
	var witnessTablePattern string
	if verbose && c.WitnessTablePatternOffsest.IsSet() {
		if reqs != "" || packShapes != "" || resilientWitnesses != "" {
			witnessTablePattern = "\n"
		}
		witnessTablePattern += "  /* witness table pattern */\n"
		witnessTablePattern += fmt.Sprintf("    /* %#x */\n", c.WitnessTablePatternOffsest.GetAddress())
	}
	if verbose {
		addr = fmt.Sprintf("// %#x\n", c.Address)
	}
	var parent string
	if c.TypeRef.Parent != nil && len(c.TypeRef.Parent.Name) > 0 {
		parent = c.TypeRef.Parent.Name + "."
	}
	return fmt.Sprintf(
		"%s"+
			"protocol conformance %s%s : %s%s {\n"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"}",
		addr,
		parent,
		c.TypeRef.Name,
		c.Protocol,
		retroactive,
		reqs,
		packShapes,
		resilientWitnesses,
		witnessTablePattern,
	)
}

// TargetProtocolConformanceDescriptor the structure of a protocol conformance.
type TargetProtocolConformanceDescriptor struct {
	ProtocolOffsest            RelativeIndirectablePointer // The protocol being conformed to.
	TypeRefOffsest             RelativeIndirectablePointer // Some description of the type that conforms to the protocol.
	WitnessTablePatternOffsest RelativeDirectPointer       // The witness table pattern, which may also serve as the witness table.
	Flags                      ConformanceFlags            // Various flags, including the kind of conformance.
}

func (d TargetProtocolConformanceDescriptor) Size() int64 {
	return int64(
		binary.Size(d.ProtocolOffsest.RelOff) +
			binary.Size(d.TypeRefOffsest.RelOff) +
			binary.Size(d.WitnessTablePatternOffsest.RelOff) +
			binary.Size(d.Flags))
}

func (d *TargetProtocolConformanceDescriptor) Read(r io.Reader, addr uint64) error {
	d.ProtocolOffsest.Address = addr
	d.TypeRefOffsest.Address = addr + uint64(binary.Size(d.ProtocolOffsest.RelOff))
	d.WitnessTablePatternOffsest.Address = addr + uint64(binary.Size(d.ProtocolOffsest.RelOff))*2
	if err := binary.Read(r, binary.LittleEndian, &d.ProtocolOffsest.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.TypeRefOffsest.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.WitnessTablePatternOffsest.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.Flags); err != nil {
		return err
	}
	return nil
}

type PCDWitnessTable struct {
	Address uint64
	Name    string
}

type ConformanceFlags uint32

const (
	UnusedLowBits ConformanceFlags = 0x07 // historical conformance kind

	TypeMetadataKindMask  ConformanceFlags = 0x7 << 3 // 8 type reference kinds
	TypeMetadataKindShift                  = 3

	IsRetroactiveMask          ConformanceFlags = 0x01 << 6
	IsSynthesizedNonUniqueMask ConformanceFlags = 0x01 << 7

	NumConditionalRequirementsMask  ConformanceFlags = 0xFF << 8
	NumConditionalRequirementsShift                  = 8

	HasResilientWitnessesMask  ConformanceFlags = 0x01 << 16
	HasGenericWitnessTableMask ConformanceFlags = 0x01 << 17

	NumConditionalPackDescriptorsMask  ConformanceFlags = 0xFF << 24
	NumConditionalPackDescriptorsShift                  = 24
)

// IsRetroactive Is the conformance "retroactive"?
//
// A conformance is retroactive when it occurs in a module that is
// neither the module in which the protocol is defined nor the module
// in which the conforming type is defined. With retroactive conformance,
// it is possible to detect a conflict at run time.
func (f ConformanceFlags) IsRetroactive() bool {
	return (f & IsRetroactiveMask) != 0
}

// IsSynthesizedNonUnique is the conformance synthesized in a non-unique manner?
//
// The Swift compiler will synthesize conformances on behalf of some
// imported entities (e.g., C typedefs with the swift_wrapper attribute).
// Such conformances are retroactive by nature, but the presence of multiple
// such conformances is not a conflict because all synthesized conformances
// will be equivalent.
func (f ConformanceFlags) IsSynthesizedNonUnique() bool {
	return (f & IsSynthesizedNonUniqueMask) != 0
}

// GetNumConditionalRequirements retrieve the # of conditional requirements.
func (f ConformanceFlags) GetNumConditionalRequirements() int {
	return int((f & NumConditionalRequirementsMask) >> NumConditionalRequirementsShift)
}

// HasResilientWitnesses whether this conformance has any resilient witnesses.
func (f ConformanceFlags) HasResilientWitnesses() bool {
	return (f & HasResilientWitnessesMask) != 0
}

// HasGenericWitnessTable whether this conformance has a generic witness table that may need to
// be instantiated.
func (f ConformanceFlags) HasGenericWitnessTable() bool {
	return (f & HasGenericWitnessTableMask) != 0
}

// NumConditionalPackShapeDescriptors retrieve the # of conditional pack shape descriptors.
func (f ConformanceFlags) NumConditionalPackShapeDescriptors() int {
	return int((f & NumConditionalPackDescriptorsMask) >> NumConditionalPackDescriptorsShift)
}

// GetTypeReferenceKind retrieve the type reference kind kind.
func (f ConformanceFlags) GetTypeReferenceKind() TypeReferenceKind {
	return TypeReferenceKind((f & TypeMetadataKindMask) >> TypeMetadataKindShift)
}

func (f ConformanceFlags) String() string {
	return fmt.Sprintf("retroactive: %t, synthesized_nonunique: %t, num_cond_reqs: %d, has_resilient_witnesses: %t, has_generic_witness_table: %t, num_cond_pack_shape_desc: %d, type_reference_kind: %s",
		f.IsRetroactive(),
		f.IsSynthesizedNonUnique(),
		f.GetNumConditionalRequirements(),
		f.HasResilientWitnesses(),
		f.HasGenericWitnessTable(),
		f.NumConditionalPackShapeDescriptors(),
		f.GetTypeReferenceKind(),
	)
}

// A witness table for a protocol.
//
// With the exception of the initial protocol conformance descriptor,
// the layout of a witness table is dependent on the protocol being
// represented.
type TargetWitnessTable struct {
	/// The protocol conformance descriptor from which this witness table
	/// was generated.
	Description int32
}

type ResilientWitnesses struct {
	TargetResilientWitness
	Symbol      string
	Requirement TargetProtocolRequirement
}

// TargetProtocolRecord the structure of a protocol reference record.
// ref: swift/ABI/Metadata.h
type TargetProtocolRecord struct {
	Protocol int32 // The protocol referenced (the remaining low bit is reserved for future use)
}

// TargetResilientWitnessesHeader a header containing information about the resilient witnesses in a protocol conformance descriptor.
// ref: swift/ABI/Metadata.h - TargetResilientWitnessesHeader
type TargetResilientWitnessesHeader struct {
	NumWitnesses uint32
}

// TargetResilientWitness object
// ref: swift/ABI/Metadata.h - TargetResilientWitness
type TargetResilientWitness struct {
	RequirementOff RelativeIndirectablePointer
	ImplOff        RelativeDirectPointer
}

func (rw TargetResilientWitness) Size() int64 {
	return int64(binary.Size(rw.RequirementOff.RelOff) + binary.Size(rw.ImplOff.RelOff))
}

func (rw *TargetResilientWitness) Read(r io.Reader, addr uint64) error {
	rw.RequirementOff.Address = addr
	rw.ImplOff.Address = addr + uint64(binary.Size(rw.RequirementOff.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &rw.RequirementOff.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &rw.ImplOff.RelOff); err != nil {
		return err
	}
	return nil
}

// TargetGenericWitnessTable object
// ref: swift/ABI/Metadata.h - TargetGenericWitnessTable
type TargetGenericWitnessTable struct {
	WitnessTableSizeInWords                                uint16
	WitnessTablePrivateSizeInWordsAndRequiresInstantiation uint16
	Instantiator                                           int32
	PrivateData                                            int32
}
