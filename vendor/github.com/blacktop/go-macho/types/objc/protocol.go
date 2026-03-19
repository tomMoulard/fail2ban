package objc

import (
	"fmt"
	"log/slog"
	"strings"
	"unsafe"
)

const (
	// Values for protocol_t->flags
	PROTOCOL_FIXED_UP_2   = (1 << 31) // must never be set by compiler
	PROTOCOL_FIXED_UP_1   = (1 << 30) // must never be set by compiler
	PROTOCOL_IS_CANONICAL = (1 << 29) // must never be set by compiler
	// Bits 0..15 are reserved for Swift's use.
	PROTOCOL_FIXED_UP_MASK = (PROTOCOL_FIXED_UP_1 | PROTOCOL_FIXED_UP_2)
)

type ProtocolList struct {
	Count     uint64
	Protocols []uint64
}

type ProtocolT struct {
	IsaVMAddr                     uint64
	NameVMAddr                    uint64
	ProtocolsVMAddr               uint64
	InstanceMethodsVMAddr         uint64
	ClassMethodsVMAddr            uint64
	OptionalInstanceMethodsVMAddr uint64
	OptionalClassMethodsVMAddr    uint64
	InstancePropertiesVMAddr      uint64
	Size                          uint32
	Flags                         uint32
	// Fields below this point are not always present on disk.
	ExtendedMethodTypesVMAddr uint64
	DemangledNameVMAddr       uint64
	ClassPropertiesVMAddr     uint64
}

type Protocol struct {
	Name                    string
	Ptr                     uint64
	Isa                     *Class
	Prots                   []Protocol
	InstanceMethods         []Method
	InstanceProperties      []Property
	ClassProperties         []Property
	ClassMethods            []Method
	OptionalInstanceMethods []Method
	OptionalClassMethods    []Method
	ExtendedMethodTypes     string
	DemangledName           string
	ProtocolT
}

func (p *Protocol) dump(verbose, addrs bool) string {
	var props string
	var cProps string
	var optProps string
	var cMethods string
	var iMethods string
	var optMethods string

	protocol := fmt.Sprintf("@protocol %s", p.Name)
	if len(p.Prots) > 0 {
		var subProts []string
		for _, prot := range p.Prots {
			subProts = append(subProts, prot.Name)
		}
		protocol += fmt.Sprintf(" <%s>", strings.Join(subProts, ", "))
	}
	if addrs {
		protocol += fmt.Sprintf(" // %#x", p.Ptr)
	}
	if len(p.InstanceProperties) > 0 {
		for _, prop := range p.InstanceProperties {
			if verbose {
				if attrs, optional := prop.Attributes(); !optional {
					props += fmt.Sprintf("@property %s%s%s;\n", attrs, prop.Type(), prop.Name)
				}
			} else {
				props += fmt.Sprintf("@property (%s) %s;\n", prop.EncodedAttributes, prop.Name)
			}
		}
		if props != "" {
			props += "\n"
		}
	}
	if len(p.ClassProperties) > 0 {
		for _, prop := range p.ClassProperties {
			if verbose {
				if attrs, optional := prop.Attributes(); !optional {
					// Ensure "class" appears in the attribute list and retain trailing space
					if attrs == "" {
						attrs = "(class) "
					} else {
						inner := strings.TrimSuffix(strings.TrimPrefix(attrs, "("), ") ")
						if inner == attrs { // fallback if format differs
							inner = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(attrs, "("), ")"))
						}
						attrs = fmt.Sprintf("(class, %s) ", inner)
					}
					cProps += fmt.Sprintf("@property %s%s%s;\n", attrs, prop.Type(), prop.Name)
				}
			} else {
				if prop.EncodedAttributes != "" {
					cProps += fmt.Sprintf("@property (class, %s) %s;\n", prop.EncodedAttributes, prop.Name)
				} else {
					cProps += fmt.Sprintf("@property (class) %s;\n", prop.Name)
				}
			}
		}
		if cProps != "" {
			cProps += "\n"
		}
	}
	if len(p.ClassMethods) > 0 {
		for _, meth := range p.ClassMethods {
			if verbose {
				if meth.Types == "" {
					slog.Warn("protocol class method has empty type encoding", "method", meth.Name, "protocol", p.Name, "typesVMAddr", meth.TypesVMAddr)
					continue
				}
				rtype, args := decodeMethodTypes(meth.Types)
				cMethods += fmt.Sprintf("+ %s\n", getMethodWithArgs(meth.Name, rtype, args))
			} else {
				cMethods += fmt.Sprintf("+[%s %s];\n", p.Name, meth.Name)
			}
		}
		if cMethods != "" {
			cMethods = "/* class methods */\n" + cMethods + "\n"
		}
	}
	if len(p.InstanceMethods) > 0 {
		for _, meth := range p.InstanceMethods {
			if verbose {
				if meth.Types == "" {
					slog.Warn("protocol instance method has empty type encoding", "method", meth.Name, "protocol", p.Name, "typesVMAddr", meth.TypesVMAddr)
					continue
				}
				rtype, args := decodeMethodTypes(meth.Types)
				iMethods += fmt.Sprintf("- %s\n", getMethodWithArgs(meth.Name, rtype, args))
			} else {
				iMethods += fmt.Sprintf("-[%s %s];\n", p.Name, meth.Name)
			}
		}
		if iMethods != "" {
			iMethods = "/* required instance methods */\n" + iMethods + "\n"
		}
	}
	if len(p.InstanceProperties) > 0 {
		for _, prop := range p.InstanceProperties {
			if verbose {
				if attrs, optional := prop.Attributes(); optional {
					optProps += fmt.Sprintf("@property %s%s%s;\n", attrs, prop.Type(), prop.Name)
				}
			} else {
				// optProps += fmt.Sprintf("@property (%s) %s;\n", prop.EncodedAttributes, prop.Name)
			}
		}
		if optProps != "" {
			optProps += "\n"
		}
	}
	if len(p.ClassProperties) > 0 {
		for _, prop := range p.ClassProperties {
			if verbose {
				if attrs, optional := prop.Attributes(); optional {
					if attrs == "" {
						attrs = "(class) "
					} else {
						inner := strings.TrimSuffix(strings.TrimPrefix(attrs, "("), ") ")
						if inner == attrs {
							inner = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(attrs, "("), ")"))
						}
						attrs = fmt.Sprintf("(class, %s) ", inner)
					}
					optProps += fmt.Sprintf("@property %s%s%s;\n", attrs, prop.Type(), prop.Name)
				}
			} else {
				// optProps += fmt.Sprintf("@property (%s) %s;\n", prop.EncodedAttributes, prop.Name)
			}
		}
		if optProps != "" {
			// leave trailing newline managed above
		}
	}
	if len(p.OptionalInstanceMethods) > 0 {
		for _, meth := range p.OptionalInstanceMethods {
			if verbose {
				if meth.Types == "" {
					slog.Warn("protocol optional instance method has empty type encoding", "method", meth.Name, "protocol", p.Name, "typesVMAddr", meth.TypesVMAddr)
					continue
				}
				rtype, args := decodeMethodTypes(meth.Types)
				optMethods += fmt.Sprintf("- %s\n", getMethodWithArgs(meth.Name, rtype, args))
			} else {
				optMethods += fmt.Sprintf("-[%s %s];\n", p.Name, meth.Name)
			}
		}
		if optMethods != "" {
			optMethods = "/* optional instance methods */\n" + optMethods + "\n"
		}
	}
	return fmt.Sprintf(
		"%s\n\n"+
			"@required\n\n"+
			"%s"+ // instance properties (required)
			"%s"+ // class properties (required)
			"%s"+
			"%s"+
			"@optional\n\n"+
			"%s"+
			"%s"+
			"@end\n",
		protocol,
		props,
		cProps,
		cMethods,
		iMethods,
		optProps,
		optMethods,
	)
}

func (p *Protocol) String() string {
	return p.dump(false, false)
}
func (p *Protocol) Verbose() string {
	return p.dump(true, false)
}
func (p *Protocol) WithAddrs() string {
	return p.dump(true, true)
}

// Computed offsets for optional tail fields to avoid magic numbers in parsers.
var (
	// Start offset where fields may not be present on disk.
	ProtocolExtendedMethodTypesOffset = uint32(unsafe.Offsetof(ProtocolT{}.ExtendedMethodTypesVMAddr))
	ProtocolDemangledNameOffset       = uint32(unsafe.Offsetof(ProtocolT{}.DemangledNameVMAddr))
	ProtocolClassPropertiesOffset     = uint32(unsafe.Offsetof(ProtocolT{}.ClassPropertiesVMAddr))
	protocolPointerSize               = uint32(unsafe.Sizeof(ProtocolT{}.ExtendedMethodTypesVMAddr))
)

// Helpers to check if optional fields are present based on on-disk size.
func (p ProtocolT) HasExtendedMethodTypes() bool {
	return p.Size >= ProtocolExtendedMethodTypesOffset+protocolPointerSize
}
func (p ProtocolT) HasDemangledName() bool {
	return p.Size >= ProtocolDemangledNameOffset+protocolPointerSize
}
func (p ProtocolT) HasClassProperties() bool {
	return p.Size >= ProtocolClassPropertiesOffset+protocolPointerSize
}
