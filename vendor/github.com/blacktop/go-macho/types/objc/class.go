package objc

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"text/tabwriter"
)

type ObjcClassT struct {
	IsaVMAddr              uint32
	SuperclassVMAddr       uint32
	MethodCacheBuckets     uint32
	MethodCacheProperties  uint32
	DataVMAddrAndFastFlags uint32
}

type ObjcClass64 struct {
	IsaVMAddr              uint64
	SuperclassVMAddr       uint64
	MethodCacheBuckets     uint64
	MethodCacheProperties  uint64
	DataVMAddrAndFastFlags uint64
}

type SwiftClassMetadata struct {
	ObjcClassT
	SwiftClassFlags uint32
}

type SwiftClassMetadata64 struct {
	ObjcClass64
	SwiftClassFlags uint64
}

type ClassRoFlags uint32

const (
	// class is a metaclass
	RO_META ClassRoFlags = (1 << 0)
	// class is a root class
	RO_ROOT ClassRoFlags = (1 << 1)
	// class has .cxx_construct/destruct implementations
	RO_HAS_CXX_STRUCTORS ClassRoFlags = (1 << 2)
	// class has +load implementation
	RO_HAS_LOAD_METHOD ClassRoFlags = (1 << 3)
	// class has visibility=hidden set
	RO_HIDDEN ClassRoFlags = (1 << 4)
	// class has attributeClassRoFlags = (objc_exception): OBJC_EHTYPE_$_ThisClass is non-weak
	RO_EXCEPTION ClassRoFlags = (1 << 5)
	// class has ro field for Swift metadata initializer callback
	RO_HAS_SWIFT_INITIALIZER ClassRoFlags = (1 << 6)
	// class compiled with ARC
	RO_IS_ARC ClassRoFlags = (1 << 7)
	// class has .cxx_destruct but no .cxx_construct ClassRoFlags = (with RO_HAS_CXX_STRUCTORS)
	RO_HAS_CXX_DTOR_ONLY ClassRoFlags = (1 << 8)
	// class is not ARC but has ARC-style weak ivar layout
	RO_HAS_WEAK_WITHOUT_ARC ClassRoFlags = (1 << 9)
	// class does not allow associated objects on instances
	RO_FORBIDS_ASSOCIATED_OBJECTS ClassRoFlags = (1 << 10)

	// class is in an unloadable bundle - must never be set by compiler
	RO_FROM_BUNDLE ClassRoFlags = (1 << 29)
	// class is unrealized future class - must never be set by compiler
	RO_FUTURE ClassRoFlags = (1 << 30)
	// class is realized - must never be set by compiler
	RO_REALIZED ClassRoFlags = (1 << 31)
)

func (f ClassRoFlags) IsMeta() bool {
	return (f & RO_META) != 0
}
func (f ClassRoFlags) IsRoot() bool {
	return (f & RO_ROOT) != 0
}
func (f ClassRoFlags) HasCxxStructors() bool {
	return (f & RO_HAS_CXX_STRUCTORS) != 0
}
func (f ClassRoFlags) HasFuture() bool {
	return (f & RO_FUTURE) != 0
}
func (f ClassRoFlags) String() string {
	var out []string
	if f.IsMeta() {
		out = append(out, "META")
	}
	if f.IsRoot() {
		out = append(out, "ROOT")
	}
	if f.HasCxxStructors() {
		out = append(out, "HAS_CXX_STRUCTORS")
	}
	if f.HasFuture() {
		out = append(out, "FUTURE")
	}
	return strings.Join(out, " | ")
}

type ClassRO struct {
	Flags                ClassRoFlags
	InstanceStart        uint32
	InstanceSize         uint32
	_                    uint32
	IvarLayoutVMAddr     uint32
	NameVMAddr           uint32
	BaseMethodsVMAddr    uint32
	BaseProtocolsVMAddr  uint32
	IvarsVMAddr          uint32
	WeakIvarLayoutVMAddr uint32
	BasePropertiesVMAddr uint32
}

type ClassRO64 struct {
	Flags         ClassRoFlags
	InstanceStart uint32
	InstanceSize  uint64
	// _                    uint32
	IvarLayoutVMAddr     uint64
	NameVMAddr           uint64
	BaseMethodsVMAddr    uint64
	BaseProtocolsVMAddr  uint64
	IvarsVMAddr          uint64
	WeakIvarLayoutVMAddr uint64
	BasePropertiesVMAddr uint64
}

type Class struct {
	Name                  string
	SuperClass            string
	Isa                   string
	InstanceMethods       []Method
	ClassMethods          []Method
	Ivars                 []Ivar
	Props                 []Property
	Protocols             []Protocol
	ClassPtr              uint64
	IsaVMAddr             uint64
	SuperclassVMAddr      uint64
	MethodCacheBuckets    uint64
	MethodCacheProperties uint64
	DataVMAddr            uint64
	IsSwiftLegacy         bool
	IsSwiftStable         bool
	ReadOnlyData          ClassRO64
}

func (c *Class) dump(verbose, addrs bool) string {
	var iVars string
	var props string
	var cMethods string
	var iMethods string

	var subClass string
	if c.ReadOnlyData.Flags.IsRoot() {
		subClass = "<ROOT>"
	} else if len(c.SuperClass) > 0 {
		subClass = c.SuperClass
	}

	class := fmt.Sprintf("@interface %s : %s", c.Name, subClass)

	if len(c.Protocols) > 0 {
		var subProts []string
		for _, prot := range c.Protocols {
			subProts = append(subProts, prot.Name)
		}
		class += fmt.Sprintf(" <%s>", strings.Join(subProts, ", "))
	}
	if len(c.Ivars) > 0 {
		class += fmt.Sprintf(" {")
	}
	if verbose {
		var comment string
		if addrs {
			comment += fmt.Sprintf(" // %#x", c.ClassPtr)
		}
		if c.IsSwift() {
			if len(comment) > 0 {
				comment += " (Swift)"
			} else {
				comment += " // (Swift)"
			}
		}
		class += comment
	}
	if len(c.Ivars) > 0 {
		s := bytes.NewBufferString("")
		w := tabwriter.NewWriter(s, 0, 0, 1, ' ', 0)
		if addrs {
			fmt.Fprintf(w, "\n    /* instance variables */\t// +size   offset\n")
		} else {
			fmt.Fprintf(w, "\n    /* instance variables */\n")
		}
		for _, ivar := range c.Ivars {
			if verbose {
				if addrs {
					fmt.Fprintf(w, "    %s\n", ivar.WithAddrs())
				} else {
					fmt.Fprintf(w, "    %s\n", ivar.Verbose())
				}
			} else {
				fmt.Fprintf(w, "    %s\n", &ivar)
			}
		}
		w.Flush()
		s.WriteString("}")
		iVars = s.String()
	}
	if len(c.Props) > 0 {
		for _, prop := range c.Props {
			if verbose {
				attrs, _ := prop.Attributes()
				props += fmt.Sprintf("@property %s%s%s;\n", attrs, prop.Type(), prop.Name)
			} else {
				props += fmt.Sprintf("@property (%s) %s;\n", prop.EncodedAttributes, prop.Name)
			}
		}
		if props != "" {
			props += "\n"
		}
	}
	if len(c.ClassMethods) > 0 {
		s := bytes.NewBufferString("/* class methods */\n")
		w := tabwriter.NewWriter(s, 0, 0, 1, ' ', 0)
		for _, meth := range c.ClassMethods {
			if !addrs && strings.HasPrefix(meth.Name, ".cxx_") {
				continue
			}
			if verbose {
				if meth.Types == "" {
					slog.Warn("class method has empty type encoding", "method", meth.Name, "class", c.Name, "typesVMAddr", meth.TypesVMAddr)
					continue
				}
				rtype, args := decodeMethodTypes(meth.Types)
				if addrs {
					s.WriteString(fmt.Sprintf("// %#x\n", meth.ImpVMAddr))
				}
				s.WriteString(fmt.Sprintf("+ %s\n", getMethodWithArgs(meth.Name, rtype, args)))
			} else {
				s.WriteString(fmt.Sprintf("+[%s %s];\n", c.Name, meth.Name))
			}
		}
		w.Flush()
		cMethods = s.String()
		if cMethods != "" {
			cMethods += "\n"
		}
	}
	if len(c.InstanceMethods) > 0 {
		s := bytes.NewBufferString("/* instance methods */\n")
		for _, meth := range c.InstanceMethods {
			if !addrs && strings.HasPrefix(meth.Name, ".cxx_") {
				continue
			}
			if verbose {
				if meth.Types == "" {
					slog.Warn("instance method has empty type encoding", "method", meth.Name, "class", c.Name, "typesVMAddr", meth.TypesVMAddr)
					continue
				}
				rtype, args := decodeMethodTypes(meth.Types)
				if addrs {
					s.WriteString(fmt.Sprintf("// %#x\n", meth.ImpVMAddr))
				}
				s.WriteString(fmt.Sprintf("- %s\n", getMethodWithArgs(meth.Name, rtype, args)))
			} else {
				s.WriteString(fmt.Sprintf("-[%s %s];\n", c.Name, meth.Name))
			}
		}
		iMethods = s.String()
		if iMethods != "" {
			iMethods += "\n"
		}
	}

	return fmt.Sprintf(
		"%s"+
			"%s\n\n"+
			"%s"+
			"%s"+
			"%s"+
			"@end\n",
		class,
		iVars,
		props,
		cMethods,
		iMethods,
	)
}

// IsSwift returns true if the class is a Swift class.
func (c *Class) IsSwift() bool {
	return c.IsSwiftLegacy || c.IsSwiftStable
}
func (c *Class) String() string {
	return c.dump(false, false)
}
func (c *Class) Verbose() string {
	return c.dump(true, false)
}
func (c *Class) WithAddrs() string {
	return c.dump(true, true)
}
