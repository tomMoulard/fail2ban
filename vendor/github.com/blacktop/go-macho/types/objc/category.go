package objc

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
)

type CategoryT struct {
	NameVMAddr               uint64
	ClsVMAddr                uint64
	InstanceMethodsVMAddr    uint64
	ClassMethodsVMAddr       uint64
	ProtocolsVMAddr          uint64
	InstancePropertiesVMAddr uint64
}

// Category represents an Objective-C category.
type Category struct {
	Name            string
	VMAddr          uint64
	Class           *Class
	Protocols       []Protocol
	ClassMethods    []Method
	InstanceMethods []Method
	Properties      []Property
	CategoryT
}

func (c *Category) dump(verbose, addrs bool) string {
	var cMethods string
	var iMethods string

	var protos string
	if len(c.Protocols) > 0 {
		var prots []string
		for _, prot := range c.Protocols {
			prots = append(prots, prot.Name)
		}
		protos += fmt.Sprintf(" <%s>", strings.Join(prots, ", "))
	}

	var className string
	if c.Class != nil {
		className = c.Class.Name + " "
	}

	var cat string
	if verbose {
		var comment string
		if addrs {
			comment += fmt.Sprintf(" // %#x", c.VMAddr)
		}
		if c.Class != nil && c.Class.IsSwift() {
			if len(comment) > 0 {
				comment += " (Swift)"
			} else {
				comment += " // (Swift)"
			}
		}
		cat = fmt.Sprintf("@interface %s(%s)%s%s", className, c.Name, protos, comment)
	} else {
		cat = fmt.Sprintf("@interface %s(%s)%s", className, c.Name, protos)
	}
	cat += "\n"

	if len(c.ClassMethods) > 0 {
		s := bytes.NewBufferString("/* class methods */\n")
		for _, meth := range c.ClassMethods {
			if !addrs && strings.HasPrefix(meth.Name, ".cxx_") {
				continue
			}
			if verbose {
				if meth.Types == "" {
					slog.Warn("category class method has empty type encoding", "method", meth.Name, "category", c.Name, "typesVMAddr", meth.TypesVMAddr)
					continue
				}
				rtype, args := decodeMethodTypes(meth.Types)
				if addrs {
					s.WriteString(fmt.Sprintf("// %#x\n", meth.ImpVMAddr))
				}
				s.WriteString(fmt.Sprintf("+ %s\n", getMethodWithArgs(meth.Name, rtype, args)))
			} else {
				s.WriteString(fmt.Sprintf("+[%s %s];\n", className, meth.Name))
			}
		}
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
					slog.Warn("category instance method has empty type encoding", "method", meth.Name, "category", c.Name, "typesVMAddr", meth.TypesVMAddr)
					continue
				}
				rtype, args := decodeMethodTypes(meth.Types)
				if addrs {
					s.WriteString(fmt.Sprintf("// %#x\n", meth.ImpVMAddr))
				}
				s.WriteString(fmt.Sprintf("- %s\n", getMethodWithArgs(meth.Name, rtype, args)))
			} else {
				s.WriteString(fmt.Sprintf("-[%s %s];\n", className, meth.Name))
			}
		}
		iMethods = s.String()
		if iMethods != "" {
			iMethods += "\n"
		}
	}

	return fmt.Sprintf(
		"%s\n"+
			"%s"+
			"%s"+
			"@end\n",
		cat,
		cMethods,
		iMethods,
	)
}

func (c *Category) String() string {
	return c.dump(false, false)
}

func (c *Category) Verbose() string {
	return c.dump(true, false)
}

func (c *Category) WithAddrs() string {
	return c.dump(true, true)
}
