package objc

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// References:
// 01. https://clang.llvm.org/docs/LanguageExtensions.html#half-precision-floating-point
// 02. https://clang.llvm.org/docs/LanguageExtensions.html#vectors-and-extended-vectors
// 03. https://developer.apple.com/documentation/objectivec/bool#discussion
// 04. https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms#Handle-data-types-and-data-alignment-properly
// 05. https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtTypeEncodings.html#//apple_ref/doc/uid/TP40008048-CH100-SW1
// 06. https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/64bitPorting/transition/transition.html#//apple_ref/doc/uid/TP40001064-CH207-SW1
// 07. https://gcc.gnu.org/onlinedocs/gcc/Half-Precision.html
// 08. https://gcc.gnu.org/onlinedocs/gcc/Vector-Extensions.html
// 09. https://github.com/apple-oss-distributions/clang/blob/rel/clang-800/src/tools/clang/include/clang/AST/DeclBase.h#L173-L200
// 10. https://github.com/apple-oss-distributions/clang/blob/rel/clang-800/src/tools/clang/include/clang/AST/DeclObjC.h#L698-L727
// 11. https://github.com/apple-oss-distributions/clang/blob/rel/clang-800/src/tools/clang/lib/AST/ASTContext.cpp#L5452-L5518
// 12. https://github.com/apple-oss-distributions/objc4/blob/rel/objc4-906/runtime/runtime.h#L1856-L1900
// 13. https://github.com/apple-oss-distributions/objc4/blob/rel/objc4-838/runtime/hashtable2.h#L251-L294
// 14. https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/doc/objc.texi
// 15. https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/gcc/objc/objc-encoding.cc
// 16. https://github.com/gcc-mirror/gcc/blob/releases/gcc-13.2.0/libobjc/objc/runtime.h#L83-L139

var typeEncoding = map[string]string{
	"":     "",                          // Nothing
	" ":    "_Float16",                  // Half-Precision C Floating-Point (LLVM only)
	"#":    "Class",                     // Objective-C Class
	"%":    "const char * /* NXAtom */", // Objective-C NXAtom (legacy Objective-C runtime only)
	"*":    "char *",                    // C String
	":":    "SEL",                       // Objective-C Selector
	"?":    "void * /* unknown */",      // Unknown (likely a C Function and unlikely an Objective-C Block)
	"@":    "id",                        // Objective-C Pointer
	"@?":   "id /* block */",            // Objective-C Block Pointer
	"B":    "_Bool",                     // C Boolean or Objective-C Boolean (on ARM and PowerPC)
	"C":    "unsigned char",             // Unsigned C Character
	"D":    "long double",               // Extended-Precision C Floating-Point (64 bits on ARM, 80 bits on Intel, and 128 bits on PowerPC)
	"I":    "unsigned int",              // Unsigned C Integer
	"L":    "unsigned int32_t",          // Unsigned C Long Integer (fixed to 32 bits)
	"Q":    "unsigned long long",        // Unsigned C Long-Long Integer
	"S":    "unsigned short",            // Unsigned C Short Integer
	"T":    "unsigned __int128",         // Unsigned C 128-bit Integer
	"^(?)": "void * /* union */",        // C Union Pointer
	"^?":   "void * /* function */",     // C Function Pointer
	"^{?}": "void * /* struct */",       // C Struct Pointer
	"c":    "signed char",               // Signed C Character (fixed signedness) or Objective-C Boolean (on Intel)
	"d":    "double",                    // Double-Precision C Floating-Point
	"f":    "float",                     // Single-Precision C Floating-Point
	"i":    "int",                       // Signed C Integer
	"l":    "int32_t",                   // Signed C Long Integer (fixed to 32 bits)
	"q":    "long long",                 // Signed C Long-Long Integer
	"s":    "short",                     // Signed C Short Integer
	"t":    "__int128",                  // Signed C 128-bit Integer
	"v":    "void",                      // C Void
	// "!": "", // GNU Vector (LLVM Vector is unrepresented)
	// "^": "", // C Pointer
	// "b": "", // C Bit Field
	// "(": "", // C Union Begin
	// ")": "", // C Union End
	// "[": "", // C Array Begin
	// "]": "", // C Array End
	// "{": "", // C Struct Begin
	// "}": "", // C Struct End
}

var swiftBuiltinTypeAlias = map[string]string{
	"Si": "id /* Swift.Int */",
	"Su": "id /* Swift.UInt */",
	"Sb": "BOOL /* Swift.Bool */",
	"SS": "NSString * /* Swift.String */",
	"Sf": "id /* Swift.Float */",
	"Sd": "id /* Swift.Double */",
}

var typeSpecifiers = map[string]string{
	"+": "/* gnu register */", // TODO: review
	"A": "_Atomic",
	"N": "inout",
	"O": "bycopy",
	"R": "byref",
	"V": "oneway",
	"j": "_Complex",
	"n": "in",
	"o": "out",
	"r": "const",
	"|": "/* gc invisible */", // TODO: review
}

const (
	propertyReadOnly  = "R" // property is read-only.
	propertyBycopy    = "C" // property is a copy of the value last assigned
	propertyByref     = "&" // property is a reference to the value last assigned
	propertyDynamic   = "D" // property is dynamic
	propertyGetter    = "G" // followed by getter selector name
	propertySetter    = "S" // followed by setter selector name
	propertyIVar      = "V" // followed by instance variable  name
	propertyType      = "T" // followed by old-style type encoding.
	propertyWeak      = "W" // 'weak' property
	propertyStrong    = "P" // property GC'able
	propertyAtomic    = "A" // property atomic
	propertyNonAtomic = "N" // property non-atomic
	propertyOptional  = "?" // property optional
)

type methodEncodedArg struct {
	DecType   string // decoded argument type
	EncType   string // encoded argument type
	StackSize string // variable stack size
}

type varEncodedType struct {
	Head     string // type specifiers
	Variable string // variable name
	DecType  string // decoded variable type
	EncType  string // encoded variable type
	Tail     string // type output tail
}

// decodeMethodTypes decodes the method types and returns a return type and the argument types
func decodeMethodTypes(encodedTypes string) (string, []string) {
	var argTypes []string

	// skip return type
	encArgs := strings.TrimLeft(skipFirstType(encodedTypes), "0123456789")

	for idx, arg := range getArguments(encArgs) {
		switch idx {
		case 0:
			argTypes = append(argTypes, fmt.Sprintf("(%s)self", arg.DecType))
		case 1:
			argTypes = append(argTypes, fmt.Sprintf("(%s)id", arg.DecType))
		default:
			argTypes = append(argTypes, fmt.Sprintf("(%s)", arg.DecType))
		}
	}
	return getReturnType(encodedTypes), argTypes
}

func getLastCapitalizedPart(s string) string {
	start := len(s)
	for i := len(s) - 1; i >= 0; i-- {
		if unicode.IsUpper(rune(s[i])) {
			start = i
		} else if start != len(s) {
			break
		}
	}
	if start == len(s) {
		return s
	}
	return strings.ToLower(s[start:])
}

func isReserved(s string) bool {
	switch s {
	case "alignas", "alignof", "auto", "bool", "break", "case", "char", "const", "constexpr", "continue", "default", "do", "double", "else", "enum", "extern", "false", "float", "for", "goto", "if", "inline", "int", "long", "nullptr", "register", "restrict", "return", "short", "signed", "sizeof", "static", "static_assert", "struct", "switch", "thread_local", "true", "typedef", "typeof", "typeof_unqual", "union", "unsigned", "void", "volatile", "while":
		return true // C Keywords
	case "and", "and_eq", "asm", "atomic_cancel", "atomic_commit", "atomic_noexcept", "bitand", "bitor", "catch", "char8_t", "char16_t", "char32_t", "class", "compl", "concept", "consteval", "constinit", "const_cast", "co_await", "co_return", "co_yield", "decltype", "delete", "dynamic_cast", "explicit", "export", "friend", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "operator", "or", "or_eq", "private", "protected", "public", "reflexpr", "reinterpret_cast", "requires", "static_cast", "synchronized", "template", "this", "throw", "try", "typeid", "typename", "using", "virtual", "wchar_t", "xor", "xor_eq":
		return true // C++ Keywords
	default:
		return false
	}
}

func getMethodWithArgs(method, returnType string, args []string) string {
	if len(args) <= 2 {
		return fmt.Sprintf("(%s)%s;", returnType, method)
	}
	args = args[2:] // skip self and SEL

	parts := strings.Split(method, ":")

	var methodStr string
	if len(parts) > 1 { // method has arguments based on SEL having ':'
		for idx, part := range parts {
			argName := getLastCapitalizedPart(part)
			if isReserved(argName) {
				argName = "_" + argName
			}
			if len(part) == 0 || idx >= len(args) {
				break
			}
			methodStr += fmt.Sprintf("%s:%s ", part, args[idx]+argName)
		}
		return fmt.Sprintf("(%s)%s;", returnType, strings.TrimSpace(methodStr))
	}
	// method has no arguments based on SEL not having ':'
	return fmt.Sprintf("(%s)%s;", returnType, method)
}

func getPropertyType(attrs string) (typ string) {
	if strings.HasPrefix(attrs, propertyType) {
		var attr string
		var typParts []string
		parts := strings.Split(attrs, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			sub := parts[i]
			switch string(sub[0]) {
			case propertyReadOnly:
			case propertyBycopy:
			case propertyByref:
			case propertyDynamic:
			case propertyGetter:
			case propertySetter:
			case propertyIVar:
			case propertyWeak:
			case propertyStrong:
			case propertyAtomic:
			case propertyNonAtomic:
			case propertyOptional:
			case propertyType:
				typParts = append([]string{strings.TrimPrefix(sub, propertyType)}, typParts...)
				attr = strings.Join(typParts, ",")
			default:
				typParts = append([]string{sub}, typParts...)
			}
		}
		if strings.HasPrefix(attr, "@\"") {
			typ = strings.Trim(attr, "@\"")
			typ = strings.ReplaceAll(typ, "><", ", ")
			if strings.HasPrefix(typ, "<") {
				typ = "id " + typ + " "
			} else {
				typ += " *"
			}
		} else {
			typ = decodeType(attr) + " "
		}
	} else {
		typ = "?"
	}
	return typ
}

func getPropertyAttributeTypes(attrs string) (string, bool) {
	// var ivarStr string
	var attrsStr string
	var attrsList []string

	isOptional := false

	for _, attr := range strings.Split(attrs, ",") {
		if strings.HasPrefix(attr, propertyIVar) {
			// found ivar name
			// ivarStr = strings.TrimPrefix(attr, propertyIVar)
			continue
		}
		// TODO: handle the following cases
		// @property struct YorkshireTeaStruct structDefault; ==> T{YorkshireTeaStruct="pot"i"lady"c},VstructDefault
		// @property int (*functionPointerDefault)(char *);   ==> T^?,VfunctionPointerDefault
		switch attr {
		case propertyGetter:
			attr = strings.TrimPrefix(attr, propertyGetter)
			attrsList = append(attrsList, fmt.Sprintf("getter=%s", attr))
		case propertySetter:
			attr = strings.TrimPrefix(attr, propertySetter)
			attrsList = append(attrsList, fmt.Sprintf("setter=%s", attr))
		case propertyReadOnly:
			attrsList = append(attrsList, "readonly")
		case propertyNonAtomic:
			attrsList = append(attrsList, "nonatomic")
		case propertyAtomic:
			attrsList = append(attrsList, "atomic")
		case propertyBycopy:
			attrsList = append(attrsList, "copy")
		case propertyByref:
			attrsList = append(attrsList, "retain")
		case propertyWeak:
			attrsList = append(attrsList, "weak")
		case propertyDynamic:
			// omit the @dynamic directive because it must never appear inside
			// @interface and @protocol blocks, only in @implementation blocks
		case propertyStrong:
			attrsList = append(attrsList, "collectable")
		case propertyOptional:
			isOptional = true
		}
	}

	if len(attrsList) > 0 {
		attrsStr = fmt.Sprintf("(%s) ", strings.Join(attrsList, ", "))
	}

	return attrsStr, isOptional
}

func getIVarType(ivType string) string {
	if strings.HasPrefix(ivType, "@\"") && len(ivType) > 1 {
		ivType = strings.Trim(ivType, "@\"")
		ivType = strings.ReplaceAll(ivType, "><", ", ")
		if strings.HasPrefix(ivType, "<") {
			return "id " + ivType + " "
		}
		return ivType + " *"
	}
	return decodeType(ivType) + " "
}

func getReturnType(types string) string {
	if len(types) == 0 {
		return ""
	}
	return decodeType(strings.TrimSuffix(types, skipFirstType(types)))
}

func decodeType(encType string) string {
	var s string

	if typ, ok := typeEncoding[encType]; ok {
		return typ
	}
	if alias, ok := swiftBuiltinTypeAlias[encType]; ok {
		return alias
	}
	if strings.HasPrefix(encType, "@\"SwiftUnresolved_0x") {
		addr := strings.TrimSuffix(strings.TrimPrefix(encType, "@\"SwiftUnresolved_"), "\"")
		return fmt.Sprintf("id /* Swift metadata %s */", addr)
	}

	if strings.HasPrefix(encType, "^") {
		if typ, ok := typeEncoding[encType]; ok {
			return typ
		}

		decType := decodeType(encType[1:])

		if len(encType) > 1 && encType[1] == '!' {
			return strings.Replace(decType, "x", "*x", 1) // vector pointer
		}

		return decType + " *" // pointer
	}

	if spec, ok := typeSpecifiers[string(encType[0])]; ok { // TODO: can there be more than 2 specifiers?
		if len(encType) > 1 {
			if spec2, ok := typeSpecifiers[string(encType[1])]; ok {
				return spec2 + " " + spec + " " + decodeType(encType[2:])
			}
		}
		return spec + " " + decodeType(encType[1:])
	}

	if strings.HasPrefix(encType, "@\"") && len(encType) > 1 {
		return strings.Trim(encType, "@\"") + " *"
	}

	if strings.HasPrefix(encType, "b") {
		return decodeBitfield(encType)
	}

	if len(encType) > 2 {
		switch encType[0] {
		case '!': // VECTOR
			start := strings.IndexByte(encType, '[')
			end := strings.LastIndexByte(encType, ']')
			if start == -1 || end == -1 || start+1 > end {
				return encType
			}
			inner := encType[start+1 : end]
			s += decodeVector(inner)

		case '(': // UNION
			start := strings.IndexByte(encType, '(')
			end := strings.LastIndexByte(encType, ')')
			if start == -1 || end == -1 || start+1 > end {
				return encType
			}
			inner := encType[start+1 : end]
			s += decodeUnion(inner)

		case '[': // ARRAY
			start := strings.IndexByte(encType, '[')
			end := strings.LastIndexByte(encType, ']')
			if start == -1 || end == -1 || start+1 > end {
				return encType
			}
			inner := encType[start+1 : end]
			s += decodeArray(inner)

		case '{': // STRUCT
			if !(strings.Contains(encType, "{") && strings.Contains(encType, "}")) {
				return "?"
			}
			start := strings.IndexByte(encType, '{')
			end := strings.LastIndexByte(encType, '}')
			if start == -1 || end == -1 || start+1 > end {
				return encType
			}
			inner := encType[start+1 : end]
			s += decodeStructure(inner)

		case '<': // block func prototype
			start := strings.IndexByte(encType, '<')
			end := strings.LastIndexByte(encType, '>')
			if start == -1 || end == -1 || start+1 > end {
				return encType
			}
			inner := encType[start+1 : end]
			ret, args := decodeMethodTypes(inner)
			s += fmt.Sprintf("(%s (^)(%s))", ret, strings.Join(args, " "))
		}
	}

	if len(s) == 0 {
		return encType
	}

	return s
}

func decodeArray(arrayType string) string {
	typIdx := 0
	for _, c := range arrayType {
		if c < '0' || c > '9' {
			break
		}

		typIdx++
	}

	decType := decodeType(arrayType[typIdx:])
	if !strings.HasSuffix(decType, "*") {
		decType += " "
	}

	return fmt.Sprintf("%sx[%s]", decType, arrayType[:typIdx])
}

func decodeStructure(structure string) string {
	return decodeStructOrUnion(structure, "struct")
}

func decodeUnion(unionType string) string {
	return decodeStructOrUnion(unionType, "union")
}

var (
	vectorRegExp = regexp.MustCompile(`(?P<size>\d+),(?P<alignment>\d+)(?P<type>.+)`)
)

func decodeVector(vectorType string) string {
	matches := vectorRegExp.FindStringSubmatch(vectorType)
	if len(matches) != 4 {
		return ""
	}

	vSize := matches[1]
	vAlignment := matches[2]

	eType := decodeType(matches[3])
	if !strings.HasSuffix(eType, "*") {
		eType += " "
	}

	return fmt.Sprintf("%sx __attribute__((aligned(%s), vector_size(%s)))", eType, vAlignment, vSize)
}

func decodeBitfield(bitfield string) string {
	span := encodingGetSizeOfArguments(bitfield)
	return fmt.Sprintf("unsigned int x:%d", span)
}

func getFieldName(field string) (string, string) {
	if strings.HasPrefix(field, "\"") {
		name, rest, ok := strings.Cut(strings.TrimPrefix(field, "\""), "\"")
		if !ok {
			return "", field
		}
		return name, rest
	}
	return "", field
}

var (
	vectorIdentifierRegExp = regexp.MustCompile(`(.+[ *])x( __attribute__.+)`)
)

func decodeStructOrUnion(typ, kind string) string {
	name, rest, _ := strings.Cut(typ, "=")
	if name == "?" {
		name = ""
	} else {
		name += " "
	}

	if len(rest) == 0 {
		return fmt.Sprintf("%s %s", kind, strings.TrimSpace(name))
	}

	var idx int
	var fields []string
	fieldName, rest := getFieldName(rest)
	field, rest, ok := CutType(rest)

	for ok {
		// Although technically possible, binaries produced by clang never have a
		// mix of named and unnamed fields in the same struct. This assumption is
		// necessary to disambiguate {"x0"@"x1"c}.
		if fieldName != "" && rest != "" && strings.HasSuffix(field, `"`) && !strings.HasPrefix(rest, `"`) {
			penultQuoteIdx := strings.LastIndex(strings.TrimRight(field, `"`), `"`)
			if penultQuoteIdx == -1 {
				rest = field + rest
				field = "id"
			} else {
				rest = field[penultQuoteIdx:] + rest
				field = field[:penultQuoteIdx]
			}
		}

		if fieldName == "" {
			fieldName = fmt.Sprintf("x%d", idx)
		}

		if strings.HasPrefix(field, "b") {
			span := encodingGetSizeOfArguments(field)
			fields = append(fields, fmt.Sprintf("unsigned int %s:%d;", fieldName, span))
		} else if strings.HasPrefix(field, "[") {
			array := decodeType(field)
			array = strings.TrimSpace(strings.Replace(array, "x", fieldName, 1)) + ";"
			fields = append(fields, array)
		} else {
			decType := decodeType(field)
			if !strings.HasSuffix(decType, "))") {
				if !strings.HasSuffix(decType, "*") {
					decType += " "
				}

				fields = append(fields, fmt.Sprintf("%s%s;", decType, fieldName))
			} else {
				matches := vectorIdentifierRegExp.FindStringSubmatchIndex(decType)
				if len(matches) != 6 {
					fields = append(fields, fmt.Sprintf("%s%s;", decType, fieldName))
				} else {
					prefix := decType[:matches[3]]
					suffix := decType[matches[4]:]

					fields = append(fields, fmt.Sprintf("%s%s%s;", prefix, fieldName, suffix))
				}
			}
		}

		idx++

		fieldName, rest = getFieldName(rest)
		field, rest, ok = CutType(rest)
	}

	return fmt.Sprintf("%s %s{ %s }", kind, name, strings.Join(fields, " "))
}

func skipFirstType(typStr string) string {
	if len(typStr) == 0 {
		return ""
	}
	i := 0
	typ := []byte(typStr)
	for {
		if i >= len(typ) {
			return ""
		}
		switch typ[i] {
		case '+': /* gnu register */
			fallthrough
		case 'A': /* _Atomic */
			fallthrough
		case 'N': /* inout */
			fallthrough
		case 'O': /* bycopy */
			fallthrough
		case 'R': /* byref */
			fallthrough
		case 'V': /* oneway */
			fallthrough
		case 'j': /* _Complex */
			fallthrough
		case 'n': /* in */
			fallthrough
		case 'o': /* out */
			fallthrough
		case 'r': /* const */
			fallthrough
		case '|': /* gc invisible */
			fallthrough
		case '^': /* pointers */
			i++
		case '@': /* objects */
			if i+1 < len(typ) && typ[i+1] == '?' {
				i++ /* Blocks */
			} else if i+1 < len(typ) && typ[i+1] == '"' {
				i++
				for i+1 < len(typ) && typ[i+1] != '"' {
					i++ /* Class */
				}
				i++
			}
			if i+1 <= len(typ) {
				return string(typ[i+1:])
			}
			return ""
		case '!': /* vectors */
			i += 2
			for i < len(typ) && (typ[i] == ',' || typ[i] >= '0' && typ[i] <= '9') {
				i++
			}
			if i < len(typ) {
				skip := subtypeUntil(string(typ[i:]), ']')
				if i+skip+1 <= len(typ) {
					return string(typ[i+skip+1:])
				}
			}
			return ""
		case '[': /* arrays */
			i++
			for i < len(typ) && typ[i] >= '0' && typ[i] <= '9' {
				i++
			}
			if i < len(typ) {
				skip := subtypeUntil(string(typ[i:]), ']')
				if i+skip+1 <= len(typ) {
					return string(typ[i+skip+1:])
				}
			}
			return ""
		case '{': /* structures */
			i++
			if i < len(typ) {
				skip := subtypeUntil(string(typ[i:]), '}')
				if i+skip+1 <= len(typ) {
					return string(typ[i+skip+1:])
				}
			}
			return ""
		case '(': /* unions */
			i++
			if i < len(typ) {
				skip := subtypeUntil(string(typ[i:]), ')')
				if i+skip+1 <= len(typ) {
					return string(typ[i+skip+1:])
				}
			}
			return ""
		case '<': /* block func prototype */
			i++
			if i < len(typ) {
				skip := subtypeUntil(string(typ[i:]), '>')
				if i+skip+1 <= len(typ) {
					return string(typ[i+skip+1:])
				}
			}
			return ""
		default: /* basic types */
			i++
			if i <= len(typ) {
				return string(typ[i:])
			}
			return ""
		}
	}
}

func subtypeUntil(typ string, end byte) int {
	var level int
	head := typ
	for len(typ) > 0 {
		if level == 0 && typ[0] == end {
			return len(head) - len(typ)
		}
		switch typ[0] {
		case ']', '}', ')', '>':
			level -= 1
		case '[', '{', '(', '<':
			level += 1
		}
		typ = typ[1:]
	}
	return 0
}

func CutType(typStr string) (string, string, bool) {
	var i int

	if len(typStr) == 0 {
		return "", "", false
	}
	if len(typStr) == 1 {
		return typStr, "", true
	}

	typ := []byte(typStr)
	for {
		if i >= len(typ) {
			return "", string(typ[1:]), false
		}
		switch typ[i] {
		case '+': /* gnu register */
			fallthrough
		case 'A': /* _Atomic */
			fallthrough
		case 'N': /* inout */
			fallthrough
		case 'O': /* bycopy */
			fallthrough
		case 'R': /* byref */
			fallthrough
		case 'V': /* oneway */
			fallthrough
		case 'j': /* _Complex */
			fallthrough
		case 'n': /* in */
			fallthrough
		case 'o': /* out */
			fallthrough
		case 'r': /* const */
			fallthrough
		case '|': /* gc invisible */
			fallthrough
		case '^': /* pointers */
			i++
		case '@': /* objects */
			if i+1 < len(typ) && typ[i+1] == '?' {
				i++ /* Blocks */
			} else if i+1 < len(typ) && typ[i+1] == '"' {
				i++
				for typ[i+1] != '"' {
					i++ /* Class */
				}
				i++
			}
			return string(typ[:i+1]), string(typ[i+1:]), true
		case 'b': /* bitfields */
			i++
			for i < len(typ) && typ[i] >= '0' && typ[i] <= '9' {
				i++
			}
			return string(typ[:i]), string(typ[i:]), true
		case '!': /* vectors */
			i += 2
			for typ[i] == ',' || typ[i] >= '0' && typ[i] <= '9' {
				i++
			}
			return string(typ[:i+subtypeUntil(string(typ[i:]), ']')+1]), string(typ[i+subtypeUntil(string(typ[i:]), ']')+1:]), true
		case '[': /* arrays */
			i++
			for typ[i] >= '0' && typ[i] <= '9' {
				i++
			}
			return string(typ[:i+subtypeUntil(string(typ[i:]), ']')+1]), string(typ[i+subtypeUntil(string(typ[i:]), ']')+1:]), true
		case '{': /* structures */
			i++
			return string(typ[:i+subtypeUntil(string(typ[i:]), '}')+1]), string(typ[i+subtypeUntil(string(typ[i:]), '}')+1:]), true
		case '(': /* unions */
			i++
			return string(typ[:i+subtypeUntil(string(typ[i:]), ')')+1]), string(typ[i+subtypeUntil(string(typ[i:]), ')')+1:]), true
		case '<': /* block func prototype */
			i++
			return string(typ[:i+subtypeUntil(string(typ[i:]), '>')+1]), string(typ[i+subtypeUntil(string(typ[i:]), '>')+1:]), true
		default: /* basic types */
			i++
			return string(typ[:i]), string(typ[i:]), true
		}
	}
}

func getNumberOfArguments(types string) int {
	var nargs int
	// First, skip the return type
	types = skipFirstType(types)
	// Next, skip stack size
	types = strings.TrimLeft(types, "0123456789")
	// Now, we have the arguments - count how many
	for len(types) > 0 {
		// Traverse argument type
		types = skipFirstType(types)
		// Skip GNU runtime's register parameter hint
		types = strings.TrimPrefix(types, "+")
		// Traverse (possibly negative) argument offset
		types = strings.TrimPrefix(types, "-")
		types = strings.TrimLeft(types, "0123456789")
		// Made it past an argument
		nargs++
	}
	return nargs
}

func getArguments(encArgs string) []methodEncodedArg {
	var args []methodEncodedArg
	t, rest, ok := CutType(encArgs)
	for ok {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		args = append(args, methodEncodedArg{
			EncType:   t,
			DecType:   decodeType(t),
			StackSize: rest[:i],
		})
		t, rest, ok = CutType(rest[i:])
	}
	return args
}

func encodingGetSizeOfArguments(typedesc string) uint {
	var stackSize uint

	stackSize = 0
	typedesc = skipFirstType(typedesc)

	for i := 0; i < len(typedesc); i++ {
		if typedesc[i] >= '0' && typedesc[i] <= '9' {
			stackSize = stackSize*10 + uint(typedesc[i]-'0')
		} else {
			break
		}
	}

	return stackSize
}
