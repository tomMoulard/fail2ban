package macho

import (
	"errors"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types/swift"
)

func fullSwiftTypeName(typ *swift.Type) string {
	var parts []string
	for t := typ; t != nil; t = t.Parent {
		if t.Name != "" {
			parts = append([]string{t.Name}, parts...)
		}
	}
	return strings.Join(parts, ".")
}

func matchSwiftFieldType(name string, fieldMap map[string]string) (string, bool) {
	if fieldMap == nil {
		return "", false
	}
	if typ, ok := fieldMap[name]; ok {
		return typ, true
	}
	trimmed := strings.TrimPrefix(name, "_")
	if typ, ok := fieldMap[trimmed]; ok {
		return typ, true
	}
	return "", false
}

func (f *File) swiftFieldTypesForClass(fullName string) (map[string]string, error) {
	types, err := f.GetSwiftTypes()
	if err != nil {
		return nil, err
	}

	for i := range types {
		typ := &types[i]
		if typ.Kind != swift.CDKindClass {
			continue
		}
		if fullSwiftTypeName(typ) != fullName {
			continue
		}
		if typ.Fields == nil {
			return nil, nil
		}
		fieldMap := make(map[string]string)
		for _, rec := range typ.Fields.Records {
			if rec.Name == "" || rec.MangledType == "" {
				continue
			}
			fieldMap[rec.Name] = rec.MangledType
		}
		return fieldMap, nil
	}

	return nil, nil
}

func (f *File) swiftASCIITypeGuess(addr uint64) (string, bool) {
	buf := make([]byte, 0x400)
	n, err := f.ReadAtAddr(buf, addr)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false
	}
	buf = buf[:n]

	best := ""
	bestScore := -1
	for i := 0; i < len(buf); {
		for i < len(buf) && buf[i] == 0 {
			i++
		}
		if i >= len(buf) {
			break
		}
		j := i
		for j < len(buf) && buf[j] != 0 {
			j++
		}
		candidate := string(buf[i:j])
		score := swiftAsciiScore(candidate)
		if score > bestScore {
			bestScore = score
			best = candidate
		}
		i = j + 1
	}
	if bestScore > 0 {
		return best, true
	}
	return "", false
}
