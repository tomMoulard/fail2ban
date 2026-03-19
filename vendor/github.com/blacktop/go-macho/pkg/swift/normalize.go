package swift

import (
	"strings"

	typeswift "github.com/blacktop/go-macho/types/swift"
)

var methodPrefixes = []string{"func ", "method ", "getter ", "setter ", "modify ", "init "}

// NormalizeIdentifier attempts to demangle the provided identifier and returns the best-effort human readable string.
func NormalizeIdentifier(name string) string {
	if demangled, ok := TryNormalizeIdentifier(name); ok {
		return demangled
	}
	return name
}

// TryNormalizeIdentifier returns the demangled identifier and a boolean indicating success.
func TryNormalizeIdentifier(name string) (string, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return name, false
	}

	for _, prefix := range methodPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			body := strings.TrimSpace(trimmed[len(prefix):])
			if demangled, ok := tryDemangleCandidate(body); ok {
				return prefix + demangled, true
			}
		}
	}

	return tryDemangleCandidate(trimmed)
}

func tryDemangleCandidate(candidate string) (string, bool) {
	if candidate == "" {
		return candidate, false
	}

	attempts := []string{candidate}
	if strings.HasPrefix(candidate, "_") {
		attempts = append(attempts, strings.TrimPrefix(candidate, "_"))
	}

	for _, attempt := range attempts {
		out, err := Demangle(attempt)
		if err != nil || out == "" || out == attempt {
			continue
		}
		for _, prefix := range []string{
			"protocol descriptor for ",
			"nominal type descriptor for ",
			"method descriptor for ",
		} {
			out = strings.TrimPrefix(out, prefix)
		}
		return out, true
	}

	if tuple, ok := tryTupleFromMangledParts(candidate); ok {
		return tuple, true
	}

	return candidate, false
}

func tryTupleFromMangledParts(candidate string) (string, bool) {
	if strings.HasSuffix(candidate, "Sg") {
		if parts, ok := parseTupleParts(strings.TrimSuffix(candidate, "Sg")); ok {
			return formatTuple(parts, true), true
		}
	}
	if parts, ok := parseTupleParts(candidate); ok {
		return formatTuple(parts, false), true
	}
	return candidate, false
}

func parseTupleParts(candidate string) ([]string, bool) {
	parts := strings.Split(candidate, "_")
	if len(parts) < 2 {
		return nil, false
	}
	resolved := make([]string, 0, len(parts))
	for _, part := range parts {
		if name, ok := resolveTuplePart(part); ok {
			resolved = append(resolved, name)
			continue
		}
		return nil, false
	}
	return resolved, true
}

func formatTuple(parts []string, optional bool) string {
	if len(parts) == 0 {
		return ""
	}
	result := "(" + strings.Join(parts, ", ") + ")"
	if optional {
		return result + "?"
	}
	return result
}

func resolveTuplePart(part string) (string, bool) {
	if name, ok := typeswift.MangledType[part]; ok {
		return name, true
	}
	if name, ok := decodeStandardLibraryToken(part); ok {
		return name, true
	}
	return "", false
}

func decodeStandardLibraryToken(part string) (string, bool) {
	if len(part) < 2 || part[0] != 'S' {
		return "", false
	}
	core := part[1:]
	optional := false
	if strings.HasSuffix(core, "Sg") {
		optional = true
		core = strings.TrimSuffix(core, "Sg")
	}
	if strings.HasSuffix(core, "t") {
		core = strings.TrimSuffix(core, "t")
	}
	if core == "" {
		return "", false
	}
	if name, ok := typeswift.MangledKnownTypeKind[core]; ok {
		if optional {
			return name + "?", true
		}
		return name, true
	}
	if len(core) > 1 {
		if name, ok := typeswift.MangledKnownTypeKind[string(core[0])]; ok {
			if optional {
				return name + "?", true
			}
			return name, true
		}
	}
	return "", false
}
