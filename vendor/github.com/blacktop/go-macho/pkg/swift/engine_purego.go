package swift

import (
	"fmt"
	"strings"
)

type pureGoEngine struct{}

func newPureGoEngine() engine {
	return pureGoEngine{}
}

func (pureGoEngine) Demangle(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty input")
	}
	// Pure-Go demangling is not yet ready; pass through unchanged until implemented.
	return input, nil
}

func (pureGoEngine) DemangleSimple(input string) (string, error) {
	return pureGoEngine{}.Demangle(input)
}

func (pureGoEngine) DemangleType(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty input")
	}
	// Type demangling is also deferred until the pure-Go engine is implemented.
	return input, nil
}

func looksLikeSwiftSymbol(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	symbolPrefixes := []string{"$s", "$S", "_$s", "_$S", "_T", "__T"}
	for _, prefix := range symbolPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	if strings.Contains(trimmed, "_$s") || strings.Contains(trimmed, "$s.") {
		return true
	}
	if strings.HasPrefix(trimmed, "So") && strings.HasSuffix(trimmed, "C") {
		return true
	}
	return false
}
