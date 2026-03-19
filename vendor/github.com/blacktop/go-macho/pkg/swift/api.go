package swift

import (
	"log"
	"os"
	"regexp"
)

var (
	blobTokenPattern = regexp.MustCompile(`(?:_?\$[sStT]|S[oO]|_T)[A-Za-z0-9_]+`)
	logBlobTokens    = os.Getenv("GO_MACHO_SWIFT_TRACE_BLOB") != ""
)

// Demangle returns the fully formatted Swift symbol text.
func Demangle(input string) (string, error) {
	return defaultEngine.Demangle(input)
}

// DemangleSimple returns a simplified Swift symbol name matching swift-demangle -simplified when available.
func DemangleSimple(input string) (string, error) {
	return defaultEngine.DemangleSimple(input)
}

// DemangleType returns the demangled Swift type name from a mangled type string.
// This is specifically for type manglings found in metadata, as opposed to full symbol manglings.
// For example: "Si" -> "Swift.Int", "Sg" -> "Swift.Optional", etc.
//
// NOTE: This function ALWAYS uses the pure-Go demangling engine, even on darwin.
// Apple's libswiftDemangle.dylib doesn't support metadata-specific encodings
// (e.g., I* function type signatures found in __swift5_capture sections).
// The CGO engine is only suitable for full symbol demangling, not type strings.
func DemangleType(input string) (string, error) {
	// Always use pure-Go engine for type demangling
	return newPureGoEngine().DemangleType(input)
}

// DemangleBlob replaces every mangled token in blob with its demangled equivalent.
func DemangleBlob(blob string) string {
	return blobTokenPattern.ReplaceAllStringFunc(blob, func(token string) string {
		if logBlobTokens {
			log.Printf("DemangleBlob token: %s", token)
		}
		out, err := Demangle(token)
		if err != nil {
			return token
		}
		return out
	})
}

// DemangleSimpleBlob replaces mangled tokens with simplified demangled text.
func DemangleSimpleBlob(blob string) string {
	return blobTokenPattern.ReplaceAllStringFunc(blob, func(token string) string {
		out, err := DemangleSimple(token)
		if err != nil {
			return token
		}
		return out
	})
}
