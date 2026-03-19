package swift

import (
	"log"
	"os"
	"strings"
)

const (
	engineEnvVar     = "GO_MACHO_SWIFT_ENGINE"
	debugEnvVar      = "GO_MACHO_SWIFT_DEBUG"
	engineModePureGo = "purego"
	engineModeDarwin = "darwin-cgo"
)

var (
	forceEngine   = strings.ToLower(os.Getenv(engineEnvVar))
	defaultEngine engine
	engineMode    string
)

func init() {
	defaultEngine, engineMode = newEngine()
	if debug := os.Getenv(debugEnvVar); debug != "" {
		log.Printf("pkg/swift: using %s demangle engine", engineMode)
	}
}

type engine interface {
	Demangle(string) (string, error)
	DemangleSimple(string) (string, error)
	DemangleType(string) (string, error)
}

// EngineMode reports which demangle engine (pure-Go or darwin-cgo) is active.
func EngineMode() string {
	return engineMode
}
