//go:build !darwin || !cgo

package swift

func newEngine() (engine, string) {
	return newPureGoEngine(), engineModePureGo
}
