//go:build darwin && cgo

package swift

/*
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef size_t swift_demangle_getDemangledName(const char *MangledName, char *OutputBuffer, size_t Length);
typedef size_t swift_demangle_getSimplifiedDemangledName(const char *MangledName, char *OutputBuffer, size_t Length);

int SwiftDemangle(char *input, char *output, size_t length) {
    if (input == NULL || input[0] == '\0' || output == NULL) {
        return -3;
    }

    void *handle = dlopen("/usr/lib/swift/libswiftDemangle.dylib", RTLD_LAZY);
    if (!handle) {
        return -2;
    }

    swift_demangle_getDemangledName *fn = dlsym(handle, "swift_demangle_getDemangledName");
    if (!fn) {
        dlclose(handle);
        return -1;
    }

    size_t ret = fn(input, output, length);
    dlclose(handle);
    return (int)ret;
}

int SwiftDemangleSimple(char *input, char *output, size_t length) {
    if (input == NULL || input[0] == '\0' || output == NULL) {
        return -3;
    }

    void *handle = dlopen("/usr/lib/swift/libswiftDemangle.dylib", RTLD_LAZY);
    if (!handle) {
        return -2;
    }

    swift_demangle_getSimplifiedDemangledName *fn = dlsym(handle, "swift_demangle_getSimplifiedDemangledName");
    if (!fn) {
        dlclose(handle);
        return -1;
    }

    size_t ret = fn(input, output, length);
    dlclose(handle);
    return (int)ret;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const (
	cgoNoop       = 0
	cgoError      = -1
	cgoNoDylib    = -2
	cgoBadArgs    = -3
	cgoBufferSize = 4096
)

type cgoDemangleFunc func(*C.char, *C.char, C.size_t) C.int

type darwinEngine struct{}

func newEngine() (engine, string) {
	if forceEngine == engineModePureGo {
		return newPureGoEngine(), engineModePureGo
	}
	return newDarwinEngine(), engineModeDarwin
}

func newDarwinEngine() engine {
	return &darwinEngine{}
}

func (e *darwinEngine) Demangle(input string) (string, error) {
	return callSwiftDemangle(func(in, out *C.char, length C.size_t) C.int {
		return C.SwiftDemangle(in, out, length)
	}, input)
}

func (e *darwinEngine) DemangleSimple(input string) (string, error) {
	return callSwiftDemangle(func(in, out *C.char, length C.size_t) C.int {
		return C.SwiftDemangleSimple(in, out, length)
	}, input)
}

func (e *darwinEngine) DemangleType(input string) (string, error) {
	// NOTE: This method is NOT used by the public DemangleType() API,
	// which always uses the pure-Go engine instead. Apple's libswiftDemangle.dylib
	// doesn't support metadata-specific encodings (e.g., I* function type signatures
	// found in __swift5_capture sections). This method is only here to satisfy the
	// engine interface and may work for simple type codes like "Si" or "SS".
	//
	// Type demangling uses the same getDemangledName function
	// The Swift runtime handles both symbols and types through the same entry point
	return callSwiftDemangle(func(in, out *C.char, length C.size_t) C.int {
		return C.SwiftDemangle(in, out, length)
	}, input)
}

func callSwiftDemangle(fn cgoDemangleFunc, input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty input")
	}

	out := (*C.char)(C.malloc(cgoBufferSize))
	defer C.free(unsafe.Pointer(out))

	cstr := C.CString(input)
	defer C.free(unsafe.Pointer(cstr))

	ret := fn(cstr, out, C.size_t(cgoBufferSize))
	if int(ret) > cgoNoop {
		return C.GoString(out), nil
	}

	var err error
	switch int(ret) {
	case cgoBadArgs:
		err = errors.New("invalid arguments")
	case cgoNoDylib:
		err = errors.New("libswiftDemangle.dylib not found")
	case cgoNoop:
		return input, nil
	case cgoError:
		fallthrough
	default:
		err = errors.New("swift demangle call failed")
	}
	return "", err
}
