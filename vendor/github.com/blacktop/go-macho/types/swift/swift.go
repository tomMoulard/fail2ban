package swift

import "fmt"

//go:generate stringer -type SpecialPointerAuthDiscriminators -trimprefix=Disc -output swift_string.go

const (
	/// The name of the standard library, which is a reserved module name.
	STDLIB_NAME = "Swift"
	/// The name of the Onone support library, which is a reserved module name.
	SWIFT_ONONE_SUPPORT = "SwiftOnoneSupport"
	/// The name of the SwiftShims module, which contains private stdlib decls.
	SWIFT_SHIMS_NAME = "SwiftShims"
	/// The name of the Builtin module, which contains Builtin functions.
	BUILTIN_NAME = "Builtin"
	/// The name of the clang imported header module.
	CLANG_HEADER_MODULE_NAME = "__ObjC"
	/// The prefix of module names used by LLDB to capture Swift expressions
	LLDB_EXPRESSIONS_MODULE_NAME_PREFIX = "__lldb_expr_"

	/// The name of the fake module used to hold imported Objective-C things.
	MANGLING_MODULE_OBJC = "__C"
	/// The name of the fake module used to hold synthesized ClangImporter things.
	MANGLING_MODULE_CLANG_IMPORTER = "__C_Synthesized"

	/// The name prefix for C++ template instantiation imported as a Swift struct.
	CXX_TEMPLATE_INST_PREFIX = "__CxxTemplateInst"

	SEMANTICS_PROGRAMTERMINATION_POINT = "programtermination_point"

	/// The name of the Builtin type prefix
	BUILTIN_TYPE_NAME_PREFIX = "Builtin."
)

const (
	/// The name of the Builtin type for Int
	BUILTIN_TYPE_NAME_INT = "Builtin.Int"
	/// The name of the Builtin type for Int8
	BUILTIN_TYPE_NAME_INT8 = "Builtin.Int8"
	/// The name of the Builtin type for Int16
	BUILTIN_TYPE_NAME_INT16 = "Builtin.Int16"
	/// The name of the Builtin type for Int32
	BUILTIN_TYPE_NAME_INT32 = "Builtin.Int32"
	/// The name of the Builtin type for Int64
	BUILTIN_TYPE_NAME_INT64 = "Builtin.Int64"
	/// The name of the Builtin type for Int128
	BUILTIN_TYPE_NAME_INT128 = "Builtin.Int128"
	/// The name of the Builtin type for Int256
	BUILTIN_TYPE_NAME_INT256 = "Builtin.Int256"
	/// The name of the Builtin type for Int512
	BUILTIN_TYPE_NAME_INT512 = "Builtin.Int512"
	/// The name of the Builtin type for IntLiteral
	BUILTIN_TYPE_NAME_INTLITERAL = "Builtin.IntLiteral"
	/// The name of the Builtin type for IEEE Floating point types.
	BUILTIN_TYPE_NAME_FLOAT = "Builtin.FPIEEE"
	// The name of the builtin type for power pc specific floating point types.
	BUILTIN_TYPE_NAME_FLOAT_PPC = "Builtin.FPPPC"
	/// The name of the Builtin type for NativeObject
	BUILTIN_TYPE_NAME_NATIVEOBJECT = "Builtin.NativeObject"
	/// The name of the Builtin type for BridgeObject
	BUILTIN_TYPE_NAME_BRIDGEOBJECT = "Builtin.BridgeObject"
	/// The name of the Builtin type for RawPointer
	BUILTIN_TYPE_NAME_RAWPOINTER = "Builtin.RawPointer"
	/// The name of the Builtin type for UnsafeValueBuffer
	BUILTIN_TYPE_NAME_UNSAFEVALUEBUFFER = "Builtin.UnsafeValueBuffer"
	/// The name of the Builtin type for UnknownObject
	///
	/// This no longer exists as an AST-accessible type, but it's still used for
	/// fields shaped like AnyObject when ObjC interop is enabled.
	BUILTIN_TYPE_NAME_UNKNOWNOBJECT = "Builtin.UnknownObject"
	/// The name of the Builtin type for Vector
	BUILTIN_TYPE_NAME_VEC = "Builtin.Vec"
	/// The name of the Builtin type for SILToken
	BUILTIN_TYPE_NAME_SILTOKEN = "Builtin.SILToken"
	/// The name of the Builtin type for Word
	BUILTIN_TYPE_NAME_WORD = "Builtin.Word"
)

type SpecialPointerAuthDiscriminators uint16

const (
	// All of these values are the stable string hash of the corresponding
	// variable name:
	//   (computeStableStringHash % 65535 + 1)

	/// HeapMetadataHeader::destroy
	DiscHeapDestructor SpecialPointerAuthDiscriminators = 0xbbbf

	/// Type descriptor data pointers.
	DiscTypeDescriptor SpecialPointerAuthDiscriminators = 0xae86

	/// Runtime function variables exported by the runtime.
	DiscRuntimeFunctionEntry SpecialPointerAuthDiscriminators = 0x625b

	/// Protocol conformance descriptors.
	DiscProtocolConformanceDescriptor SpecialPointerAuthDiscriminators = 0xc6eb

	/// Pointer to value witness table stored in type metadata.
	///
	/// Computed with ptrauth_string_discriminator("value_witness_table_t").
	DiscValueWitnessTable SpecialPointerAuthDiscriminators = 0x2e3f

	/// Extended existential type shapes.
	DiscExtendedExistentialTypeShape          SpecialPointerAuthDiscriminators = 0x5a3d // SpecialPointerAuthDiscriminators = 23101
	DiscNonUniqueExtendedExistentialTypeShape SpecialPointerAuthDiscriminators = 0xe798 // SpecialPointerAuthDiscriminators = 59288

	/// Value witness functions.
	DiscInitializeBufferWithCopyOfBuffer   SpecialPointerAuthDiscriminators = 0xda4a
	DiscDestroy                            SpecialPointerAuthDiscriminators = 0x04f8
	DiscInitializeWithCopy                 SpecialPointerAuthDiscriminators = 0xe3ba
	DiscAssignWithCopy                     SpecialPointerAuthDiscriminators = 0x8751
	DiscInitializeWithTake                 SpecialPointerAuthDiscriminators = 0x48d8
	DiscAssignWithTake                     SpecialPointerAuthDiscriminators = 0xefda
	DiscDestroyArray                       SpecialPointerAuthDiscriminators = 0x2398
	DiscInitializeArrayWithCopy            SpecialPointerAuthDiscriminators = 0xa05c
	DiscInitializeArrayWithTakeFrontToBack SpecialPointerAuthDiscriminators = 0x1c3e
	DiscInitializeArrayWithTakeBackToFront SpecialPointerAuthDiscriminators = 0x8dd3
	DiscStoreExtraInhabitant               SpecialPointerAuthDiscriminators = 0x79c5
	DiscGetExtraInhabitantIndex            SpecialPointerAuthDiscriminators = 0x2ca8
	DiscGetEnumTag                         SpecialPointerAuthDiscriminators = 0xa3b5
	DiscDestructiveProjectEnumData         SpecialPointerAuthDiscriminators = 0x041d
	DiscDestructiveInjectEnumTag           SpecialPointerAuthDiscriminators = 0xb2e4
	DiscGetEnumTagSinglePayload            SpecialPointerAuthDiscriminators = 0x60f0
	DiscStoreEnumTagSinglePayload          SpecialPointerAuthDiscriminators = 0xa0d1

	/// KeyPath metadata functions.
	DiscKeyPathDestroy           SpecialPointerAuthDiscriminators = 0x7072
	DiscKeyPathCopy              SpecialPointerAuthDiscriminators = 0x6f66
	DiscKeyPathEquals            SpecialPointerAuthDiscriminators = 0x756e
	DiscKeyPathHash              SpecialPointerAuthDiscriminators = 0x6374
	DiscKeyPathGetter            SpecialPointerAuthDiscriminators = 0x6f72
	DiscKeyPathNonmutatingSetter SpecialPointerAuthDiscriminators = 0x6f70
	DiscKeyPathMutatingSetter    SpecialPointerAuthDiscriminators = 0x7469
	DiscKeyPathGetLayout         SpecialPointerAuthDiscriminators = 0x6373
	DiscKeyPathInitializer       SpecialPointerAuthDiscriminators = 0x6275
	DiscKeyPathMetadataAccessor  SpecialPointerAuthDiscriminators = 0x7474

	/// ObjC bridging entry points.
	DiscObjectiveCTypeDiscriminator                    SpecialPointerAuthDiscriminators = 0x31c3 // SpecialPointerAuthDiscriminators = 12739
	DiscbridgeToObjectiveCDiscriminator                SpecialPointerAuthDiscriminators = 0xbca0 // SpecialPointerAuthDiscriminators = 48288
	DiscforceBridgeFromObjectiveCDiscriminator         SpecialPointerAuthDiscriminators = 0x22fb // SpecialPointerAuthDiscriminators = 8955
	DiscconditionallyBridgeFromObjectiveCDiscriminator SpecialPointerAuthDiscriminators = 0x9a9b // SpecialPointerAuthDiscriminators = 39579

	/// Dynamic replacement pointers.
	DiscDynamicReplacementScope SpecialPointerAuthDiscriminators = 0x48F0 // SpecialPointerAuthDiscriminators = 18672
	DiscDynamicReplacementKey   SpecialPointerAuthDiscriminators = 0x2C7D // SpecialPointerAuthDiscriminators = 11389

	/// Resume functions for yield-once coroutines that yield a single
	/// opaque borrowed/inout value.  These aren't actually hard-coded, but
	/// they're important enough to be worth writing in one place.
	DiscOpaqueReadResumeFunction   SpecialPointerAuthDiscriminators = 56769
	DiscOpaqueModifyResumeFunction SpecialPointerAuthDiscriminators = 3909

	/// ObjC class pointers.
	DiscObjCISA        SpecialPointerAuthDiscriminators = 0x6AE1
	DiscObjCSuperclass SpecialPointerAuthDiscriminators = 0xB5AB

	/// Resilient class stub initializer callback
	DiscResilientClassStubInitCallback SpecialPointerAuthDiscriminators = 0xC671

	/// Jobs, tasks, and continuations.
	DiscJobInvokeFunction                SpecialPointerAuthDiscriminators = 0xcc64 // SpecialPointerAuthDiscriminators = 52324
	DiscTaskResumeFunction               SpecialPointerAuthDiscriminators = 0x2c42 // SpecialPointerAuthDiscriminators = 11330
	DiscTaskResumeContext                SpecialPointerAuthDiscriminators = 0x753a // SpecialPointerAuthDiscriminators = 30010
	DiscAsyncRunAndBlockFunction         SpecialPointerAuthDiscriminators = 0x0f08 // 3848
	DiscAsyncContextParent               SpecialPointerAuthDiscriminators = 0xbda2 // SpecialPointerAuthDiscriminators = 48546
	DiscAsyncContextResume               SpecialPointerAuthDiscriminators = 0xd707 // SpecialPointerAuthDiscriminators = 55047
	DiscAsyncContextYield                SpecialPointerAuthDiscriminators = 0xe207 // SpecialPointerAuthDiscriminators = 57863
	DiscCancellationNotificationFunction SpecialPointerAuthDiscriminators = 0x1933 // SpecialPointerAuthDiscriminators = 6451
	DiscEscalationNotificationFunction   SpecialPointerAuthDiscriminators = 0x5be4 // SpecialPointerAuthDiscriminators = 23524
	DiscAsyncThinNullaryFunction         SpecialPointerAuthDiscriminators = 0x0f08 // SpecialPointerAuthDiscriminators = 3848
	DiscAsyncFutureFunction              SpecialPointerAuthDiscriminators = 0x720f // SpecialPointerAuthDiscriminators = 29199

	/// Swift async context parameter stored in the extended frame info.
	DiscSwiftAsyncContextExtendedFrameEntry SpecialPointerAuthDiscriminators = 0xc31a // SpecialPointerAuthDiscriminators = 49946

	// C type TaskContinuationFunction* descriminator.
	DiscClangTypeTaskContinuationFunction SpecialPointerAuthDiscriminators = 0x2abe // SpecialPointerAuthDiscriminators = 10942

	/// Dispatch integration.
	DiscDispatchInvokeFunction SpecialPointerAuthDiscriminators = 0xf493 // SpecialPointerAuthDiscriminators = 62611

	/// Functions accessible at runtime (i.e. distributed method accessors).
	DiscAccessibleFunctionRecord SpecialPointerAuthDiscriminators = 0x438c // = 17292
)

// TOC is a table of contents for Swift contents.
type TOC struct {
	Builtins             int
	Fields               int
	Types                int
	AssociatedTypes      int
	Protocols            int
	ProtocolConformances int
}

func (t TOC) String() string {
	return fmt.Sprintf(
		"Swift TOC\n"+
			"--------\n"+
			"  __swift5_builtin  = %d\n"+
			"  __swift5_types(2) = %d\n"+
			"  __swift5_protos   = %d\n"+
			"  __swift5_proto    = %d\n",
		t.Builtins, t.Types, t.Protocols, t.ProtocolConformances,
	)
}
