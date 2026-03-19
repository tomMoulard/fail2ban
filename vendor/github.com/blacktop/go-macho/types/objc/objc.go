package objc

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/blacktop/go-macho/types"
)

const IsDyldPreoptimized = 1 << 7

const (
	WORD_SHIFT = 3 // assuming 64-bit pointers (log2(8))
)

type Toc struct {
	ClassList        uint64
	NonLazyClassList uint64
	CatList          uint64
	NonLazyCatList   uint64
	ProtoList        uint64
	ClassRefs        uint64
	SuperRefs        uint64
	SelRefs          uint64
	Stubs            uint64
}

func (i Toc) String() string {
	return fmt.Sprintf(
		"ObjC TOC\n"+
			"--------\n"+
			"  __objc_classlist  = %d\n"+
			"  __objc_nlclslist  = %d\n"+
			"  __objc_catlist    = %d\n"+
			"  __objc_nlcatlist  = %d\n"+
			"  __objc_protolist  = %d\n"+
			"  __objc_classrefs  = %d\n"+
			"  __objc_superrefs  = %d\n"+
			"  __objc_selrefs    = %d\n",
		// "  __objc_stubs      = %d\n",
		i.ClassList,
		i.NonLazyClassList,
		i.CatList,
		i.NonLazyCatList,
		i.ProtoList,
		i.ClassRefs,
		i.SuperRefs,
		i.SelRefs,
		// i.Stubs,
	)
}

type ImageInfoFlag uint32

const (
	DyldCategoriesOptimized    ImageInfoFlag = 1 << 0 // categories were optimized by dyld
	SupportsGC                 ImageInfoFlag = 1 << 1 // image supports GC
	RequiresGC                 ImageInfoFlag = 1 << 2 // image requires GC
	OptimizedByDyld            ImageInfoFlag = 1 << 3 // image is from an optimized shared cache
	SignedClassRO              ImageInfoFlag = 1 << 4 // class_ro_t pointers are signed
	IsSimulated                ImageInfoFlag = 1 << 5 // image compiled for a simulator platform
	HasCategoryClassProperties ImageInfoFlag = 1 << 6 // class properties in category_t

	// OptimizedByDyldClosure is currently set by dyld, but we don't use it
	// anymore. Instead use
	// _dyld_objc_notify_mapped_info::dyldObjCRefsOptimized.
	// Once dyld stops setting it, it will be unused.
	OptimizedByDyldClosure ImageInfoFlag = 1 << 7 // dyld (not the shared cache) optimized this.

	// 1 byte Swift unstable ABI version number
	SwiftUnstableVersionMaskShift = 8
	SwiftUnstableVersionMask      = 0xff << SwiftUnstableVersionMaskShift

	// 2 byte Swift stable ABI version number
	SwiftStableVersionMaskShift = 16
	SwiftStableVersionMask      = 0xffff << SwiftStableVersionMaskShift
)

// DyldCategoriesOptimized
//
//	Indicates that dyld preattached categories from this image in the shared
//	cache and we don't need to scan those categories ourselves. Note: this bit
//	used to be used for the IsReplacement flag used for Fix & Continue. That
//	usage is obsolete.
func (f ImageInfoFlag) DyldCategoriesOptimized() bool {
	return f&DyldCategoriesOptimized != 0
}

// SupportsGC
//
//	App: GC is required. Framework: GC is supported but not required.
func (f ImageInfoFlag) SupportsGC() bool {
	return f&SupportsGC != 0
}

// RequiresGC
//
//	Framework: GC is required.
func (f ImageInfoFlag) RequiresGC() bool {
	return f&RequiresGC != 0
}

// OptimizedByDyld
//
//	Assorted metadata precooked in the dyld shared cache.
//	Never set for images outside the shared cache file itself.
func (f ImageInfoFlag) OptimizedByDyld() bool {
	return f&OptimizedByDyld != 0
}
func (f ImageInfoFlag) SignedClassRO() bool {
	return f&SignedClassRO != 0
}

// IsSimulated
//
//	Image was compiled for a simulator platform. Not used by the runtime.
func (f ImageInfoFlag) IsSimulated() bool {
	return f&IsSimulated != 0
}

// HasClassProperties
//
//	New ABI: category_t.classProperties fields are present.
//	Old ABI: Set by some compilers. Not used by the runtime.
func (f ImageInfoFlag) HasCategoryClassProperties() bool {
	return f&HasCategoryClassProperties != 0
}
func (f ImageInfoFlag) OptimizedByDyldClosure() bool {
	return f&OptimizedByDyldClosure != 0
}

func (f ImageInfoFlag) List() []string {
	var flags []string
	if (f & DyldCategoriesOptimized) != 0 {
		flags = append(flags, "DyldCategoriesOptimized")
	}
	if (f & SupportsGC) != 0 {
		flags = append(flags, "SupportsGC")
	}
	if (f & RequiresGC) != 0 {
		flags = append(flags, "RequiresGC")
	}
	if (f & OptimizedByDyld) != 0 {
		flags = append(flags, "OptimizedByDyld")
	}
	if (f & SignedClassRO) != 0 {
		flags = append(flags, "SignedClassRO")
	}
	if (f & IsSimulated) != 0 {
		flags = append(flags, "IsSimulated")
	}
	if (f & HasCategoryClassProperties) != 0 {
		flags = append(flags, "HasCategoryClassProperties")
	}
	if (f & OptimizedByDyldClosure) != 0 {
		flags = append(flags, "OptimizedByDyldClosure")
	}
	return flags
}

func (f ImageInfoFlag) String() string {
	return fmt.Sprintf(
		"Flags = %s\n"+
			"Swift = %s\n",
		strings.Join(f.List(), ", "),
		f.SwiftVersion(),
	)
}

func (f ImageInfoFlag) SwiftVersion() string {
	// TODO: I noticed there is some flags higher than swift version
	// (Console has 84019008, which is a version of 0x502)
	swiftVersion := (f >> 8) & 0xff
	if swiftVersion != 0 {
		switch swiftVersion {
		case 1:
			return "Swift 1.0"
		case 2:
			return "Swift 1.2"
		case 3:
			return "Swift 2.0"
		case 4:
			return "Swift 3.0"
		case 5:
			return "Swift 4.0"
		case 6:
			return "Swift 4.1/4.2"
		case 7:
			return "Swift 5 or later"
		default:
			return fmt.Sprintf("Unknown future Swift version: %d", swiftVersion)
		}
	}
	return "not swift"
}

const dyldPreoptimized = 1 << 7

type ImageInfo struct {
	Version uint32
	Flags   ImageInfoFlag
}

func (i ImageInfo) IsDyldPreoptimized() bool {
	return (i.Flags & dyldPreoptimized) != 0
}

func (i ImageInfo) HasSwift() bool {
	return (i.Flags>>8)&0xff != 0
}

const (
	bigSignedMethodListFlag              uint64 = 0x8000000000000000
	relativeMethodSelectorsAreDirectFlag uint32 = 0x40000000
	smallMethodListFlag                  uint32 = 0x80000000
	METHOD_LIST_FLAGS_MASK               uint32 = 0xffff0003
	// The size is bits 2 through 16 of the entsize field
	// The low 2 bits are uniqued/sorted as above.  The upper 16-bits
	// are reserved for other flags
	METHOD_LIST_SIZE_MASK uint32 = 0x0000FFFC
)

type MLFlags uint32

const (
	METHOD_LIST_IS_UNIQUED MLFlags = 1
	METHOD_LIST_IS_SORTED  MLFlags = 2
	METHOD_LIST_FIXED_UP   MLFlags = 3
)

type MLKind uint32

const (
	kindMask = 3
	// Note: method_invoke detects small methods by detecting 1 in the low
	// bit. Any change to that will require a corresponding change to
	// method_invoke.
	big MLKind = 0
	// `small` encompasses both small and small direct methods. We
	// distinguish those cases by doing a range check against the shared
	// cache.
	small       MLKind = 1
	bigSigned   MLKind = 2
	bigStripped MLKind = 3 // ***HACK: This is a TEMPORARY HACK FOR EXCLAVEKIT. It MUST go away.
)

type methodPtr uint64

func (m methodPtr) Kind() MLKind {
	return MLKind(m & kindMask)
}
func (m methodPtr) Pointer() uint64 {
	return uint64(m & ^methodPtr(kindMask))
}

type EntryList struct {
	Entsize uint32
	Count   uint32
}

func (el EntryList) String() string {
	return fmt.Sprintf("ent_size: %d, count: %d", el.Entsize, el.Count)
}

type Entry int64

func (e Entry) ImageIndex() uint16 {
	return uint16(e & 0xFFFF)
}
func (e Entry) MethodListOffset() int64 {
	return int64(e >> 16)
}
func (e Entry) String() string {
	return fmt.Sprintf("image_index: %d, method_list_offset: %d", e.ImageIndex(), e.MethodListOffset())
}

type MethodList struct {
	EntSizeAndFlags uint32
	Count           uint32
	// Space           uint32
	// MethodArrayBase uint64
}

func (ml MethodList) IsUniqued() bool {
	return (ml.Flags() & METHOD_LIST_IS_UNIQUED) == 1
}
func (ml MethodList) Sorted() bool {
	return (ml.Flags() & METHOD_LIST_IS_SORTED) == 1
}
func (ml MethodList) FixedUp() bool {
	return (ml.Flags() & METHOD_LIST_FIXED_UP) == 1
}
func (ml MethodList) UsesDirectOffsetsToSelectors() bool {
	return (ml.EntSizeAndFlags & relativeMethodSelectorsAreDirectFlag) != 0
}
func (ml MethodList) UsesRelativeOffsets() bool {
	return (ml.EntSizeAndFlags & smallMethodListFlag) != 0
}
func (ml MethodList) EntSize() uint32 {
	return ml.EntSizeAndFlags & METHOD_LIST_SIZE_MASK
}
func (ml MethodList) Flags() MLFlags {
	return MLFlags(ml.EntSizeAndFlags & METHOD_LIST_FLAGS_MASK)
}
func (ml MethodList) String() string {
	offType := "direct"
	if ml.UsesRelativeOffsets() {
		offType = "relative"
	}
	return fmt.Sprintf("count=%d, entsiz_flags=%#x, entrysize=%d, flags=%#x, fixed_up=%t, sorted=%t, uniqued=%t, type=%s",
		ml.Count,
		ml.EntSizeAndFlags,
		ml.EntSize(),
		ml.Flags(),
		ml.FixedUp(),
		ml.Sorted(),
		ml.IsUniqued(),
		offType)
}

type MethodT struct {
	NameVMAddr  uint64 // SEL
	TypesVMAddr uint64 // const char *
	ImpVMAddr   uint64 // IMP
}

type RelativeMethodT struct {
	NameOffset  int32 // SEL
	TypesOffset int32 // const char *
	ImpOffset   int32 // IMP
}

type Method struct {
	NameVMAddr  uint64 // & SEL
	TypesVMAddr uint64 // & const char *
	ImpVMAddr   uint64 // & IMP

	// We also need to know where the reference to the nameVMAddr was
	// This is so that we know how to rebind that location
	NameLocationVMAddr uint64
	Name               string
	Types              string
}

// NumberOfArguments returns the number of method arguments
func (m *Method) NumberOfArguments() int {
	if m == nil {
		return 0
	}
	return getNumberOfArguments(m.Types)
}

// ReturnType returns the method's return type
func (m *Method) ReturnType() string {
	return getReturnType(m.Types)
}

func (m *Method) ArgumentType(index int) string {
	args := getArguments(m.Types)
	if 0 < len(args) && index <= len(args) {
		return args[index].DecType
	}
	return "<error>"
}

type PropertyList struct {
	EntSize uint32
	Count   uint32
}

type PropertyT struct {
	NameVMAddr       uint64
	AttributesVMAddr uint64
}

type Property struct {
	PropertyT
	Name              string
	EncodedAttributes string
}

func (p *Property) Type() string {
	return getPropertyType(p.EncodedAttributes)
}
func (p *Property) Attributes() (string, bool) {
	return getPropertyAttributeTypes(p.EncodedAttributes)
}

// CFString object in a 64-bit MachO file
type CFString struct {
	Name    string
	ISA     string
	Address uint64
	Class   *Class
	CFString64Type
}

// CFString64Type object in a 64-bit MachO file
type CFString64Type struct {
	IsaVMAddr uint64 // class64_t * (64-bit pointer)
	Info      uint64 // flag bits
	Data      uint64 // char * (64-bit pointer)
	Length    uint64 // number of non-NULL characters in above
}

// CFString encoding constants (derived from Info field)
const (
	CFStringEncodingMask    = 0x0FF0 // mask to extract encoding from Info field
	CFStringEncodingASCII   = 0x07C8 // UTF-8/ASCII encoding
	CFStringEncodingUnicode = 0x07D0 // UTF-16LE encoding
)

// Encoding returns the string encoding type from the CFString Info field
func (c CFString64Type) Encoding() uint64 {
	return c.Info & CFStringEncodingMask
}

// IsUTF16 returns true if the CFString uses UTF-16 encoding
func (c CFString64Type) IsUTF16() bool {
	return c.Encoding() == CFStringEncodingUnicode
}

const (
	FAST_IS_SWIFT_LEGACY = 1 << 0 // < 5
	FAST_IS_SWIFT_STABLE = 1 << 1 // 5.X
	FAST_HAS_DEFAULT_RR  = 1 << 2
	IsSwiftPreStableABI  = 0x1
)

const (
	FAST_DATA_MASK  = 0xfffffffc
	FAST_FLAGS_MASK = 0x00000003

	FAST_DATA_MASK64_IPHONE = 0x0000007ffffffff8
	FAST_DATA_MASK64        = 0x00007ffffffffff8
	FAST_FLAGS_MASK64       = 0x0000000000000007
	FAST_IS_RW_POINTER64    = 0x8000000000000000
)

type IvarList struct {
	EntSize uint32
	Count   uint32
}

type IvarT struct {
	Offset       uint64 // uint32_t*  (uint64_t* on x86_64)
	NameVMAddr   uint64 // const char*
	TypesVMAddr  uint64 // const char*
	AlignmentRaw uint32
	Size         uint32
}

func (i IvarT) Alignment() uint32 {
	if i.AlignmentRaw == ^uint32(0) {
		return 1 << WORD_SHIFT
	}
	return 1 << i.AlignmentRaw
}

type Ivar struct {
	Name   string
	Type   string
	Offset uint32
	IvarT
}

func replaceLast(s, old, new string) string {
	if i := strings.LastIndex(s, old); i != -1 {
		return s[:i] + new + s[i+len(old):]
	}
	return s
}

func (i *Ivar) dump(verbose, addrs bool) string {
	var addr string
	if addrs {
		addr = fmt.Sprintf("\t// %-7s %#x", fmt.Sprintf("+%#x", i.Size), i.Offset)
	}
	if verbose {
		ivtype := getIVarType(i.Type)
		if regexp.MustCompile(`x(\s?)(\[[0-9]+\]|:[0-9]+) $`).MatchString(ivtype) { // array|bitfield special case
			ivtype = strings.TrimSpace(replaceLast(ivtype, "x", i.Name))
			return fmt.Sprintf("%s;%s", ivtype, addr)
		}
		return fmt.Sprintf("%s%s;%s", ivtype, i.Name, addr)
	}
	return fmt.Sprintf("%s %s;%s", i.Type, i.Name, addr)
}

func (i *Ivar) String() string {
	return i.dump(false, false)
}
func (i *Ivar) Verbose() string {
	return i.dump(true, false)
}
func (i *Ivar) WithAddrs() string {
	return i.dump(true, true)
}

type Selector struct {
	VMAddr uint64
	Name   string
}

type OptOffsets struct {
	MethodNameStart     uint64
	MethodNameEnd       uint64
	InlinedMethodsStart uint64
	InlinedMethodsEnd   uint64
}

type OptOffsets2 struct {
	Version             uint64
	MethodNameStart     uint64
	MethodNameEnd       uint64
	InlinedMethodsStart uint64
	InlinedMethodsEnd   uint64
}

type ImpCacheV1 struct {
	ImpCacheHeaderV1
	Entries []ImpCacheEntryV1
}
type ImpCacheEntryV1 struct {
	SelOffset uint32
	ImpOffset uint32
}

type ImpCacheHeaderV1 struct {
	FallbackClassOffset int32
	Info                uint32
	// uint32_t cache_shift :  5
	// uint32_t cache_mask  : 11
	// uint32_t occupied    : 14
	// uint32_t has_inlines :  1
	// uint32_t bit_one     :  1
}

func (p ImpCacheHeaderV1) CacheShift() uint32 {
	return uint32(types.ExtractBits(uint64(p.Info), 0, 5))
}
func (p ImpCacheHeaderV1) CacheMask() uint32 {
	return uint32(types.ExtractBits(uint64(p.Info), 5, 11))
}
func (p ImpCacheHeaderV1) Occupied() uint32 {
	return uint32(types.ExtractBits(uint64(p.Info), 16, 14))
}
func (p ImpCacheHeaderV1) HasInlines() bool {
	return types.ExtractBits(uint64(p.Info), 30, 1) != 0
}
func (p ImpCacheHeaderV1) BitOne() bool {
	return types.ExtractBits(uint64(p.Info), 31, 1) != 0
}
func (p ImpCacheHeaderV1) Capacity() uint32 {
	return p.CacheMask() + 1
}
func (p ImpCacheHeaderV1) String() string {
	return fmt.Sprintf("cache_shift: %d, cache_mask: %d, occupied: %d, has_inlines: %t, bit_one: %t",
		p.CacheShift(),
		p.CacheMask(),
		p.Occupied(),
		p.HasInlines(),
		p.BitOne())
}

type Stub struct {
	Name        string
	SelectorRef uint64
}

type IntObj struct {
	ISA          uint64
	EncodingAddr uint64
	Number       uint64
}

type ImpCacheV2 struct {
	ImpCacheHeaderV2
	Entries []ImpCacheEntryV2
}
type ImpCacheEntryV2 uint64

func (e ImpCacheEntryV2) GetImpOffset() int64 {
	return int64(types.ExtractBits(uint64(e), 0, 38))
}
func (e ImpCacheEntryV2) GetSelOffset() uint64 {
	return types.ExtractBits(uint64(e), 38, 26)
}

type ImpCacheHeaderV2 struct { // FIXME: 64bit new version
	FallbackClassOffset int64
	Info                uint64
	// int64_t  fallback_class_offset;
	// union {
	//     struct {
	//         uint16_t shift       :  5;
	//         uint16_t mask        : 11;
	//     };
	//     uint16_t hash_params;
	// };
	// uint16_t occupied    : 14;
	// uint16_t has_inlines :  1;
	// uint16_t padding     :  1;
	// uint32_t unused      : 31;
	// uint32_t bit_one     :  1;
	// preopt_cache_entry_t entries[];
}

func (p ImpCacheHeaderV2) CacheShift() uint32 {
	return uint32(types.ExtractBits(uint64(p.Info), 0, 5))
}
func (p ImpCacheHeaderV2) CacheMask() uint32 {
	return uint32(types.ExtractBits(uint64(p.Info), 5, 11))
}
func (p ImpCacheHeaderV2) Occupied() uint32 {
	return uint32(types.ExtractBits(uint64(p.Info), 16, 14))
}
func (p ImpCacheHeaderV2) HasInlines() bool {
	return types.ExtractBits(uint64(p.Info), 30, 1) != 0
}
func (p ImpCacheHeaderV2) BitOne() bool {
	return types.ExtractBits(uint64(p.Info), 63, 1) != 0
}
func (p ImpCacheHeaderV2) Capacity() uint32 {
	return p.CacheMask() + 1
}
func (p ImpCacheHeaderV2) String() string {
	return fmt.Sprintf("cache_shift: %d, cache_mask: %d, occupied: %d, has_inlines: %t, bit_one: %t",
		p.CacheShift(),
		p.CacheMask(),
		p.Occupied(),
		p.HasInlines(),
		p.BitOne())
}
