package fixupchains

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/blacktop/go-macho/types"
)

// ErrNoFixupAtOffset is returned when no fixup exists at the specified file offset.
var ErrNoFixupAtOffset = errors.New("no fixup found at offset")

// NewChainedFixups creates a new DyldChainedFixups instance
func NewChainedFixups(lcdat *bytes.Reader, sr *types.MachoReader, bo binary.ByteOrder) *DyldChainedFixups {
	return &DyldChainedFixups{
		r:      lcdat,
		sr:     *sr,
		bo:     bo,
		fixups: make(map[uint64]Fixup),
	}
}

// Parse parses a LC_DYLD_CHAINED_FIXUPS load command
func (dcf *DyldChainedFixups) Parse() (*DyldChainedFixups, error) {
	if err := dcf.ParseStarts(); err != nil {
		return nil, err
	}

	if err := dcf.EnsureImports(); err != nil {
		return nil, fmt.Errorf("failed to parse imports: %v", err)
	}

	if dcf.chainsParsed {
		return dcf, nil
	}

	if dcf.fixups == nil {
		dcf.fixups = make(map[uint64]Fixup)
	} else {
		for k := range dcf.fixups {
			delete(dcf.fixups, k)
		}
	}
	for idx := range dcf.Starts {
		if len(dcf.Starts[idx].Fixups) > 0 {
			dcf.Starts[idx].Fixups = dcf.Starts[idx].Fixups[:0]
		}
	}

	for segIdx, start := range dcf.Starts {
		if start.PageStarts == nil || start.PageCount == 0 {
			continue
		}

		for pageIndex := uint16(0); pageIndex < start.PageCount; pageIndex++ {
			offsetInPage := start.PageStarts[pageIndex]
			if offsetInPage == DYLD_CHAINED_PTR_START_NONE {
				continue
			}
			if offsetInPage&DYLD_CHAINED_PTR_START_MULTI != 0 {
				overflowIndex := offsetInPage & ^DYLD_CHAINED_PTR_START_MULTI
				chainEnd := false
				for !chainEnd {
					chainEnd = (start.PageStarts[overflowIndex] & DYLD_CHAINED_PTR_START_LAST) != 0
					offsetInPage = start.PageStarts[overflowIndex] & ^DYLD_CHAINED_PTR_START_LAST
					if err := dcf.walkDcFixupChain(segIdx, pageIndex, offsetInPage); err != nil {
						return nil, err
					}
					overflowIndex++
				}
				continue
			}
			if err := dcf.walkDcFixupChain(segIdx, pageIndex, offsetInPage); err != nil {
				return nil, err
			}
		}
	}

	dcf.chainsParsed = true

	return dcf, nil
}

// ParseStarts parses the DyldChainedStartsInSegment(s)
func (dcf *DyldChainedFixups) ParseStarts() error {
	if dcf.metadataParsed {
		return nil
	}

	if err := binary.Read(dcf.r, dcf.bo, &dcf.DyldChainedFixupsHeader); err != nil {
		return err
	}

	if _, err := dcf.r.Seek(int64(dcf.StartsOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to starts offset %d: %v", dcf.StartsOffset, err)
	}

	var segCount uint32
	if err := binary.Read(dcf.r, dcf.bo, &segCount); err != nil {
		return err
	}

	dcf.Starts = make([]DyldChainedStarts, segCount)
	segInfoOffsets := make([]uint32, segCount)
	if err := binary.Read(dcf.r, dcf.bo, &segInfoOffsets); err != nil {
		return err
	}

	for segIdx, segInfoOffset := range segInfoOffsets {
		if segInfoOffset == 0 {
			continue
		}

		if _, err := dcf.r.Seek(int64(dcf.StartsOffset+segInfoOffset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to starts offset %d: %v", dcf.StartsOffset+segInfoOffset, err)
		}
		if err := binary.Read(dcf.r, dcf.bo, &dcf.Starts[segIdx].DyldChainedStartsInSegment); err != nil {
			return err
		}

		dcf.Starts[segIdx].PageStarts = make([]DCPtrStart, dcf.Starts[segIdx].PageCount)
		if err := binary.Read(dcf.r, dcf.bo, &dcf.Starts[segIdx].PageStarts); err != nil {
			return err
		}

		if dcf.PointerFormat == 0 {
			dcf.PointerFormat = dcf.Starts[segIdx].PointerFormat
		}
	}

	dcf.metadataParsed = true
	dcf.segmentIndex = nil

	return nil
}

// ResetSegmentIndex invalidates the cached segment lookup index so it can be rebuilt.
func (dcf *DyldChainedFixups) ResetSegmentIndex() {
	dcf.segmentIndex = nil
}

func (dcf *DyldChainedFixups) ensureSegmentIndex() {
	if dcf.segmentIndex != nil {
		return
	}
	index := make([]segmentRange, 0, len(dcf.Starts))
	for idx := range dcf.Starts {
		start := &dcf.Starts[idx]
		if start.PageCount == 0 || start.PageSize == 0 || start.PageStarts == nil {
			continue
		}
		segStart := start.SegmentOffset
		segEnd := segStart + uint64(start.PageCount)*uint64(start.PageSize)
		if segEnd <= segStart {
			continue
		}
		index = append(index, segmentRange{start: segStart, end: segEnd, index: idx})
	}
	sort.Slice(index, func(i, j int) bool {
		if index[i].start == index[j].start {
			return index[i].end < index[j].end
		}
		return index[i].start < index[j].start
	})
	dcf.segmentIndex = index
}

func (dcf *DyldChainedFixups) findSegmentForOffset(offset uint64) *DyldChainedStarts {
	dcf.ensureSegmentIndex()
	if len(dcf.segmentIndex) == 0 {
		return nil
	}
	i := sort.Search(len(dcf.segmentIndex), func(i int) bool {
		return dcf.segmentIndex[i].start > offset
	})
	if i == 0 {
		cover := dcf.segmentIndex[0]
		if offset >= cover.start && offset < cover.end {
			return &dcf.Starts[cover.index]
		}
		return nil
	}
	cover := dcf.segmentIndex[i-1]
	if offset >= cover.start && offset < cover.end {
		return &dcf.Starts[cover.index]
	}
	if i < len(dcf.segmentIndex) {
		next := dcf.segmentIndex[i]
		if offset >= next.start && offset < next.end {
			return &dcf.Starts[next.index]
		}
	}
	return nil
}

// EnsureImports lazily parses the imports table for chained fixups.
func (dcf *DyldChainedFixups) EnsureImports() error {
	if dcf.importsParsed {
		return nil
	}
	if dcf.ImportsCount == 0 {
		dcf.Imports = dcf.Imports[:0]
		dcf.importsParsed = true
		return nil
	}
	if err := dcf.parseImports(); err != nil {
		return err
	}
	dcf.importsParsed = true
	return nil
}

// Rebase returns the rebased target encoded at the given file offset if the location contains
// a chained rebase pointer. The offset must be a file offset matching the coordinate system used
// by dyld chained fixups metadata. The result matches the semantics of IsRebase (runtime offset).
func (dcf *DyldChainedFixups) Rebase(offset uint64, preferredLoadAddress uint64) (uint64, error) {
	start, pageStart, err := dcf.locateStartForOffset(offset)
	if err != nil {
		return 0, err
	}
	if pageStart == DYLD_CHAINED_PTR_START_NONE {
		return 0, fmt.Errorf("offset %#x is not covered by chained rebase fixups", offset)
	}
	dcf.PointerFormat = start.PointerFormat

	raw, err := dcf.readRawPointer(start.PointerFormat, offset)
	if err != nil {
		return 0, err
	}

	return dcf.decodeRebaseTarget(start.PointerFormat, offset, raw, preferredLoadAddress)
}

// RebaseRaw decodes a chained rebase pointer given the file offset and raw pointer bits.
// preferredLoadAddress is used to produce the runtime offset consistent with IsRebase.
func (dcf *DyldChainedFixups) RebaseRaw(offset uint64, raw uint64, preferredLoadAddress uint64) (uint64, error) {
	start, pageStart, err := dcf.locateStartForOffset(offset)
	if err != nil {
		return 0, err
	}
	if pageStart == DYLD_CHAINED_PTR_START_NONE {
		return 0, fmt.Errorf("offset %#x is not covered by chained rebase fixups", offset)
	}
	dcf.PointerFormat = start.PointerFormat

	return dcf.decodeRebaseTarget(start.PointerFormat, offset, raw, preferredLoadAddress)
}

// PointerFormatForOffset reports the chained pointer format that applies to the given file offset.
func (dcf *DyldChainedFixups) PointerFormatForOffset(offset uint64) (DCPtrKind, error) {
	start, pageStart, err := dcf.locateStartForOffset(offset)
	if err != nil {
		return 0, err
	}
	if pageStart == DYLD_CHAINED_PTR_START_NONE {
		return 0, fmt.Errorf("offset %#x is not covered by chained fixups", offset)
	}
	dcf.PointerFormat = start.PointerFormat
	return start.PointerFormat, nil
}

func (dcf *DyldChainedFixups) locateStartForOffset(offset uint64) (*DyldChainedStarts, DCPtrStart, error) {
	if err := dcf.ParseStarts(); err != nil {
		return nil, 0, err
	}

	start := dcf.findSegmentForOffset(offset)
	if start == nil {
		return nil, 0, fmt.Errorf("offset %#x is not covered by chained rebase fixups", offset)
	}

	if start.PageSize == 0 {
		return nil, 0, fmt.Errorf("invalid page size for chained fixups segment covering offset %#x", offset)
	}

	pageSize := uint64(start.PageSize)
	segStart := start.SegmentOffset
	if offset < segStart {
		return nil, 0, fmt.Errorf("offset %#x precedes segment start %#x", offset, segStart)
	}
	pageIndex := (offset - segStart) / pageSize
	if pageIndex >= uint64(len(start.PageStarts)) {
		return nil, 0, fmt.Errorf("offset %#x exceeds page array bounds", offset)
	}

	return start, start.PageStarts[pageIndex], nil
}

func (dcf *DyldChainedFixups) decodeRebaseTarget(format DCPtrKind, offset uint64, raw uint64, preferredLoadAddress uint64) (uint64, error) {
	switch format {
	case DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_USERLAND24,
		DYLD_CHAINED_PTR_ARM64E_KERNEL, DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		if DcpArm64eIsBind(raw) {
			return 0, fmt.Errorf("offset %#x encodes a bind pointer, not a rebase", offset)
		}
		if DcpArm64eIsAuth(raw) {
			rebase := DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: offset}
			return rebase.Target(), nil
		}
		rebase := DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: offset}
		target := rebase.UnpackTarget()
		if format == DYLD_CHAINED_PTR_ARM64E || format == DYLD_CHAINED_PTR_ARM64E_USERLAND24 || format == DYLD_CHAINED_PTR_ARM64E_FIRMWARE {
			target -= preferredLoadAddress
		}
		return target, nil
	case DYLD_CHAINED_PTR_64:
		if Generic64IsBind(raw) {
			return 0, fmt.Errorf("offset %#x encodes a bind pointer, not a rebase", offset)
		}
		rebase := DyldChainedPtr64Rebase{Pointer: raw, Fixup: offset}
		target := rebase.UnpackedTarget()
		target -= preferredLoadAddress
		return target, nil
	case DYLD_CHAINED_PTR_64_OFFSET:
		if Generic64IsBind(raw) {
			return 0, fmt.Errorf("offset %#x encodes a bind pointer, not a rebase", offset)
		}
		rebase := DyldChainedPtr64RebaseOffset{Pointer: raw, Fixup: offset}
		target := rebase.UnpackedTarget()
		target -= preferredLoadAddress
		return target, nil
	case DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		rebase := DyldChainedPtr64KernelCacheRebase{Pointer: raw, Fixup: offset}
		return rebase.Target(), nil
	case DYLD_CHAINED_PTR_32:
		ptr32 := uint32(raw)
		if Generic32IsBind(ptr32) {
			return 0, fmt.Errorf("offset %#x encodes a bind pointer, not a rebase", offset)
		}
		rebase := DyldChainedPtr32Rebase{Pointer: ptr32, Fixup: offset}
		target := rebase.Target()
		return target - preferredLoadAddress, nil
	case DYLD_CHAINED_PTR_32_CACHE:
		rebase := DyldChainedPtr32CacheRebase{Pointer: uint32(raw), Fixup: offset}
		return rebase.Target(), nil
	case DYLD_CHAINED_PTR_32_FIRMWARE:
		rebase := DyldChainedPtr32FirmwareRebase{Pointer: uint32(raw), Fixup: offset}
		return rebase.Target() - preferredLoadAddress, nil
	default:
		return 0, fmt.Errorf("pointer format %d not supported for rebase lookups", format)
	}
}
func (dcf *DyldChainedFixups) walkDcFixupChain(segIdx int, pageIndex uint16, offsetInPage DCPtrStart) error {

	var dcPtr uint32
	var dcPtr64 uint64
	var next uint64

	chainEnd := false
	segOffset := dcf.Starts[segIdx].SegmentOffset
	pageContentStart := segOffset + uint64(pageIndex)*uint64(dcf.Starts[segIdx].PageSize)

	for !chainEnd {
		fixupLocation := pageContentStart + uint64(offsetInPage) + next
		if _, err := dcf.sr.Seek(int64(fixupLocation), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to fixup location %d: %v", fixupLocation, err)
		}

		pointerFormat := dcf.Starts[segIdx].PointerFormat

		switch pointerFormat {
		case DYLD_CHAINED_PTR_32:
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr); err != nil {
				return err
			}
			if Generic32IsBind(dcPtr) {
				bind := DyldChainedPtr32Bind{Pointer: dcPtr, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else {
				rebase := DyldChainedPtr32Rebase{
					Pointer: dcPtr,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.fixups[rebase.Target()] = rebase
			}
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_32_CACHE:
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr); err != nil {
				return err
			}
			rebase := DyldChainedPtr32CacheRebase{
				Pointer: dcPtr,
				Fixup:   fixupLocation,
			}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.fixups[rebase.Target()] = rebase
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_32_FIRMWARE:
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr); err != nil {
				return err
			}
			rebase := DyldChainedPtr32FirmwareRebase{
				Pointer: dcPtr,
				Fixup:   fixupLocation,
			}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.fixups[rebase.Target()] = rebase
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_64: // target is vmaddr
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr64); err != nil {
				return err
			}
			if Generic64IsBind(dcPtr64) {
				bind := DyldChainedPtr64Bind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else {
				rebase := DyldChainedPtr64Rebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.fixups[rebase.Target()] = rebase
			}
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_64_OFFSET: // target is vm offset
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr64); err != nil {
				return err
			}
			// NOTE: the fixup-chains.h seems to indicate that DYLD_CHAINED_PTR_64_OFFSET is a rebase, but can also be a bind
			if Generic64IsBind(dcPtr64) {
				bind := DyldChainedPtr64Bind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else {
				rebase := DyldChainedPtr64RebaseOffset{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.fixups[rebase.Target()] = rebase
			}
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr64); err != nil {
				return err
			}
			rebase := DyldChainedPtr64KernelCacheRebase{
				Pointer: dcPtr64,
				Fixup:   fixupLocation,
			}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.fixups[rebase.Target()] = rebase
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: // stride 1, x86_64 kernel caches
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr64); err != nil {
				return err
			}
			rebase := DyldChainedPtr64KernelCacheRebase{
				Pointer: dcPtr64,
				Fixup:   fixupLocation,
			}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.fixups[rebase.Target()] = rebase
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_ARM64E_KERNEL: // stride 4, unauth target is vm offset
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr64); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				rebase := DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.fixups[rebase.Target()] = rebase
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, authRebase)
				dcf.fixups[authRebase.Target()] = authRebase
			} else {
				bind := DyldChainedPtrArm64eAuthBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_ARM64E_FIRMWARE: // stride 4, unauth target is vmaddr
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr64); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				rebase := DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.fixups[rebase.Target()] = rebase
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, authRebase)
				dcf.fixups[authRebase.Target()] = authRebase
			} else {
				bind := DyldChainedPtrArm64eAuthBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_ARM64E: // stride 8, unauth target is vmaddr
			fallthrough
		case DYLD_CHAINED_PTR_ARM64E_USERLAND: // stride 8, unauth target is vm offset
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr64); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				rebase := DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.fixups[rebase.Target()] = rebase
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, authRebase)
				dcf.fixups[authRebase.Target()] = authRebase
			} else {
				bind := DyldChainedPtrArm64eAuthBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * stride(pointerFormat)
		case DYLD_CHAINED_PTR_ARM64E_USERLAND24: // stride 8, unauth target is vm offset, 24-bit bind
			if err := binary.Read(dcf.sr, dcf.bo, &dcPtr64); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				rebase := DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.fixups[rebase.Target()] = rebase
			} else if DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eAuthBind24{Pointer: dcPtr64, Fixup: fixupLocation}
				bind.Import = dcf.Imports[bind.Ordinal()].Name
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, authRebase)
				dcf.fixups[authRebase.Target()] = authRebase
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eBind24{Pointer: dcPtr64, Fixup: fixupLocation}
				bind.Import = dcf.Imports[bind.Ordinal()].Name
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * stride(pointerFormat)
		default:
			return fmt.Errorf("unknown pointer format %#04X", dcf.Starts[segIdx].PointerFormat)
		}
	}

	return nil
}

func (dcf *DyldChainedFixups) readRawPointer(format DCPtrKind, offset uint64) (uint64, error) {
	size := pointerSize(format)
	if size != 4 && size != 8 {
		return 0, fmt.Errorf("unsupported pointer size for format %d", format)
	}

	// Check if we have a valid reader
	if dcf.sr == nil {
		return 0, fmt.Errorf("no reader available for reading pointer at %#x", offset)
	}

	var buf [8]byte
	n, err := dcf.sr.ReadAt(buf[:size], int64(offset))
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("failed to read pointer at %#x: %w", offset, err)
	}
	if n != size {
		return 0, fmt.Errorf("short read at %#x", offset)
	}
	if size == 4 {
		return uint64(dcf.bo.Uint32(buf[:4])), nil
	}
	return dcf.bo.Uint64(buf[:8]), nil
}

func (dcf *DyldChainedFixups) parseImports() error {

	var imports []Import
	dcf.Imports = dcf.Imports[:0]

	if _, err := dcf.r.Seek(int64(dcf.ImportsOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to imports offset %d: %v", dcf.ImportsOffset, err)
	}

	switch dcf.ImportsFormat {
	case DC_IMPORT:
		ii := make([]DyldChainedImport, dcf.ImportsCount)
		if err := binary.Read(dcf.r, dcf.bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	case DC_IMPORT_ADDEND:
		ii := make([]DyldChainedImportAddend, dcf.ImportsCount)
		if err := binary.Read(dcf.r, dcf.bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	case DC_IMPORT_ADDEND64:
		ii := make([]DyldChainedImportAddend64, dcf.ImportsCount)
		if err := binary.Read(dcf.r, dcf.bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	}

	symbolsPool := io.NewSectionReader(dcf.r, int64(dcf.SymbolsOffset), dcf.r.Size()-int64(dcf.SymbolsOffset))
	for _, i := range imports {
		if _, err := symbolsPool.Seek(int64(i.NameOffset()), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to symbol name offset %d: %v", i.NameOffset(), err)
		}
		s, err := bufio.NewReader(symbolsPool).ReadString('\x00')
		if err != nil {
			return fmt.Errorf("failed to read string at: %d: %v", uint64(dcf.SymbolsOffset)+i.NameOffset(), err)
		}
		dcf.Imports = append(dcf.Imports, DcfImport{
			Name:   strings.Trim(s, "\x00"),
			Import: i,
		})
	}

	return nil
}

func (dcf *DyldChainedFixups) IsRebase(addr, preferredLoadAddress uint64) (uint64, bool) {
	var targetRuntimeOffset uint64
	switch dcf.PointerFormat {
	case DYLD_CHAINED_PTR_ARM64E:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_USERLAND:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_KERNEL:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		if DcpArm64eIsBind(addr) {
			return 0, false
		}
		if DcpArm64eIsAuth(addr) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: addr}.Target(), true
		}
		if DcpArm64eIsRebase(addr) {
			targetRuntimeOffset = DyldChainedPtrArm64eRebase{Pointer: addr}.UnpackTarget()
			if (dcf.PointerFormat == DYLD_CHAINED_PTR_ARM64E) || (dcf.PointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND24) || (dcf.PointerFormat == DYLD_CHAINED_PTR_ARM64E_FIRMWARE) {
				targetRuntimeOffset -= preferredLoadAddress
			}
			return targetRuntimeOffset, true
		}
		return 0, false
	case DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET:
		if Generic64IsBind(addr) {
			return targetRuntimeOffset, false
		}
		targetRuntimeOffset = DyldChainedPtr64Rebase{Pointer: addr}.UnpackedTarget()
		if dcf.PointerFormat == DYLD_CHAINED_PTR_64 || dcf.PointerFormat == DYLD_CHAINED_PTR_64_OFFSET {
			targetRuntimeOffset -= preferredLoadAddress
		}
		return targetRuntimeOffset, true
	case DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		targetRuntimeOffset = DyldChainedPtr64KernelCacheRebase{Pointer: addr}.Target()
		return targetRuntimeOffset, true
	case DYLD_CHAINED_PTR_32:
		if Generic32IsBind(uint32(addr)) {
			return targetRuntimeOffset, false
		}
		targetRuntimeOffset = uint64(DyldChainedPtr32Rebase{Pointer: uint32(addr)}.Target()) - preferredLoadAddress
		return targetRuntimeOffset, true
	case DYLD_CHAINED_PTR_32_FIRMWARE:
		targetRuntimeOffset = uint64(DyldChainedPtr32FirmwareRebase{Pointer: uint32(addr)}.Target()) - preferredLoadAddress
		return targetRuntimeOffset, true
	default:
		return 0, false
	}
}

func (dcf *DyldChainedFixups) IsBind(addr uint64) (*DcfImport, int64, bool) {
	if err := dcf.EnsureImports(); err != nil {
		return nil, 0, false
	}
	if len(dcf.Imports) == 0 {
		return nil, 0, false
	}

	switch dcf.PointerFormat {
	case DYLD_CHAINED_PTR_ARM64E:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_USERLAND:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_KERNEL:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		if !DcpArm64eIsBind(addr) {
			return nil, 0, false
		}
		if DcpArm64eIsAuth(addr) { // is auth-bind
			if dcf.PointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
				ord := DyldChainedPtrArm64eAuthBind24{Pointer: addr}.Ordinal()
				if ord > uint64(len(dcf.Imports)-1) {
					return nil, 0, false // OOB
				}
				return &dcf.Imports[ord], 0, true
			}
			ord := DyldChainedPtrArm64eAuthBind{Pointer: addr}.Ordinal()
			if ord > uint64(len(dcf.Imports)-1) {
				return nil, 0, false // OOB
			}
			return &dcf.Imports[ord], 0, true
		}
		if dcf.PointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
			ord := DyldChainedPtrArm64eAuthBind24{Pointer: addr}.Ordinal()
			if ord > uint64(len(dcf.Imports)-1) {
				return nil, 0, false // OOB
			}
			return &dcf.Imports[ord], DyldChainedPtrArm64eBind{Pointer: addr}.SignExtendedAddend(), true
		}
		ord := DyldChainedPtrArm64eAuthBind{Pointer: addr}.Ordinal()
		if ord > uint64(len(dcf.Imports)-1) {
			return nil, 0, false // OOB
		}
		return &dcf.Imports[ord], DyldChainedPtrArm64eBind{Pointer: addr}.SignExtendedAddend(), true
	case DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET:
		if !Generic64IsBind(addr) {
			return nil, 0, false
		}
		ord := DyldChainedPtr64Bind{Pointer: addr}.Ordinal()
		if ord > uint64(len(dcf.Imports)-1) {
			return nil, 0, false // OOB
		}
		return &dcf.Imports[ord], int64(DyldChainedPtr64Bind{Pointer: addr}.Addend()), true
	case DYLD_CHAINED_PTR_32:
		if !Generic32IsBind(uint32(addr)) {
			return nil, 0, false
		}
		ord := DyldChainedPtr32Bind{Pointer: uint32(addr)}.Ordinal()
		if ord > uint64(len(dcf.Imports)-1) {
			return nil, 0, false // OOB
		}
		return &dcf.Imports[ord], int64(DyldChainedPtr32Bind{Pointer: uint32(addr)}.Addend()), true
	case DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		return nil, 0, false
	default:
		return nil, 0, false
	}
}

// LookupByTarget returns all fixups that point to the given target address.
// This only includes rebases (including auth rebases), not binds.
// Note: This requires the chains to be walked first (calls Parse if needed).
func (dcf *DyldChainedFixups) LookupByTarget(targetOffset uint64) []Fixup {
	// Ensure chains have been walked to populate the fixups map
	if !dcf.chainsParsed {
		if _, err := dcf.Parse(); err != nil {
			return nil
		}
	}

	if dcf.fixups == nil {
		return nil
	}

	// For now, return single fixup as slice for compatibility
	if f, ok := dcf.fixups[targetOffset]; ok {
		return []Fixup{f}
	}
	return nil
}

// LookupByOffset returns the fixup at the given file offset (where the fixup is located).
// Note: This requires the chains to be walked first (calls Parse if needed).
func (dcf *DyldChainedFixups) LookupByOffset(fileOffset uint64) (Fixup, bool) {
	// Ensure chains have been walked to populate the Fixups slices
	if !dcf.chainsParsed {
		if _, err := dcf.Parse(); err != nil {
			return nil, false
		}
	}

	if dcf.Starts == nil {
		return nil, false
	}

	// Search through all segments
	for _, seg := range dcf.Starts {
		for _, fixup := range seg.Fixups {
			if fixup.Offset() == fileOffset {
				return fixup, true
			}
		}
	}
	return nil, false
}

// GetAuthRebase returns the auth rebase at the given target, if it exists.
// This is useful for quickly checking if a pointer is authenticated and getting its diversity.
// Note: This requires the chains to be walked first (calls Parse if needed).
func (dcf *DyldChainedFixups) GetAuthRebase(targetOffset uint64) (Auth, bool) {
	// Ensure chains have been walked to populate the fixups map
	if !dcf.chainsParsed {
		if _, err := dcf.Parse(); err != nil {
			return nil, false
		}
	}

	if fixup, ok := dcf.fixups[targetOffset]; ok {
		if auth, ok := fixup.(Auth); ok {
			return auth, true
		}
	}
	return nil, false
}

func (dcf *DyldChainedFixups) GetFixupAtOffset(offset uint64) (Fixup, error) {
	// Ensure metadata is parsed
	if err := dcf.ParseStarts(); err != nil {
		return nil, fmt.Errorf("failed to parse starts: %w", err)
	}

	// Ensure imports are available for bind fixups
	if err := dcf.EnsureImports(); err != nil {
		return nil, fmt.Errorf("failed to ensure imports: %w", err)
	}

	// Find the segment and page start for this offset
	start, pageStart, err := dcf.locateStartForOffset(offset)
	if err != nil {
		return nil, fmt.Errorf("failed to locate start for offset %#x: %w", offset, err)
	}

	// If page has no fixups, this offset can't contain a fixup
	if pageStart == DYLD_CHAINED_PTR_START_NONE {
		return nil, ErrNoFixupAtOffset
	}

	// Check if this offset is properly aligned for the pointer format
	pointerSize := uint64(pointerSize(start.PointerFormat))
	if offset%pointerSize != 0 {
		return nil, ErrNoFixupAtOffset
	}

	// Calculate page boundaries
	pageSize := uint64(start.PageSize)
	segStart := start.SegmentOffset
	pageIndex := (offset - segStart) / pageSize
	pageContentStart := segStart + pageIndex*pageSize
	offsetInPage := offset - pageContentStart

	// Check if this offset could be part of a chain based on stride alignment
	stride := stride(start.PointerFormat)
	if offsetInPage%stride != 0 {
		return nil, ErrNoFixupAtOffset
	}

	// Now we need to check if this specific offset is actually part of a chain
	// We'll do this by checking if it's reachable from any chain start on this page
	if pageStart&DYLD_CHAINED_PTR_START_MULTI != 0 {
		// Multiple starts in page - check each one
		overflowIndex := pageStart & ^DYLD_CHAINED_PTR_START_MULTI
		for {
			chainEnd := (start.PageStarts[overflowIndex] & DYLD_CHAINED_PTR_START_LAST) != 0
			chainStart := start.PageStarts[overflowIndex] & ^DYLD_CHAINED_PTR_START_LAST

			if found, fixup, err := dcf.checkChainForOffset(start, pageContentStart, uint64(chainStart), offsetInPage); err != nil {
				return nil, err
			} else if found {
				return fixup, nil
			}

			if chainEnd {
				break
			}
			overflowIndex++
		}
	} else {
		// Single chain start in page
		if found, fixup, err := dcf.checkChainForOffset(start, pageContentStart, uint64(pageStart), offsetInPage); err != nil {
			return nil, err
		} else if found {
			return fixup, nil
		}
	}

	return nil, ErrNoFixupAtOffset
}

// checkChainForOffset walks a single chain to see if it contains the target offset.
// Returns (true, fixup, nil) if found, (false, nil, nil) if not found, or (false, nil, err) on error.
func (dcf *DyldChainedFixups) checkChainForOffset(start *DyldChainedStarts, pageContentStart, chainStartOffset, targetOffsetInPage uint64) (bool, Fixup, error) {
	currentOffset := chainStartOffset
	stride := stride(start.PointerFormat)

	for {
		// Check if we've reached our target offset
		if currentOffset == targetOffsetInPage {
			// Read and decode the fixup at this location
			fixupLocation := pageContentStart + currentOffset
			fixup, err := dcf.readAndDecodeFixup(start.PointerFormat, fixupLocation)
			return true, fixup, err
		}

		// Read the current pointer to get the next offset
		fixupLocation := pageContentStart + currentOffset
		raw, err := dcf.readRawPointer(start.PointerFormat, fixupLocation)
		if err != nil {
			return false, nil, fmt.Errorf("failed to read pointer at %#x: %w", fixupLocation, err)
		}

		// Calculate next offset based on pointer format
		var next uint64
		switch start.PointerFormat {
		case DYLD_CHAINED_PTR_32, DYLD_CHAINED_PTR_32_CACHE, DYLD_CHAINED_PTR_32_FIRMWARE:
			next = Generic32Next(uint32(raw))
		case DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			next = Generic64Next(raw)
		case DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_USERLAND24,
			DYLD_CHAINED_PTR_ARM64E_KERNEL, DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
			next = DcpArm64eNext(raw)
		default:
			return false, nil, fmt.Errorf("unsupported pointer format %d", start.PointerFormat)
		}

		// If next is 0, we've reached the end of the chain
		if next == 0 {
			break
		}

		// Move to next fixup in chain
		currentOffset += next * stride

		// Safety check to prevent infinite loops
		if currentOffset > uint64(start.PageSize) {
			break
		}
	}

	return false, nil, nil
}

// readAndDecodeFixup reads the raw pointer at the given location and decodes it into the appropriate Fixup type.
func (dcf *DyldChainedFixups) readAndDecodeFixup(format DCPtrKind, fixupLocation uint64) (Fixup, error) {
	raw, err := dcf.readRawPointer(format, fixupLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to read raw pointer: %w", err)
	}

	// Decode based on pointer format
	switch format {
	case DYLD_CHAINED_PTR_32:
		ptr32 := uint32(raw)
		if Generic32IsBind(ptr32) {
			bind := DyldChainedPtr32Bind{Pointer: ptr32, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		}
		return DyldChainedPtr32Rebase{Pointer: ptr32, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_32_CACHE:
		return DyldChainedPtr32CacheRebase{Pointer: uint32(raw), Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_32_FIRMWARE:
		return DyldChainedPtr32FirmwareRebase{Pointer: uint32(raw), Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_64:
		if Generic64IsBind(raw) {
			bind := DyldChainedPtr64Bind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		}
		return DyldChainedPtr64Rebase{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_64_OFFSET:
		if Generic64IsBind(raw) {
			bind := DyldChainedPtr64Bind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		}
		return DyldChainedPtr64RebaseOffset{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		return DyldChainedPtr64KernelCacheRebase{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_ARM64E_KERNEL:
		if !DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		} else if !DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else {
			bind := DyldChainedPtrArm64eAuthBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		}

	case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		if !DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		} else if !DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else {
			bind := DyldChainedPtrArm64eAuthBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		}

	case DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND:
		if !DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		} else if !DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else {
			bind := DyldChainedPtrArm64eAuthBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		}

	case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		if !DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eAuthBind24{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		} else if !DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eBind24{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
			}
			return bind, nil
		}

	default:
		return nil, fmt.Errorf("unsupported pointer format %d for fixup decoding", format)
	}

	return nil, fmt.Errorf("failed to decode fixup for format %d", format)
}
