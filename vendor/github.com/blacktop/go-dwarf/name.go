package dwarf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// DWARFv5 .debug_names section format constants
const (
	// Format values for Header.Format
	dwarfFormat32bit = 0x00
	dwarfFormat64bit = 0x01
	// Attribute form encodings
	dwFormImplicitConst = 0x21
	nameIndexSignature  = 0x444E414D // "DNAM" in ASCII
)

// dbgNamesHeader represents the header of a DWARF v5 .debug_names section
type dbgNamesHeader struct {
	UnitLength           uint64 // Length of the unit, not including this field
	Version              uint16 // Version (5)
	Padding              uint16 // Padding
	CompUnitCount        uint32 // Number of CUs
	LocalTypeUnitCount   uint32 // Number of local TUs
	ForeignTypeUnitCount uint32 // Number of foreign TUs
	BucketCount          uint32 // Number of hash buckets
	NameCount            uint32 // Number of unique names
	AbbrevTableSize      uint32 // Size in bytes of the abbreviations table
	AugmentationLen      uint32 // Length of augmentation string
	Augmentation         string // Augmentation string
}

// Add this struct to store offsets
type debugNamesOffsets struct {
	CUsBase           int64
	BucketsBase       int64
	HashesBase        int64
	StringOffsetsBase int64
	EntryOffsetsBase  int64
	EntriesBase       int64
}

// DebugNames represents the DWARF v5 .debug_names section
type DebugNames struct {
	Header         dbgNamesHeader
	CompUnits      []uint64       // CU offsets
	LocalTypes     []uint64       // Local TU offsets
	ForeignTypes   []uint64       // Foreign TU offsets
	BucketTable    []uint32       // Hash lookup table (hash buckets)
	NameTable      []uint32       // String offsets
	StringOffsets  []uint32       // String offsets
	EntryOffsets   []uint32       // Entry offsets
	AbbrevTable    abbrevTable    // Abbreviation table
	CompUnitsMap   map[uint64]int // Map for quick CU lookup
	LocalTypesMap  map[uint64]int // Map for quick local TU lookup
	ForeignTypeMap map[uint64]int // Map for quick foreign TU lookup

	offsets *debugNamesOffsets
	data    *bytes.Reader // Original data for parsing
}

// DebugNameEntry represents an entry in the .debug_names section
type DebugNameEntry struct {
	DIEOffset Offset // Offset of the DIE in the .debug_info section
	CUOffset  Offset // compilation unit entry offset
	CUIndex   uint64 // Index into the compilation unit list
	Tag       Tag    // The tag of the DIE
	ParentIdx Offset // Parent index - only used if IndexedParent is set
}

// Add this function to calculate offsets
func findDebugNamesOffsets(endOfHeaderOffset int64, headerFormat byte, header dbgNamesHeader) *debugNamesOffsets {
	dwarfSize := getDwarfOffsetByteSize(headerFormat)
	ret := debugNamesOffsets{}

	ret.CUsBase = endOfHeaderOffset
	ret.BucketsBase = ret.CUsBase +
		int64(header.CompUnitCount)*int64(dwarfSize) +
		int64(header.LocalTypeUnitCount)*int64(dwarfSize) +
		int64(header.ForeignTypeUnitCount)*8

	ret.HashesBase = ret.BucketsBase + int64(header.BucketCount)*4

	var hashTableSize int64 = 0
	if header.BucketCount > 0 {
		hashTableSize = int64(header.NameCount) * 4
	}
	ret.StringOffsetsBase = ret.HashesBase + hashTableSize

	ret.EntryOffsetsBase = ret.StringOffsetsBase + int64(header.NameCount)*int64(dwarfSize)
	ret.EntriesBase = ret.EntryOffsetsBase + int64(header.NameCount)*int64(dwarfSize) + int64(header.AbbrevTableSize)

	return &ret
}

func (d *Data) parseNames(name string, hashes []byte) error {
	d.names = &DebugNames{
		data: bytes.NewReader(hashes),
	}

	// Parse header
	var unitLength uint32
	if err := binary.Read(d.names.data, d.order, &unitLength); err != nil {
		return err
	}

	var headerFormat byte = dwarfFormat32bit
	if unitLength == 0xffffffff {
		headerFormat = dwarfFormat64bit
		// Read 64-bit length
		var length64 uint64
		if err := binary.Read(d.names.data, d.order, &length64); err != nil {
			return err
		}
		d.names.Header.UnitLength = length64
	} else {
		d.names.Header.UnitLength = uint64(unitLength)
	}

	// Read version (must be 5 for .debug_names)
	if err := binary.Read(d.names.data, d.order, &d.names.Header.Version); err != nil {
		return err
	}
	if d.names.Header.Version != 5 {
		return fmt.Errorf(".debug_names: unsupported version %d", d.names.Header.Version)
	}
	if err := binary.Read(d.names.data, d.order, &d.names.Header.Padding); err != nil {
		return err
	}
	if err := binary.Read(d.names.data, d.order, &d.names.Header.CompUnitCount); err != nil {
		return err
	}
	if err := binary.Read(d.names.data, d.order, &d.names.Header.LocalTypeUnitCount); err != nil {
		return err
	}
	if err := binary.Read(d.names.data, d.order, &d.names.Header.ForeignTypeUnitCount); err != nil {
		return err
	}
	if err := binary.Read(d.names.data, d.order, &d.names.Header.BucketCount); err != nil {
		return err
	}
	if err := binary.Read(d.names.data, d.order, &d.names.Header.NameCount); err != nil {
		return err
	}
	if err := binary.Read(d.names.data, d.order, &d.names.Header.AbbrevTableSize); err != nil {
		return err
	}
	if err := binary.Read(d.names.data, d.order, &d.names.Header.AugmentationLen); err != nil {
		return err
	}

	// Read augmentation string if present
	if d.names.Header.AugmentationLen > 0 {
		augBytes := make([]byte, d.names.Header.AugmentationLen)
		if err := binary.Read(d.names.data, d.order, &augBytes); err != nil {
			return err
		}
		d.names.Header.Augmentation = string(augBytes)
	}

	// calculate the offsets
	headerEndOffset, _ := d.names.data.Seek(0, io.SeekCurrent)
	d.names.offsets = findDebugNamesOffsets(headerEndOffset, headerFormat, d.names.Header)

	// Parse compilation unit offsets
	d.names.CompUnits = make([]uint64, d.names.Header.CompUnitCount)
	d.names.CompUnitsMap = make(map[uint64]int, d.names.Header.CompUnitCount)
	for i := uint32(0); i < d.names.Header.CompUnitCount; i++ {
		if headerFormat == dwarfFormat32bit {
			var offset uint32
			if err := binary.Read(d.names.data, d.order, &offset); err != nil {
				return err
			}
			d.names.CompUnits[i] = uint64(offset)
		} else {
			var offset uint64
			if err := binary.Read(d.names.data, d.order, &offset); err != nil {
				return err
			}
			d.names.CompUnits[i] = offset
		}
		d.names.CompUnitsMap[d.names.CompUnits[i]] = int(i)
	}

	// Parse local type unit offsets
	d.names.LocalTypes = make([]uint64, d.names.Header.LocalTypeUnitCount)
	d.names.LocalTypesMap = make(map[uint64]int, d.names.Header.LocalTypeUnitCount)
	for i := uint32(0); i < d.names.Header.LocalTypeUnitCount; i++ {
		if headerFormat == dwarfFormat32bit {
			var offset uint32
			if err := binary.Read(d.names.data, d.order, &offset); err != nil {
				return err
			}
			d.names.LocalTypes[i] = uint64(offset)
		} else {
			var offset uint64
			if err := binary.Read(d.names.data, d.order, &offset); err != nil {
				return err
			}
			d.names.LocalTypes[i] = offset
		}
		d.names.LocalTypesMap[d.names.LocalTypes[i]] = int(i)
	}

	// Parse foreign type unit offsets (signatures)
	d.names.ForeignTypes = make([]uint64, d.names.Header.ForeignTypeUnitCount)
	d.names.ForeignTypeMap = make(map[uint64]int, d.names.Header.ForeignTypeUnitCount)
	for i := uint32(0); i < d.names.Header.ForeignTypeUnitCount; i++ {
		var signature uint64
		if err := binary.Read(d.names.data, d.order, &signature); err != nil {
			return err
		}
		d.names.ForeignTypes[i] = signature
		d.names.ForeignTypeMap[d.names.ForeignTypes[i]] = int(i)
	}

	// The hash lookup table
	d.names.BucketTable = make([]uint32, d.names.Header.BucketCount)
	if err := binary.Read(d.names.data, d.order, &d.names.BucketTable); err != nil {
		return err
	}

	// Parse name table (string offsets)
	d.names.NameTable = make([]uint32, d.names.Header.NameCount)
	if err := binary.Read(d.names.data, d.order, &d.names.NameTable); err != nil {
		return err
	}

	// Parse string offsets
	d.names.StringOffsets = make([]uint32, d.names.Header.NameCount)
	if err := binary.Read(d.names.data, d.order, &d.names.StringOffsets); err != nil {
		return err
	}

	// Parse entry offsets
	d.names.EntryOffsets = make([]uint32, d.names.Header.NameCount)
	if err := binary.Read(d.names.data, d.order, &d.names.EntryOffsets); err != nil {
		return err
	}

	// Parse abbreviation table
	// Get the current position, which is the start of the abbreviation table
	abbrevdata := make([]byte, d.names.Header.AbbrevTableSize)
	err := binary.Read(d.names.data, d.order, &abbrevdata)
	if err != nil {
		return err
	}
	d.names.AbbrevTable, err = d.parseDbgAbbrev(abbrevdata, 5)
	if err != nil {
		return err
	}

	return nil
}

func (d *Data) parseDbgAbbrev(data []byte, vers int) (abbrevTable, error) {
	b := makeBuf(d, unknownFormat{}, "dbg_abbrev", 0, data)

	// Error handling is simplified by the buf getters
	// returning an endless stream of 0s after an error.
	m := make(abbrevTable)
	for {
		// Table ends with id == 0.
		id := uint32(b.uint())
		if id == 0 {
			break
		}

		// Walk over attributes, counting.
		n := 0
		b1 := b   // Read from copy of b.
		b1.uint() // tag
		for {
			idx := b1.uint()
			fmt := b1.uint()
			if idx == 0 && fmt == 0 {
				break
			}
			if format(fmt) == formImplicitConst {
				b1.int()
			}
			n++
		}
		if b1.err != nil {
			return nil, b1.err
		}

		// Walk over attributes again, this time writing them down.
		var a abbrev
		a.tag = Tag(b.uint())
		a.field = make([]afield, n)
		for i := range a.field {
			a.field[i].idx = Index(b.uint())
			a.field[i].fmt = format(b.uint())
			// a.field[i].class = formToClass(a.field[i].fmt, a.field[i].attr, vers, &b)
			if a.field[i].fmt == formImplicitConst {
				a.field[i].val = b.int()
			}
		}
		b.uint()
		b.uint()

		m[id] = a
	}
	if b.err != nil {
		return nil, b.err
	}
	return m, nil
}

func getDwarfOffsetByteSize(headerFormat byte) int {
	switch headerFormat {
	case dwarfFormat32bit:
		return 4
	case dwarfFormat64bit:
		return 8
	default:
		panic(fmt.Sprintf("unknown header format: %d", headerFormat)) // FIXME: prob don't panic
	}
}

func caseFoldingDjbHash(s []byte) uint32 {
	var hash uint32 = 5381
	for _, c := range s {
		// Convert ASCII uppercase to lowercase
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		hash = ((hash << 5) + hash) + uint32(c)
	}
	return hash
}

// readULEB128 reads an unsigned LEB128 value from the reader
func readULEB128(r io.Reader) (uint64, error) {
	var result uint64
	var shift uint

	for {
		var b byte
		err := binary.Read(r, binary.LittleEndian, &b)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}

		result |= uint64(b&0x7f) << shift

		if b&0x80 == 0 {
			break
		}

		shift += 7
	}

	return result, nil
}

// LookupDebugName searches for a name in the DWARF v5 .debug_names section
// and returns the DIE offset if found.
func (d *Data) LookupDebugName(name string) ([]DebugNameEntry, error) {
	var nentries []DebugNameEntry

	nameHash := caseFoldingDjbHash([]byte(name))

	// Check if the bucket table is empty
	if len(d.names.BucketTable) == 0 {
		return nil, fmt.Errorf("empty bucket table in .debug_names")
	}

	// Determine the bucket using the hash
	bucketIdx := nameHash % uint32(len(d.names.BucketTable))
	hashIdx := d.names.BucketTable[bucketIdx]

	// Check if the bucket is empty
	if hashIdx >= uint32(len(d.names.NameTable)) {
		return nil, fmt.Errorf("hash not found for %s", name)
	}

	// Find matching hash
	for ; hashIdx < uint32(len(d.names.NameTable)); hashIdx++ {
		// if thash.Hashes[hashIdx] == nameHash {
		// Found a hash match, now check if the name matches
		entryOffset := d.names.EntryOffsets[hashIdx-1]

		// Read entry data - the first thing should be the string offset
		strOffset := d.names.StringOffsets[hashIdx-1]

		// Extract the name at this string offset
		// We'll need to verify it matches our search name
		entryName, err := readNullTerminatedString(d.str, int(strOffset))
		if err != nil {
			return nil, err
		}

		// If the name matches, we found our entry
		if entryName == name {
			// Seek to the entry offset
			if _, err := d.names.data.Seek(d.names.offsets.EntriesBase+int64(entryOffset), 0); err != nil {
				return nil, err
			}

			for {
				// Read abbreviation code (unsigned LEB128)
				code, err := readULEB128(d.names.data)
				if err != nil {
					return nil, err
				}
				if code == 0 {
					break // End of abbreviation table
				}

				nentry := DebugNameEntry{Tag: d.names.AbbrevTable[uint32(code)].tag}
				if len(d.names.CompUnits) == 1 {
					nentry.CUIndex = 0
					nentry.CUOffset = Offset(d.names.CompUnits[0])
				}

				for i := range d.names.AbbrevTable[uint32(code)].field {
					attr := d.names.AbbrevTable[uint32(code)].field[i]
					if attr.idx == Index(0) {
						continue
					}
					switch attr.idx {
					case IndexCompileUnit:
						switch attr.fmt {
						case formData1:
							var cuIdx uint8
							if err := binary.Read(d.names.data, d.order, &cuIdx); err != nil {
								return nil, err
							}
							nentry.CUIndex = uint64(cuIdx)
							nentry.CUOffset = d.unit[cuIdx].off
						case formData2:
							var cuIdx uint16
							if err := binary.Read(d.names.data, d.order, &cuIdx); err != nil {
								return nil, err
							}
							nentry.CUIndex = uint64(cuIdx)
							nentry.CUOffset = d.unit[cuIdx].off
						case formData4:
							var cuIdx uint32
							if err := binary.Read(d.names.data, d.order, &cuIdx); err != nil {
								return nil, err
							}
							nentry.CUIndex = uint64(cuIdx)
							nentry.CUOffset = d.unit[cuIdx].off
						case formData8:
							if err := binary.Read(d.names.data, d.order, &nentry.CUIndex); err != nil {
								return nil, err
							}
							nentry.CUOffset = d.unit[nentry.CUIndex].off
						default:
							return nil, fmt.Errorf("unsupported CU index form: %v", attr.fmt)
						}
					case IndexDieOffset:
						switch attr.fmt {
						case formRef1:
							var dieOffset uint8
							if err := binary.Read(d.names.data, d.order, &dieOffset); err != nil {
								return nil, err
							}
							nentry.DIEOffset = Offset(dieOffset) + d.unit[nentry.CUIndex].base
						case formRef2:
							var dieOffset uint16
							if err := binary.Read(d.names.data, d.order, &dieOffset); err != nil {
								return nil, err
							}
							nentry.DIEOffset = Offset(dieOffset) + d.unit[nentry.CUIndex].base
						case formRef4:
							var dieOffset uint32
							if err := binary.Read(d.names.data, d.order, &dieOffset); err != nil {
								return nil, err
							}
							nentry.DIEOffset = Offset(dieOffset) + d.unit[nentry.CUIndex].base
						case formRef8:
							var dieOffset uint64
							if err := binary.Read(d.names.data, d.order, &dieOffset); err != nil {
								return nil, err
							}
							nentry.DIEOffset = Offset(dieOffset) + d.unit[nentry.CUIndex].base
						case formRefUdata:
							dieOffset, err := readULEB128(d.names.data)
							if err != nil {
								return nil, err
							}
							nentry.DIEOffset = Offset(dieOffset) + d.unit[nentry.CUIndex].base
						default:
							return nil, fmt.Errorf("unsupported DIE offset form: %v", attr.fmt)
						}
					case IndexParent:
						switch attr.fmt {
						case formRef1:
							var dieOffset uint8
							if err := binary.Read(d.names.data, d.order, &dieOffset); err != nil {
								return nil, err
							}
							nentry.ParentIdx = Offset(dieOffset)
						case formRef2:
							var dieOffset uint16
							if err := binary.Read(d.names.data, d.order, &dieOffset); err != nil {
								return nil, err
							}
							nentry.ParentIdx = Offset(dieOffset)
						case formRef4:
							var dieOffset uint32
							if err := binary.Read(d.names.data, d.order, &dieOffset); err != nil {
								return nil, err
							}
							nentry.ParentIdx = Offset(dieOffset)
						case formRef8:
							var dieOffset uint64
							if err := binary.Read(d.names.data, d.order, &dieOffset); err != nil {
								return nil, err
							}
							nentry.ParentIdx = Offset(dieOffset)
						case formRefUdata:
							dieOffset, err := readULEB128(d.names.data)
							if err != nil {
								return nil, err
							}
							nentry.ParentIdx = Offset(dieOffset)
						case formFlagPresent:
							// Parent is present, but we don't have an offset
						default:
							return nil, fmt.Errorf("unsupported Parent form: %v", attr.fmt)
						}
					}
				}

				nentries = append(nentries, nentry)
			}
		}

		// If we've gone past the bucket's hash range, stop searching
		if (d.names.NameTable[hashIdx-1] % uint32(len(d.names.BucketTable))) != bucketIdx {
			break
		}
	}

	if len(nentries) == 0 {
		return nil, fmt.Errorf("name not found: %s", name)
	}

	return nentries, nil
}

// DumpDebugNames returns all entries from the DWARF v5 .debug_names section
func (d *Data) DumpDebugNames() (Entries, error) {
	return nil, nil // FIXME: implement
}

// readNullTerminatedString extracts a null-terminated string from data at the given offset
func readNullTerminatedString(data []byte, offset int) (string, error) {
	if offset < 0 || offset >= len(data) {
		return "", fmt.Errorf("string offset %d out of bounds [0,%d)", offset, len(data))
	}

	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}

	if end >= len(data) {
		return "", fmt.Errorf("string at offset %d not null-terminated", offset)
	}

	return string(data[offset:end]), nil
}
