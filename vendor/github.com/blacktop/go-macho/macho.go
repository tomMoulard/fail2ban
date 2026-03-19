// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Mach-O header data structures
// Originally at:
// http://developer.apple.com/mac/library/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html (since deleted by Apple)
// Archived copy at:
// https://web.archive.org/web/20090819232456/http://developer.apple.com/documentation/DeveloperTools/Conceptual/MachORuntime/index.html
// For cloned PDF see:
// https://github.com/aidansteele/osx-abi-macho-file-format-reference

package macho

import (
	"fmt"
	"strings"
)

// Regs386 is the Mach-O 386 register structure.
type Regs386 struct {
	AX    uint32
	BX    uint32
	CX    uint32
	DX    uint32
	DI    uint32
	SI    uint32
	BP    uint32
	SP    uint32
	SS    uint32
	FLAGS uint32
	IP    uint32
	CS    uint32
	DS    uint32
	ES    uint32
	FS    uint32
	GS    uint32
}

func (r Regs386) String(padding int) string {
	return fmt.Sprintf(
		"%seax 0x%08x ebx    0x%08x ecx 0x%08x edx 0x%08x\n"+
			"%sedi 0x%08x esi    0x%08x ebp 0x%08x esp 0x%08x\n"+
			"%sss  0x%08x eflags 0x%08x eip 0x%08x cs  0x%08x\n"+
			"%sds  0x%08x es     0x%08x fs  0x%08x gs  0x%08x\n",
		strings.Repeat(" ", padding), r.AX, r.BX, r.CX, r.DX,
		strings.Repeat(" ", padding), r.DI, r.SI, r.BP, r.SP,
		strings.Repeat(" ", padding), r.SS, r.FLAGS, r.IP, r.CS,
		strings.Repeat(" ", padding), r.DS, r.ES, r.FS, r.GS)
}

// RegsAMD64 is the Mach-O AMD64 register structure.
type RegsAMD64 struct {
	AX    uint64
	BX    uint64
	CX    uint64
	DX    uint64
	DI    uint64
	SI    uint64
	BP    uint64
	SP    uint64
	R8    uint64
	R9    uint64
	R10   uint64
	R11   uint64
	R12   uint64
	R13   uint64
	R14   uint64
	R15   uint64
	IP    uint64
	FLAGS uint64
	CS    uint64
	FS    uint64
	GS    uint64
}

func (r RegsAMD64) String(padding int) string {
	return fmt.Sprintf(
		"%s   rax  %#016x rbx %#016x rcx  %#016x\n"+
			"%s   rdx  %#016x rdi %#016x rsi  %#016x\n"+
			"%s   rbp  %#016x rsp %#016x r8   %#016x\n"+
			"%s    r9  %#016x r10 %#016x r11  %#016x\n"+
			"%s   r12  %#016x r13 %#016x r14  %#016x\n"+
			"%s   r15  %#016x rip %#016x\n"+
			"%srflags  %#016x cs  %#016x fs   %#016x\n"+
			"%s    gs  %#016x\n",
		strings.Repeat(" ", padding), r.AX, r.BX, r.CX,
		strings.Repeat(" ", padding), r.DX, r.DI, r.SI,
		strings.Repeat(" ", padding), r.BP, r.SP, r.R8,
		strings.Repeat(" ", padding), r.R9, r.R10, r.R11,
		strings.Repeat(" ", padding), r.R12, r.R13, r.R14,
		strings.Repeat(" ", padding), r.R15, r.IP,
		strings.Repeat(" ", padding), r.FLAGS, r.CS, r.FS,
		strings.Repeat(" ", padding), r.GS)
}

// RegsARM is the Mach-O ARM register structure.
type RegsARM struct {
	R0   uint32
	R1   uint32
	R2   uint32
	R3   uint32
	R4   uint32
	R5   uint32
	R6   uint32
	R7   uint32
	R8   uint32
	R9   uint32
	R10  uint32
	R11  uint32
	R12  uint32
	SP   uint32
	LR   uint32
	PC   uint32
	CPSR uint32
}

func (r RegsARM) OnlyEntry() bool {
	return r.R0 == 0 && r.R1 == 0 && r.R2 == 0 && r.R3 == 0 &&
		r.R4 == 0 && r.R5 == 0 && r.R6 == 0 && r.R7 == 0 &&
		r.R8 == 0 && r.R9 == 0 && r.R10 == 0 && r.R11 == 0 &&
		r.R12 == 0 && r.SP == 0 && r.LR == 0 && r.PC != 0 &&
		r.CPSR == 0
}

func (r RegsARM) String(padding int) string {
	return fmt.Sprintf(
		"%s r0  %#08x r1     %#08x r2  %#08x r3  %#08x\n"+
			"%s r4  %#08x r5     %#08x r6  %#08x r7  %#08x\n"+
			"%s r8  %#08x r9     %#08x r10 %#08x r11 %#08x\n"+
			"%s r12 %#08x sp     %#08x lr  %#08x pc  %#08x\n"+
			"%scpsr %#08x",
		strings.Repeat(" ", padding), r.R0, r.R1, r.R2, r.R3,
		strings.Repeat(" ", padding), r.R4, r.R5, r.R6, r.R7,
		strings.Repeat(" ", padding), r.R8, r.R9, r.R10, r.R11,
		strings.Repeat(" ", padding), r.R12, r.SP, r.LR, r.PC,
		strings.Repeat(" ", padding), r.CPSR)
}

// RegsARM64 is the Mach-O ARM 64 register structure.
type RegsARM64 struct {
	X0   uint64 /* General purpose registers x0-x28 */
	X1   uint64
	X2   uint64
	X3   uint64
	X4   uint64
	X5   uint64
	X6   uint64
	X7   uint64
	X8   uint64
	X9   uint64
	X10  uint64
	X11  uint64
	X12  uint64
	X13  uint64
	X14  uint64
	X15  uint64
	X16  uint64
	X17  uint64
	X18  uint64
	X19  uint64
	X20  uint64
	X21  uint64
	X22  uint64
	X23  uint64
	X24  uint64
	X25  uint64
	X26  uint64
	X27  uint64
	X28  uint64
	FP   uint64 /* Frame pointer x29 */
	LR   uint64 /* Link register x30 */
	SP   uint64 /* Stack pointer x31 */
	PC   uint64 /* Program counter */
	CPSR uint32 /* Current program status register */
	PAD  uint32 /* Same size for 32-bit or 64-bit clients */
}

func (r RegsARM64) OnlyEntry() bool {
	return r.X0 == 0 && r.X1 == 0 && r.X2 == 0 && r.X3 == 0 &&
		r.X4 == 0 && r.X5 == 0 && r.X6 == 0 && r.X7 == 0 &&
		r.X8 == 0 && r.X9 == 0 && r.X10 == 0 && r.X11 == 0 &&
		r.X12 == 0 && r.X13 == 0 && r.X14 == 0 && r.X15 == 0 &&
		r.X16 == 0 && r.X17 == 0 && r.X18 == 0 && r.X19 == 0 &&
		r.X20 == 0 && r.X21 == 0 && r.X22 == 0 && r.X23 == 0 &&
		r.X24 == 0 && r.X25 == 0 && r.X26 == 0 && r.X27 == 0 &&
		r.X28 == 0 && r.FP == 0 && r.LR == 0 && r.SP == 0 &&
		r.PC != 0 && r.CPSR == 0 && r.PAD == 0
}

func (r RegsARM64) String(padding int) string {
	return fmt.Sprintf(
		"%s x0: %#016x   x1: %#016x   x2: %#016x   x3: %#016x\n"+
			"%s x4: %#016x   x5: %#016x   x6: %#016x   x7: %#016x\n"+
			"%s x8: %#016x   x9: %#016x  x10: %#016x  x11: %#016x\n"+
			"%sx12: %#016x  x13: %#016x  x14: %#016x  x15: %#016x\n"+
			"%sx16: %#016x  x17: %#016x  x18: %#016x  x19: %#016x\n"+
			"%sx20: %#016x  x21: %#016x  x22: %#016x  x23: %#016x\n"+
			"%sx24: %#016x  x25: %#016x  x26: %#016x  x27: %#016x\n"+
			"%sx28: %#016x   fp: %#016x   lr: %#016x\n"+
			"%s sp: %#016x   pc: %#016x cpsr: %#08x\n"+
			"%sesr: %#08x",
		strings.Repeat(" ", padding), r.X0, r.X1, r.X2, r.X3,
		strings.Repeat(" ", padding), r.X4, r.X5, r.X6, r.X7,
		strings.Repeat(" ", padding), r.X8, r.X9, r.X10, r.X11,
		strings.Repeat(" ", padding), r.X12, r.X13, r.X14, r.X15,
		strings.Repeat(" ", padding), r.X16, r.X17, r.X18, r.X19,
		strings.Repeat(" ", padding), r.X20, r.X21, r.X22, r.X23,
		strings.Repeat(" ", padding), r.X24, r.X25, r.X26, r.X27,
		strings.Repeat(" ", padding), r.X28, r.FP, r.LR,
		strings.Repeat(" ", padding), r.SP, r.PC, r.CPSR,
		strings.Repeat(" ", padding), r.PAD)
}

type ArmExceptionState struct {
	FAR       uint32 /* Virtual Fault Address */
	ESR       uint32 /* Exception syndrome */
	Exception uint32 /* number of arm exception taken */
}

func (r ArmExceptionState) String(padding int) string {
	return fmt.Sprintf(
		"%sfar: %#08x   esr: %#08x   exception: %#08x",
		strings.Repeat(" ", padding), r.FAR, r.ESR, r.Exception)
}

type ArmExceptionState64 struct {
	FAR       uint64 /* Virtual Fault Address */
	ESR       uint32 /* Exception syndrome */
	Exception uint32 /* number of arm exception taken */
}

func (r ArmExceptionState64) String(padding int) string {
	return fmt.Sprintf(
		"%sfar: %#016x   esr: %#08x   exception: %#08x",
		strings.Repeat(" ", padding), r.FAR, r.ESR, r.Exception)
}
