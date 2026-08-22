/*
 * barrel-giga.yar
 *
 * Detection rules for Barrel-Giga output artifacts: trojaned legitimate
 * Windows executables with embedded shellcode carriers.
 *
 * Barrel-Giga takes a raw shellcode payload (e.g., Adaptix agent DLL) and
 * embeds it inside a legitimate open-source PE (default: AppleWin-x64.exe).
 * The carrier code uses XorShift64 decoding, split-image memory placement,
 * and a function backdoor (5-byte JMP patch) to hijack the host's entry point.
 *
 * Scan context: file (PE executables).
 */

import "pe"
import "math"

rule BarrelGiga_CarrierEntry_AlignRSP {
    meta:
        description = "Barrel-Giga carrier entry shim: AlignRSP stack alignment prologue before carrier execution"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file"
        os = "windows"

    strings:
        // AlignRSP: push rbp; mov rbp, rsp; and rsp, -16; sub rsp, 0x20; call sg_entry
        $align_rsp = { 55 48 89 E5 48 83 E4 F0 48 83 EC 20 E8 ?? ?? ?? ?? 48 89 EC 5D C3 }

    condition:
        pe.is_pe
        and pe.machine == pe.MACHINE_AMD64
        and $align_rsp
}

rule BarrelGiga_XorShift64_Decoder {
    meta:
        description = "Barrel-Giga XorShift64 stream cipher decoder with shift constants 13, 7, 17"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // XorShift64 core: shl rax/rcx, 13; xor; shr rdx/rax, 7; xor; shl rax/rcx, 17
        // The three shift constants in sequence (register allocation may vary)

        // shl reg, 13  (0x0D)
        $shift_13 = { 48 C1 E? 0D }
        // shr reg, 7   (0x07)
        $shift_7  = { 48 C1 E? 07 }
        // shl reg, 17  (0x11)
        $shift_17 = { 48 C1 E? 11 }

        // movabs loading 8-byte XorShift seed: 48 B9 xx xx xx xx xx xx xx xx (mov rcx, imm64)
        // or 48 B8 (mov rax, imm64)
        $seed_load = { 48 (B8|B9|BA|BB) ?? ?? ?? ?? ?? ?? ?? ?? }

        // XOR byte into destination in the decode loop
        // xor byte pattern: destination[index] = source[index] ^ (BYTE)state
        $xor_byte = { 30 (04|0C|14|1C|24|2C|34|3C) ?? }

    condition:
        all of ($shift_*) and $seed_load
        and for all of ($shift_13, $shift_7, $shift_17) : (
            @shift_13 < @shift_17 and @shift_7 < @shift_17
        )
}

rule BarrelGiga_ErrorCodes {
    meta:
        description = "Barrel-Giga carrier error exit codes passed to ExitProcess on failure"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // ExitProcess(0xE0010001) — guardrail check failed
        $err_guardrail   = { (B9|B8) 01 00 01 E0 }
        // ExitProcess(0xE0010002) — memory allocation failed
        $err_memory      = { (B9|B8) 02 00 01 E0 }
        // ExitProcess(0xE0010003) — memory finalize failed
        $err_finalize    = { (B9|B8) 03 00 01 E0 }
        // ExitProcess(0xE0010004) — anti-emulation check failed
        $err_antiemu     = { (B9|B8) 04 00 01 E0 }

    condition:
        3 of them
}

rule BarrelGiga_SplitImageMemory {
    meta:
        description = "Barrel-Giga split-image memory: VirtualProtect(PAGE_READWRITE) + FlushInstructionCache(handle=-1)"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // VirtualProtect with PAGE_READWRITE (0x04): mov r8d, 4 (or edx, 4)
        $vp_rw = { 41 B8 04 00 00 00 }

        // FlushInstructionCache with handle -1 (current process pseudo-handle)
        // mov rcx, -1  (48 C7 C1 FF FF FF FF)
        $flush_handle = { 48 C7 C1 FF FF FF FF }

        // IAT call to FlushInstructionCache: call [rip+disp32]
        $iat_call = { FF 15 ?? ?? ?? ?? }

    condition:
        $vp_rw and $flush_handle and $iat_call
}

rule BarrelGiga_SleepKeepalive {
    meta:
        description = "Barrel-Giga thread keepalive: calls payload as function then loops Sleep(INFINITE)"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // Sleep(0xFFFFFFFF) loop: mov ecx, 0xFFFFFFFF
        $sleep_inf = { B9 FF FF FF FF }

        // Tight backward jump after sleep call (2-byte short jmp)
        // call reg; jmp back  (EB Fx pattern — short backward jump)
        $sleep_loop = { B9 FF FF FF FF FF (D0|D1|D2|D3|D4|D5|D6|D7|D8|D9|DA|DB|DC|DD|DE|DF|15 ?? ?? ?? ??) EB (F5|F6|F7|F8|F9) }

    condition:
        $sleep_loop
}

rule BarrelGiga_GuardrailStubs {
    meta:
        description = "Barrel-Giga no-op guardrail and anti-emulation stubs returning TRUE"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // Two consecutive mov eax, 1; ret stubs (guardrail + anti_emulation, both returning 1)
        // With possible alignment NOPs between them
        $dual_stub = { B8 01 00 00 00 C3 (90 90 90 90 90 90 90 90 90 90|90 90 90 90 90 90|90 90|) B8 01 00 00 00 C3 }

    condition:
        $dual_stub
}

rule BarrelGiga_PE_Anomalies {
    meta:
        description = "Barrel-Giga trojaned PE: legitimate executable with carrier indicators"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file"
        os = "windows"

    strings:
        $align_rsp   = { 55 48 89 E5 48 83 E4 F0 48 83 EC 20 E8 }
        $err_code    = { (B9|B8) 01 00 01 E0 }
        $flush_neg1  = { 48 C7 C1 FF FF FF FF }
        $sleep_inf   = { B9 FF FF FF FF }

    condition:
        pe.is_pe
        and pe.machine == pe.MACHINE_AMD64
        // Must not be a DLL
        and not (pe.characteristics & pe.DLL)
        // IMAGE_DLLCHARACTERISTICS_GUARD_CF is cleared (carrier disables CFG)
        and not (pe.dll_characteristics & pe.GUARD_CF)
        // Has a .text section and a .rdata section
        and pe.number_of_sections >= 3
        and 3 of ($align_rsp, $err_code, $flush_neg1, $sleep_inf)
}

rule BarrelGiga_Combined {
    meta:
        description = "Barrel-Giga composite: trojaned PE carrier with XorShift64 decoder and split-image execution"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // AlignRSP entry
        $entry = { 55 48 89 E5 48 83 E4 F0 48 83 EC 20 E8 }

        // XorShift64 shift constants
        $xs_13 = { 48 C1 E? 0D }
        $xs_7  = { 48 C1 E? 07 }
        $xs_17 = { 48 C1 E? 11 }

        // Error exit codes (any two)
        $err1 = { (B9|B8) 01 00 01 E0 }
        $err2 = { (B9|B8) 02 00 01 E0 }
        $err3 = { (B9|B8) 03 00 01 E0 }
        $err4 = { (B9|B8) 04 00 01 E0 }

        // FlushInstructionCache(-1, ...)
        $flush = { 48 C7 C1 FF FF FF FF }

        // Sleep(INFINITE)
        $sleep = { B9 FF FF FF FF }

        // VirtualProtect PAGE_READWRITE
        $vp = { 41 B8 04 00 00 00 }

    condition:
        $entry
        and ($xs_13 and $xs_7 and $xs_17)
        and 2 of ($err*)
        and ($flush or $sleep or $vp)
}
