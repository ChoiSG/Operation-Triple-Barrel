/*
 * barrel-kit.yar
 *
 * Detection rules for Barrel-Kit: a two-stage PIC+PICO User-Defined
 * Reflective Loader (UDRL) for Adaptix C2, built with Crystal Palace.
 *
 * Barrel-Kit is a raw PIC shellcode blob (no PE headers). It module-stomps
 * sacrificial System32 DLLs via VEH/HWBP, hooks 28+ Windows APIs through
 * Crystal Palace's addhook mechanism, and uses Kraken sleep masking
 * (RC4 + clean-image remap) to evade memory scanners.
 *
 * Scan context: file (raw .bin blobs) and memory.
 */

rule BarrelKit_StitchStub_Magic {
    meta:
        description = "Barrel-Kit gadget-stitching call-stack spoof stub with STCH magic"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // Stitch blob header: 3 DWORDs (worker_offset, fixup_offset, blob_size)
        // followed by magic 0x48435453 ("STCH" little-endian)
        $stitch_magic = { ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 53 54 43 48 }

        // stitch_worker entry: save non-volatiles, set up frame
        // mov [rcx+0x58], rbx; mov [rcx+0x60], rsi; mov rbx, rcx; push rbp; mov rbp, rsp
        $stitch_worker_prologue = { 48 89 59 58 48 89 71 60 48 89 CB 55 48 89 E5 }

        // stitch_wait loop: WaitForSingleObjectEx(handle, INFINITE, FALSE)
        // mov rcx, [rbx+8]; mov edx, 0xffffffff; xor r8d, r8d; call [rbx+0x20]
        $stitch_wait = { 48 8B 4B 08 BA FF FF FF FF 45 31 C0 FF 53 20 }

        // stitch_fixup: store return value, signal completion
        // mov [rbx+0x30], rax; mov rsp, rbp
        $stitch_fixup = { 48 89 43 30 48 89 EC }

    condition:
        $stitch_magic and 1 of ($stitch_worker_prologue, $stitch_wait, $stitch_fixup)
}

rule BarrelKit_WorkerThread_NopSled {
    meta:
        description = "Barrel-Kit worker thread entry: 16 NOP sled followed by indirect JMP through RCX"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "memory"
        os = "windows"

    strings:
        // 16 NOPs + jmp qword ptr [rcx+0x48] (offset 72 — worker_thread_entry)
        $nop_jmp_48 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FF 61 48 }

        // 16 NOPs + jmp qword ptr [rcx+0x78] (offset 120 — stitch_worker_entry / wininet_gate_worker_entry)
        $nop_jmp_78 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FF 61 78 }

    condition:
        any of them
}

rule BarrelKit_PICLoader_Resolve {
    meta:
        description = "Barrel-Kit PIC loader: ROR13 hash-based API resolution with known module/function hashes"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // resolve(KERNEL32_hash, VirtualAlloc_hash)
        // sub rsp, 0x20; mov ecx, 0x6A4ABC5B; mov edx, 0x91AFCA54; call resolve
        $resolve_VirtualAlloc = { 48 83 EC 20 B9 5B BC 4A 6A BA 54 CA AF 91 E8 ?? ?? ?? ?? }

        // resolve(KERNEL32_hash, VirtualProtect_hash)
        $resolve_VirtualProtect = { 48 83 EC 20 B9 5B BC 4A 6A BA 1B C6 46 79 E8 ?? ?? ?? ?? }

        // resolve(KERNEL32_hash, VirtualFree_hash)
        $resolve_VirtualFree = { 48 83 EC 20 B9 5B BC 4A 6A BA AC 33 06 03 E8 ?? ?? ?? ?? }

        // resolve(KERNEL32_hash, LoadLibraryA_hash)
        $resolve_LoadLibraryA = { 48 83 EC 20 B9 5B BC 4A 6A BA 8E 4E 0E EC E8 ?? ?? ?? ?? }

        // resolve(0x3CFA685D_hash, function_hash) — ntdll or other module
        $resolve_ntdll = { 48 83 EC 20 B9 5D 68 FA 3C BA ?? ?? ?? ?? E8 ?? ?? ?? ?? }

        // PEB walk: mov rax, qword ptr gs:[0x60]
        $peb_walk = { 65 48 8B 04 25 60 00 00 00 }

        // .text section hash comparison: cmp dword ptr [rbp-0x24], 0xEBC2F9B4
        $text_section_hash = { 81 7D DC B4 F9 C2 EB }

        // _GetProcAddress hook sentinel: mov edx, 0x0FFD97FB; cmp ecx, edx
        $gpa_hook_sentinel = { BA FB 97 FD 0F 39 D1 }

    condition:
        $peb_walk and 2 of ($resolve_*)
        or $peb_walk and ($text_section_hash or $gpa_hook_sentinel)
        or 3 of ($resolve_*)
}

rule BarrelKit_KrakenSleepMask {
    meta:
        description = "Barrel-Kit Kraken sleep mask: RC4 encryption via SystemFunction032 with clean-image remap"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // "advapi32.dll" resolved for SystemFunction032
        $advapi32 = "advapi32.dll" ascii nocase
        // "SystemFunction032" resolved via GetProcAddress
        $sysfunc032 = "SystemFunction032" ascii

        // VirtualProtect chunk size 0x2000 (evasion: stays under Elastic hollow_image threshold)
        // cmp/mov with 0x2000
        $vp_chunk = { (B8|B9|BA|41 B8|41 B9) 00 20 00 00 }

        // Kraken LCG key derivation: state * 1103515245 + 12345
        // imul with 0x41C64E6D (1103515245)
        $lcg_mul = { 69 ?? 6D 4E C6 41 }
        // add 0x3039 (12345)
        $lcg_add = { (05|81 C?) 39 30 00 00 }

        // NtUnmapViewOfSection / NtMapViewOfSection strings for clean-image remap
        $unmap = "NtUnmapViewOfSection" ascii
        $map = "NtMapViewOfSection" ascii

    condition:
        ($sysfunc032 or $advapi32) and ($vp_chunk or $lcg_mul)
        or $unmap and $map and $vp_chunk
}

rule BarrelKit_CFGBypass {
    meta:
        description = "Barrel-Kit Control Flow Guard bypass via NtSetInformationVirtualMemory"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // NtSetInformationVirtualMemory call + NTSTATUS 0xC00000F4 check
        // mov rax, [imp]; call rax; mov [rbp-4], eax; cmp [rbp-4], 0xC00000F4
        $cfg_bypass = { 48 8B 05 ?? ?? ?? ?? FF D0 89 45 FC 81 7D FC F4 00 00 C0 }

        // ProcessControlFlowGuardPolicy info class = 52 for NtQueryInformationProcess
        $cfg_query_class = { (B9|BA|41 B8|41 B9) 34 00 00 00 }

        // NTSTATUS 0xC0000045 (STATUS_INVALID_PAGE_PROTECTION) treated as success
        $cfg_page_prot = { (3D|81 7D ??) 45 00 00 C0 }

    condition:
        $cfg_bypass and ($cfg_query_class or $cfg_page_prot)
}

rule BarrelKit_NtContinueCleanup {
    meta:
        description = "Barrel-Kit self-cleanup via NtContinue timer queue callbacks"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // CreateTimerQueue + CreateTimerQueueTimer + RtlCaptureContext + NtContinue
        // combined pattern: these imports appear together in the PICO blob

        // Timer setup: MEM_RELEASE (0x8000) in R8 for VirtualFree via NtContinue context
        // mov r8, 0x8000  (or variant)
        $mem_release_ctx = { 49 C7 C0 00 80 00 00 }

        // mov dword ptr [rbp], 0x10001F — CONTEXT_ALL flags
        $context_all = { C7 45 00 1F 00 10 00 }

        // Timer period constant (0xE70 = 3696 bytes) used for heap allocation size
        // mov r8d, 0xE70
        $ctx_alloc_size = { 41 B8 70 0E 00 00 BA 08 00 00 00 48 89 C1 }

    condition:
        $context_all and ($mem_release_ctx or $ctx_alloc_size)
}

rule BarrelKit_ModuleStomp_Phantom {
    meta:
        description = "Barrel-Kit module stomping via VEH/HWBP with known sacrificial System32 DLLs"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // Sacrificial DLL paths (wide strings in PIC code)
        $sac_esent       = "C:\\Windows\\System32\\esent.dll" wide
        $sac_xps         = "C:\\Windows\\System32\\xpsservices.dll" wide
        $sac_localspl    = "C:\\Windows\\System32\\localspl.dll" wide
        $sac_wsmsvc      = "C:\\Windows\\System32\\WsmSvc.dll" wide

        // VEH registration: AddVectoredExceptionHandler
        $add_veh = "AddVectoredExceptionHandler" ascii
        // VEH removal: RemoveVectoredExceptionHandler
        $remove_veh = "RemoveVectoredExceptionHandler" ascii

        // Hardware breakpoint setup via SetThreadContext
        // DR0-DR3 register offsets in CONTEXT structure
        $set_ctx = "SetThreadContext" ascii
        $get_ctx = "GetThreadContext" ascii

        // VirtualProtect chunk size 0x2000 for stomp protection
        $stomp_chunk = { (B8|B9|BA|41 B8|41 B9) 00 20 00 00 }

    condition:
        2 of ($sac_*) and ($add_veh or $remove_veh)
        or 2 of ($sac_*) and $set_ctx and $get_ctx
        or 3 of ($sac_*) and $stomp_chunk
}

rule BarrelKit_InlineHook_WaitForSingleObject {
    meta:
        description = "Barrel-Kit inline hook: absolute 12-byte trampoline (mov rax, imm64; jmp rax)"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "memory"
        os = "windows"

    strings:
        // 12-byte inline hook: mov rax, <addr>; jmp rax
        $inline_hook = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }

        // NtProtectVirtualMemory for writing the hook (changes page protection)
        $nt_protect = "NtProtectVirtualMemory" ascii

        // WaitForSingleObject target (hooked to redirect through PICO dispatch)
        $wfso = "WaitForSingleObject" ascii

    condition:
        $inline_hook and $nt_protect
        or $inline_hook and $wfso
}

rule BarrelKit_LibPreloads {
    meta:
        description = "Barrel-Kit library preloading sequence: 8 specific DLLs loaded before agent start"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        $dll1 = "winhttp.dll" ascii
        $dll2 = "netapi32.dll" ascii
        $dll3 = "samlib.dll" ascii
        $dll4 = "wtsapi32.dll" ascii
        $dll5 = "secur32.dll" ascii
        $dll6 = "iphlpapi.dll" ascii
        $dll7 = "dnsapi.dll" ascii
        $dll8 = "wbemprox.dll" ascii

    condition:
        6 of them
}

rule BarrelKit_Combined {
    meta:
        description = "Barrel-Kit composite detection: PIC+PICO reflective loader for Adaptix C2"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        arch_context = "x64"
        scan_context = "file, memory"
        os = "windows"

    strings:
        // PEB walk
        $peb = { 65 48 8B 04 25 60 00 00 00 }

        // KERNEL32 module hash 0x6A4ABC5B
        $k32_hash = { B9 5B BC 4A 6A }

        // Stitch magic
        $stitch = { 53 54 43 48 }

        // VP chunk 0x2000
        $vp_chunk = { (B8|B9|BA|41 B8|41 B9) 00 20 00 00 }

        // SystemFunction032
        $rc4 = "SystemFunction032" ascii

        // Any sacrificial DLL path
        $sac_dll = /C:\\Windows\\System32\\(esent|xpsservices|localspl|WsmSvc)\.dll/ wide

        // NtContinue cleanup context flags
        $ctx_all = { C7 45 00 1F 00 10 00 }

        // Library preloads (any 3)
        $preload1 = "wbemprox.dll" ascii
        $preload2 = "samlib.dll" ascii
        $preload3 = "wtsapi32.dll" ascii

    condition:
        $peb and $k32_hash and 3 of ($stitch, $vp_chunk, $rc4, $sac_dll, $ctx_all, $preload1, $preload2, $preload3)
}
