# Barrel Kit Architecture

x64 UDRL for stock Adaptix C2 v2.0 DLLs. `loader.spec` builds the one-shot PIC
bootstrap. `pico.spec` builds the resident PICO runtime and selects its modules.

```text
loader.spec
  loader.c -> services.c -> load_phantom.c
      |
      +-> pico.spec
            pico.c
              +-> hooks.c -> spoof_worker_thread.c
              |          -> wininet_gate (spoof_stitch.c + stitch_stub.S)
              +-> cfg_gadgets.c
              +-> sleep_kraken_adv.c
              +-> cleanup.c
```

## Build Composition

- **`loader.spec` - PIC composition and resource masking**: Merges the loader,
  resolver, phantom allocator, LibTCG, XOR-masked agent DLL, and PICO blob.
  Reference: [Crystal Palace documentation](https://tradecraftgarden.org/docs.html)
- **`pico.spec` - PICO composition and import hooking**: Selects the resident
  modules, embeds the stitch assembly, exports setup functions, and declares
  the 34 `addhook` entries.
  Reference: [Simple Loader: Hooking](https://tradecraftgarden.org/simplehook.html)

## PIC Modules

### `loader.c`

- **Reflective PE loading / manual mapping**: Decrypts the embedded DLL, copies
  sections, applies relocations, resolves imports, restores section
  permissions, calls `DllMain`, and patches the Adaptix wait dispatch path.
- **Optional initial check-in delay**: A build-time delay runs before embedded
  resources are decrypted or the agent is initialized. `0` disables it.
- **PIC-to-PICO staging**: Loads PICO into a dedicated sacrificial `MEM_IMAGE`
  module so its runtime survives remapping of the separate agent module.
- References: [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection),
  [Crystal Palace PIC and PICO](https://tradecraftgarden.org/docs.html)

### `services.c`

- **Dynamic function resolution / ROR13 API hashing**: Walks the PEB and export
  tables to resolve loader APIs without a conventional import table.
- Reference: [Simple Loader: API Hashing](https://tradecraftgarden.org/simpleapi.html)

### `load_phantom.c`

- **Dual phantom module stomping / `SEC_IMAGE` overloading**: Loads two
  eligible System32 images. One holds zero-initialized PICO code/data; the
  other holds the reflective agent image remapped by Kraken.
- **Clean-image handle retention**: Keeps the backing section handle for the
  sleep path. Falls back to private `VirtualAlloc` when phantom allocation
  is unavailable.
- Reference: [PHANTOMPULSE: PhantomInject](https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole)

## PICO Modules

### `pico.c`

- **Resident runtime coordinator**: Owns the shared memory layout, initializes
  hooks and proxy workers, tracks agent heap allocations, and starts cleanup.
- **Inline API detour**: Patches `KERNEL32!WaitForSingleObject` with an absolute
  jump because Adaptix resolves that API through the PEB and bypasses its IAT.
- References: [Microsoft Detours](https://github.com/microsoft/Detours),
  [Cobalt Strike Sleep Masks](https://www.cobaltstrike.com/sleep-masks)

### `hooks.c`

- **IAT hooking / API interposition**: Implements 28 pass-through wrappers for
  WinInet, Winsock, Kernel32, and OLE32. Six state-aware wrappers live in
  `pico.c`, giving the spec 34 hook entries in total.
- **Proxy routing**: Sends normal APIs to `spoof_worker_thread`; the three WinInet APIs
  use the independent image-gadget gate.
- Reference: [Simple Loader: Hooking](https://tradecraftgarden.org/simplehook.html)

### `spoof_worker_thread.c`

- **Worker-thread API proxy / call-stack displacement**: Executes hooked APIs
  on a dedicated event-driven worker with real `call` and `ret` pairs, leaving
  system thread-start frames above the target API.
- **Operational fallbacks**: Uses caller-thread dispatch while impersonating a
  token and a controlled direct path for sustained handle traffic.
- Reference: [MassDriver](https://github.com/Sizeable-Bingus/MassDriver)

### `wininet_gate` from `spoof_stitch.c` and `stitch_stub.S`

- **CET-compatible call-preceded gadget stitching**: Routes three WinInet APIs
  through a separate worker and a `call [reg+disp]; jmp [reg+disp]` gadget with
  valid unwind metadata.
- **Image-backed execution gate**: The assembly stub recreates the selected
  gadget frame, captures the result and last error, then signals completion.
- References: [BingusLdr CET stack spoofing](https://bigbingus.com/posts/bingusldr-cet-stack-spoofing/),
  [BingusLdr](https://github.com/Sizeable-Bingus/BingusLdr)

### `cfg_gadgets.c`

- **CFG valid-call-target registration**: Detects CFG and registers PICO,
  executable agent regions, aligned proxy workers, and indirect API targets
  through `NtSetInformationVirtualMemory`.
- Reference: [Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)

### `sleep_kraken_adv.c`

- **Kraken-style sleep masking**: Runs synchronously from PICO on the existing
  image-backed agent thread. RC4 encrypts the agent backup plus tracked heap
  allocations with `SystemFunction032` during eligible waits.
- **Clean-image unmap/remap**: Replaces the live stomped mapping with clean
  `dbghelp.dll` while sleeping, then restores agent bytes and section
  permissions at the same address.
- References: [KrakenMask](https://github.com/NtDallas/KrakenMask),
  [PHANTOMPULSE](https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole)

This module does not implement KrakenMask's APC chain or TIB spoofing. PICO
remains mapped and completes the wait before returning to the restored agent.

### `cleanup.c`

- **Timer-queue `NtContinue` self-deletion**: After `ExitThread` interception,
  delayed contexts unmap phantom memory or free private memory from a timer
  thread that is outside the region being destroyed.
- References: [Ekko](https://github.com/Cracked5pider/Ekko),
  [Self-Cleaning PICO Loader](https://github.com/pard0p/Self-Cleaning-PICO-Loader)

## Shared Interfaces

| File | Contract |
| --- | --- |
| `memory.h` | Agent, PICO, section, heap, and phantom allocation state |
| `spoof.h` | Proxy call ABI and shared worker state |
| `cfg.h` | CFG registration interface |
| `mask.h` | Sleep wait interface |
| `cleanup.h` | Deferred cleanup interface |

## Selection Boundaries

- Active stitch object: `wininet_gate.x64.o`, built from `spoof_stitch.c` with
  `SPOOF_STITCH_GATE_ONLY=1`
- `spoof_stitch.x64.o` and `stitch_entry.x64.o` have Makefile targets but are
  not selected by `OBJECTS` or `pico.spec`
- x64 only
- Stock Adaptix v2.0 DLL: no agent source changes
- Short, infinite, or failed advanced waits use the normal proxy path
