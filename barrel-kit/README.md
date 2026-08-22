# Barrel Kit

User-Defined Reflective Loader for AdaptixC2 testing-v2.0, built with Crystal Palace.

Two-stage PIC+PICO architecture: loader runs once at startup, PICO runtime lives for the agent's lifetime hooking Sleep, Heap, ExitThread, etc. Ported from Modular-Crystal (Cobalt Strike UDRL reference), with all CS-specific code removed.

Barrel Kit was vibe-coded in two days for Operation Triple Barrel, which is a adversary simulation workshop for beginners in South Korea. So yeah, please do NOT use this in production. 

## Installation

Linux 
```
sudo apt install make mingw-w64 default-jre
```

## GUI Build (Linux) 

1. Add Script -> barrel-kit.aws
2. Disable Sandbox (`Settings -> AxScript -> Code Editor (Toolbar Actions) -> Sandbox filesystem (DISABLE)`)
3. Generate normal Adaptix x64 DLL payload
4. Generate barrel-kit
  - Code Editor top right -> Change AxScript to Barrel Kit 
  - Specify Adaptix DLL from #3 
  - Click the hammer "Build" button on top right 

Default output path: `barrel-kit/output/agent.x64.bin`


## CLI Build

```bash
# Full build: compile, generate agent DLL via Adaptix API, scrub YARA sigs, link with Crystal Palace
./build.sh --url https://10.10.0.5:4321 -u operator1 -p changeme -l https-testo

# With check-in delay (seconds) and custom share path
./build.sh --url https://10.10.0.5:4321 -u operator1 -p changeme -l https-testo -d 30 -s /mnt/share
```

## Test

```bash
# Build runner (mingw)
x86_64-w64-mingw32-gcc -O2 -s -o runner.exe tests/build/runner.c

# Build runner with strict CFG (MSVC)
cl /O2 /guard:cf tests\build\runner.c /link /guard:cf /out:runner_cfg.exe

# Run
runner.exe agent.x64.bin
```

## Architecture

```
PIC Loader (loader.c)              runs once
  |-- XOR decrypt embedded DLL (128-byte key, applied at link time)
  |-- Stomp PICO into a dedicated sacrificial SEC_IMAGE
  |-- Stomp the agent into a second sacrificial SEC_IMAGE
  |-- setup_hooks: override GetProcAddress for IAT hooking
  |-- Reflective load: sections, relocations, imports, per-section perms
  |-- setup_memory: PICO stores full memory layout
  |-- DllMain(DLL_PROCESS_ATTACH)

PICO Runtime (pico.c)              lives for agent lifetime
  |-- _WaitForSingleObject: Kraken sleep mask on eligible waits
  |-- _ExitThread:     timer-queue cleanup via NtContinue
  |-- _HeapAlloc/Free: track allocations for sleep masking
  |-- _GetProcAddress: resolve IAT hooks before real GPA
  |-- 28 pass-through hooks via spoof_worker_thread; WinInet via image gate

Kraken (sleep_kraken_adv.c)        runs on the existing agent thread
  |-- RC4 encrypt agent image + tracked heap
  |-- Unmap stomped image, map clean DLL at same base
  |-- Wait, then restore bytes and section permissions
```

## References &amp; Credits

Crystal Palace: 

- Crystal Palace: [tradecraftgarden.org](https://tradecraftgarden.org/docs.html) 
- [Aff-wg](https://aff-wg.org/)
- [rastamouse.me](https://rastamouse.me/)
- [StealthPalace](https://github.com/MaorSabag/Adaptix-StealthPalace)

Module stomping (LoadLibrary + VEH/HWBP):

- [Swappala  - Vincenzo Santucci (oldboy21)](https://oldboy21.github.io/posts/2024/05/swappala-why-change-when-you-can-hide/)
- [Module Stomping  - Dylan Tran](https://dtsec.us/2023-11-04-ModuleStompin/)

Copy-on-write / memory scanner research:

- [Moneta  - Forrest Orr](https://github.com/forrest-orr/moneta)
- [Elastic protections-artifacts](https://github.com/elastic/protections-artifacts)

Call stack spoofing:

- [BingusLdr  - Sizeable-Bingus](https://github.com/Sizeable-Bingus/BingusLdr)
- [MassDriver  - Sizeable-Bingus](https://github.com/Sizeable-Bingus/MassDriver)
- [SilentMoonWalk  - KlezVirus](https://github.com/klezVirus/SilentMoonwalk)
- [BingusLdr CET stack spoofing](https://bigbingus.com/posts/bingusldr-cet-stack-spoofing/)

Sleep masking:

- [KrakenMask  - NtDallas](https://github.com/NtDallas/KrakenMask)
- [PHANTOMPULSE  - Elastic Security Labs](https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole)

Reflective loading:

- [ReflectiveDLLInjection  - Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection)

CFG:

- [Control Flow Guard  - Microsoft](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)

Cleanup:

- [Ekko  - Cracked5pider](https://github.com/Cracked5pider/Ekko)

