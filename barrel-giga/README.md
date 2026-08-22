# Barrel-Giga

Fixed-recipe x64 PE carrier builder for Operation Triple Barrel.

- Input: raw x64 Barrel Kit carrier
- Injectable: pinned `AppleWin-x64.exe` v1.32.0.0
- Output: self-signed, RFC 3161-timestamped x64 EXE
- Toolchain: MSVC on Windows, MinGW on Linux

## Requirements

```text
Python 3.11+
Windows: Visual Studio 2022 C++ tools (Desktop development with C++)
Linux: MinGW-w64 and osslsigncode
```

- [Visual Studio 2022 C++ tools](https://aka.ms/vs/17/release/vs_BuildTools.exe)

## Installation

Windows:

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -e .
```

Linux:

```bash
sudo apt install mingw-w64 osslsigncode python3-venv
python3 -m venv .venv
./.venv/bin/python -m pip install -e .
```

## Commands

```powershell
# Download required injectable, osslsigncode, etc.
.\.venv\Scripts\python barrel-giga.py prep

# Show injectables
.\.venv\Scripts\python barrel-giga.py list

# Build barrel-giga
.\.venv\Scripts\python barrel-giga.py build --input ..\barrel-kit\output\agent.x64.bin --injectable AppleWin-x64.exe --output output\applewin-barrel.exe
```

## Default techniques


| Technique      | Implementation                                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------------------------------ |
| Placement      | Encoded payload in read-only image space; carrier and decoded payload in executable image space                    |
| Invocation     | Backdoor an existing call or jump in the entry-point function; preserve the entry-point RVA                        |
| IAT reuse      | Patch carrier API calls to the host IAT; repair AppleWin's `DeleteCriticalSection` slot to `FlushInstructionCache` |
| Memory         | Temporarily set the decode destination RW, restore its original protection, then flush the instruction cache       |
| Encoding       | Per-build xorshift64 XOR stream                                                                                    |
| Execution      | Run the payload, then keep the host process alive with `Sleep(INFINITE)`                                           |
| Guardrails     | None                                                                                                               |
| Anti-emulation | None                                                                                                               |


## References and credits

- [Dobin Rutishauser](https://github.com/dobin)
- [SuperMega](https://github.com/dobin/SuperMega)
- [Cordyceps: Shellcode in EXE Injection](https://blog.deeb.ch/posts/exe-injection/)

