# EDRChoker-BOF (AdaptixC2)

Port of Two Seven One Three's EDRChoker to an AdaptixC2 BOF. Registers Windows QoS policies (`MSFT_NetQosPolicySettingData`) that cap outbound TCP+UDP bandwidth on EDR processes to 8 bytes/sec. `pacer.sys` enforces the cap in kernel NDIS, below the EDR's socket layer.

x64 only. Requires high integrity (admin).

## Commands

```
edrchoker throttleedr              Enumerate running EDR processes, throttle each
edrchoker throttle <process name>  Throttle one process by name (basename or full path)
edrchoker clearall                 Remove QoS policies created by this session
edrchoker clear <policy name>      Remove one QoS policy by exact Name
edrchoker list                     Show session policies, running EDRs, throttle status
edrchoker state                    Print the session-random policy Name prefix
```

## Build

```
make dist
```

Requires `x86_64-w64-mingw32-gcc`. Output: `_bin/edrchoker.x64.o`.

## Prerequisite

Policies only take effect if `pacer.sys` (`ms_pacer`) is bound to the NIC. Usually bound on client SKUs by default; often unbound on Server SKUs.

```powershell
Get-NetAdapterBinding -ComponentID ms_pacer
```
