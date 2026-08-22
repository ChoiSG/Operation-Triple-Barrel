/*
 * barrel-shot.yar
 *
 * Detection rules for Barrel-Shot: a custom RDP/SSH tunneling tool
 * written in Go. Transports traffic over WebSocket + SSH with a
 * reverse-connect agent model. Supports standalone EXE and DLL
 * sideloading builds.
 *
 * Architecturally derived from chisel but is a clean rewrite with
 * distinct protocol identifiers, making string-based detection reliable.
 *
 * Scan context: file (PE and ELF binaries).
 */

rule BarrelShot_ProtocolStrings {
    meta:
        description = "Barrel-Shot protocol version and channel type identifiers"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        scan_context = "file"
        os = "windows, linux"

    strings:
        // SSH version string (appears on the wire and in binary)
        $ssh_version = "SSH-2.0-barrel-shot-1" ascii

        // Protocol version constant
        $proto_ver = "barrel-shot-1" ascii

        // SSH channel type
        $chan_type = "barrel-shot" ascii

    condition:
        $ssh_version or ($proto_ver and $chan_type)
}

rule BarrelShot_GoSymbols {
    meta:
        description = "Barrel-Shot Go module path and embedded config symbols"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        scan_context = "file"
        os = "windows, linux"

    strings:
        // Go module path (appears in build info and symbol table)
        $mod_path = "barrel-shot/agent" ascii

        // Embedded config variable symbols (set via -ldflags -X)
        $embed_server      = "barrel-shot/agent.embeddedServer" ascii
        $embed_auth        = "barrel-shot/agent.embeddedAuth" ascii
        $embed_fingerprint = "barrel-shot/agent.embeddedFingerprint" ascii
        $embed_remotes     = "barrel-shot/agent.embeddedRemotes" ascii
        $embed_tlsskip     = "barrel-shot/agent.embeddedTLSSkip" ascii
        $embed_trigger     = "barrel-shot/agent.embeddedTrigger" ascii

    condition:
        $mod_path and 2 of ($embed_*)
}

rule BarrelShot_LogStrings {
    meta:
        description = "Barrel-Shot agent and server log format strings"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        scan_context = "file"
        os = "windows, linux"

    strings:
        // Agent-side log strings
        $log_connecting    = "[agent] Connecting to %s" ascii
        $log_connected     = "[agent] Connected (latency %s)" ascii
        $log_conn_error    = "[agent] Connection error: %v" ascii
        $log_tunnel        = "[agent] Tunnel -> %s" ascii

        // Server-side log strings
        $log_agent_up      = "[+] Agent connected: %s" ascii
        $log_tunnel_srv    = "[+] Tunnel: %s -> %s" ascii
        $log_socks         = "[+] SOCKS5: %s" ascii
        $log_agent_down    = "[-] Agent disconnected: %s" ascii

        // Session log strings
        $log_ws_upgrade    = "WS upgrade failed" ascii
        $log_ssh_handshake = "SSH handshake failed" ascii
        $log_config_timeout = "Config timeout" ascii

    condition:
        3 of ($log_*)
}

rule BarrelShot_DLLExports {
    meta:
        description = "Barrel-Shot DLL sideloading build: GoNow, RunAgent, and ServiceMain exports"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        scan_context = "file"
        os = "windows"

    strings:
        // DLL export function names (Go //export directives)
        $export_gonow       = "GoNow" ascii
        $export_runagent    = "RunAgent" ascii
        $export_servicemain = "ServiceMain" ascii

        // Go module path confirming this is barrel-shot
        $mod_path = "barrel-shot" ascii

    condition:
        $mod_path and 2 of ($export_*)
}

rule BarrelShot_BuildPaths {
    meta:
        description = "Barrel-Shot build artifacts: source paths leaked in Go binary"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        scan_context = "file"
        os = "windows, linux"

    strings:
        // Build host source paths (embedded in Go runtime debug info)
        $path1 = "op-triple-barrel/barrel-shot/" ascii
        $path2 = "barrel-shot/agent/agent.go" ascii
        $path3 = "barrel-shot/agent/embed.go" ascii
        $path4 = "barrel-shot/server/server.go" ascii
        $path5 = "barrel-shot/share/protocol.go" ascii
        $path6 = "barrel-shot/share/crypto.go" ascii

    condition:
        3 of them
}

rule BarrelShot_UsageStrings {
    meta:
        description = "Barrel-Shot CLI usage and help text"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        scan_context = "file"
        os = "windows, linux"

    strings:
        $usage1 = "barrel-shot - RDP/SSH tunneling tool" ascii
        $usage2 = "Usage: barrel-shot" ascii
        $usage3 = "barrel-shot agent" ascii
        $usage4 = "barrel-shot server" ascii
        $usage5 = "barrel-shot keygen" ascii

    condition:
        2 of them
}

rule BarrelShot_ConfigPayload {
    meta:
        description = "Barrel-Shot SSH config request: JSON payload with protocol version marker"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        scan_context = "file, memory"
        os = "windows, linux"

    strings:
        // JSON config structure sent over SSH global request
        // Contains version field and remotes array
        $config_json = /\{"v":"barrel-shot-1","r":\[/ ascii

        // SSH global request type
        $req_type = "config" ascii

        // Ping/pong keepalive
        $ping = "ping" ascii
        $pong = "pong" ascii

        // Protocol identifier
        $proto = "barrel-shot-1" ascii

    condition:
        $config_json
        or ($proto and $req_type)
}

rule BarrelShot_Combined {
    meta:
        description = "Barrel-Shot composite: Go-based SSH/WebSocket tunneling agent"
        author = "Operation Triple Barrel"
        date = "2026-08-22"
        scan_context = "file"
        os = "windows, linux"

    strings:
        // Core identifiers
        $proto      = "barrel-shot-1" ascii
        $ssh_ver    = "SSH-2.0-barrel-shot-1" ascii
        $chan        = "barrel-shot" ascii
        $mod_path   = "barrel-shot/agent" ascii

        // Operational strings
        $connecting = "[agent] Connecting to %s" ascii
        $agent_up   = "[+] Agent connected" ascii
        $socks      = "SOCKS5" ascii

        // Config symbols
        $embed      = "embeddedServer" ascii
        $embed2     = "embeddedRemotes" ascii

        // Dependencies (gorilla websocket, go-socks5)
        $dep_ws     = "gorilla/websocket" ascii
        $dep_socks  = "armon/go-socks5" ascii

    condition:
        ($ssh_ver or $proto) and $mod_path
        or $chan and 2 of ($connecting, $agent_up, $embed, $embed2)
        or $mod_path and $dep_ws and $dep_socks
}
