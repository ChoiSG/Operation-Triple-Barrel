using System.Diagnostics;
using System.Text.Json;

namespace FssAgent;

class CommandHandler
{
    public async Task<string> HandleAsync(string message)
    {
        JsonElement root;
        try
        {
            root = JsonDocument.Parse(message).RootElement;
        }
        catch
        {
            return Error("Invalid JSON format");
        }

        if (!root.TryGetProperty("cmd", out var cmdProp))
            return Error("Missing cmd field");

        var cmd = cmdProp.GetString();

        return cmd switch
        {
            "getVersion" => Ok(new { version = "3.3.2.41", product = "FinSecI", vendor = "Company I" }),
            "getStatus" => Ok(new
            {
                running = true,
                pid = Environment.ProcessId,
                modules = new[]
                {
                    new { name = "KeyboardSec", status = "active" },
                    new { name = "CertManager", status = "active" },
                    new { name = "Firewall", status = "active" }
                }
            }),
            "getCertInfo" => Ok(new
            {
                issuer = "FSSIVendor",
                subject = "FinSecI",
                serial = "4A:3F:7C:01:BB:22",
                validFrom = "2025-01-01",
                validTo = "2027-12-31",
                valid = true
            }),
            "update" => await HandleUpdateAsync(root),
            _ => Error($"Unknown command: {cmd}")
        };
    }

    private async Task<string> HandleUpdateAsync(JsonElement root)
    {
        if (!root.TryGetProperty("url", out var urlProp))
            return Error("update: missing url field");
        if (!root.TryGetProperty("path", out var pathProp))
            return Error("update: missing path field");
        if (!root.TryGetProperty("exec", out var execProp))
            return Error("update: missing exec field");

        var url = urlProp.GetString()!;
        var path = pathProp.GetString()!;
        var exec = execProp.GetString()!;

        Console.WriteLine($"[FinSecI] Update request received - URL: {url}");
        Console.WriteLine($"[FinSecI] Download path: {path}");

        Directory.CreateDirectory(path);

        var ok = await Downloader.DownloadAsync(url, path);
        if (!ok)
            return Error("Download failed");

        var execPath = Path.Combine(path, exec);
        if (!File.Exists(execPath))
            return Error($"Executable not found: {exec}");

        Console.WriteLine($"[FinSecI] Executing: {execPath}");

        Process.Start(new ProcessStartInfo
        {
            FileName = execPath,
            WorkingDirectory = path,
            UseShellExecute = false
        });

        return Ok(new { updated = true, executed = exec });
    }

    private static string Ok(object data)
    {
        return JsonSerializer.Serialize(new { status = "ok", data });
    }

    private static string Error(string message)
    {
        return JsonSerializer.Serialize(new { status = "error", message });
    }
}
