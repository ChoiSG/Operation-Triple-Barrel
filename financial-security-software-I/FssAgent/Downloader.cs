using System.IO.Compression;

namespace FssAgent;

static class Downloader
{
    private static readonly HttpClient Http = new();

    public static async Task<bool> DownloadAsync(string url, string destDir)
    {
        try
        {
            var bytes = await Http.GetByteArrayAsync(url);
            var fileName = GetFileName(url);
            var destPath = Path.Combine(destDir, fileName);

            if (IsZip(bytes))
            {
                Console.WriteLine($"[FinSecI] ZIP detected - extracting to: {destDir}");
                using var ms = new MemoryStream(bytes);
                using var archive = new ZipArchive(ms, ZipArchiveMode.Read);
                archive.ExtractToDirectory(destDir, overwriteFiles: true);
            }
            else
            {
                Console.WriteLine($"[FinSecI] Saving file: {destPath}");
                await File.WriteAllBytesAsync(destPath, bytes);
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FinSecI] Download error: {ex.Message}");
            return false;
        }
    }

    private static string GetFileName(string url)
    {
        var uri = new Uri(url);
        var name = Path.GetFileName(uri.LocalPath);
        return string.IsNullOrWhiteSpace(name) ? "update.bin" : name;
    }

    private static bool IsZip(byte[] data)
    {
        return data.Length >= 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04;
    }
}
