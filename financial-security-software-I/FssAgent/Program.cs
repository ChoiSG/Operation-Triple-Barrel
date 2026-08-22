namespace FssAgent;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("[FinSecI v3.3.2.41] Starting...");
        Console.WriteLine("[FinSecI] Initialized");
        Console.WriteLine("[FinSecI] WebSocket server started: ws://127.0.0.1:4441");
        Console.WriteLine("[FinSecI] Waiting for browser connections...");
        Console.WriteLine();

        var server = new WebSocketServer("http://127.0.0.1:4441/");
        var cts = new CancellationTokenSource();

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            await server.RunAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("[FinSecI] Shutting down...");
        }
    }
}
