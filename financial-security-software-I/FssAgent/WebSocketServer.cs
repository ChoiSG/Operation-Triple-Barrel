using System.Net;
using System.Net.WebSockets;
using System.Text;

namespace FssAgent;

class WebSocketServer
{
    private readonly HttpListener _listener;
    private readonly CommandHandler _handler = new();

    public WebSocketServer(string prefix)
    {
        _listener = new HttpListener();
        _listener.Prefixes.Add(prefix);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _listener.Start();

        while (!ct.IsCancellationRequested)
        {
            var context = await _listener.GetContextAsync().WaitAsync(ct);

            if (context.Request.IsWebSocketRequest)
            {
                _ = HandleConnectionAsync(context, ct);
            }
            else
            {
                context.Response.StatusCode = 400;
                context.Response.Close();
            }
        }
    }

    private async Task HandleConnectionAsync(HttpListenerContext httpContext, CancellationToken ct)
    {
        var wsContext = await httpContext.AcceptWebSocketAsync(null);
        var ws = wsContext.WebSocket;
        var buffer = new byte[4096];

        Console.WriteLine($"[FinSecI] Client connected: {httpContext.Request.RemoteEndPoint}");

        try
        {
            while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
            {
                var result = await ws.ReceiveAsync(buffer, ct);

                if (result.MessageType == WebSocketMessageType.Close)
                    break;

                var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                Console.WriteLine($"[FinSecI] Recv: {message}");

                var response = await _handler.HandleAsync(message);
                var responseBytes = Encoding.UTF8.GetBytes(response);

                Console.WriteLine($"[FinSecI] Resp: {response}");

                await ws.SendAsync(responseBytes, WebSocketMessageType.Text, true, ct);
            }
        }
        catch (WebSocketException)
        {
            // client disconnected
        }

        Console.WriteLine("[FinSecI] Client disconnected");
    }
}
