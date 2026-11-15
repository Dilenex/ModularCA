using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// A CRL distribution point on the loopback interface, for tests that need an online revocation
/// check to actually succeed, or to actually find a revocation, rather than only to fail for want
/// of somewhere to ask.
/// <para>
/// It is a bare socket listener speaking just enough HTTP/1.1 to answer a GET, so it needs no URL
/// reservation on Windows and behaves the same on Linux. Every published CRL gets a URL with a
/// fresh random path: both chain engines cache what they download by URL (Windows in the
/// machine's URL cache, the OpenSSL-backed engine in a per-user directory), and a URL that has
/// never existed before cannot be answered from a cache left by an earlier run.
/// </para>
/// <para>
/// It counts the requests it serves per URL, so a test can show that a check went to the network
/// (or, for a certificate that should have been turned away first, that it did not).
/// </para>
/// </summary>
internal sealed class LocalCrlServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, byte[]> _bodies = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, int> _requests = new(StringComparer.Ordinal);
    private readonly Task _accepting;

    /// <summary>Starts listening on a free loopback port.</summary>
    public LocalCrlServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _accepting = Task.Run(AcceptAsync);
    }

    /// <summary>The port being listened on.</summary>
    public int Port { get; }

    /// <summary>
    /// Reserves a URL that answers 404 until <see cref="Publish"/> is given something for it. A
    /// certificate has to name its distribution point before the CRL that will list (or not list)
    /// it can be built.
    /// </summary>
    public string NewUrl() => $"http://127.0.0.1:{Port}/{Guid.NewGuid():N}.crl";

    /// <summary>Serves <paramref name="crl"/> at <paramref name="url"/>, a URL from <see cref="NewUrl"/>.</summary>
    /// <param name="url">The distribution point.</param>
    /// <param name="crl">The DER-encoded CRL.</param>
    public void Publish(string url, byte[] crl) => _bodies[new Uri(url).AbsolutePath] = crl;

    /// <summary>How many requests have arrived for <paramref name="url"/>, answered or not.</summary>
    /// <param name="url">The distribution point.</param>
    public int RequestsFor(string url) => _requests.GetValueOrDefault(new Uri(url).AbsolutePath);

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                return;
            }
            _ = Task.Run(() => ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        try
        {
            using (client)
            {
                client.ReceiveTimeout = 5000;
                var stream = client.GetStream();
                var head = await ReadHeadAsync(stream);
                var parts = head.Split(' ');
                if (parts.Length < 2)
                    return;
                var method = parts[0];
                var path = parts[1];
                if (Uri.TryCreate(path, UriKind.Absolute, out var absolute))
                    path = absolute.AbsolutePath;
                _requests.AddOrUpdate(path, 1, (_, n) => n + 1);

                var found = _bodies.TryGetValue(path, out var body);
                body ??= [];
                var header = (found ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 404 Not Found\r\n")
                    + "Content-Type: application/pkix-crl\r\n"
                    + $"Content-Length: {body.Length}\r\n"
                    + "Connection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(header));
                if (!string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase))
                    await stream.WriteAsync(body);
                await stream.FlushAsync();
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // The client went away; nothing to answer.
        }
    }

    /// <summary>Reads up to the blank line that ends the request head and returns the request line.</summary>
    private static async Task<string> ReadHeadAsync(NetworkStream stream)
    {
        var buffer = new byte[8192];
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read));
            if (n == 0)
                break;
            read += n;
            if (Encoding.ASCII.GetString(buffer, 0, read).Contains("\r\n\r\n", StringComparison.Ordinal))
                break;
        }
        var text = Encoding.ASCII.GetString(buffer, 0, read);
        var end = text.IndexOf("\r\n", StringComparison.Ordinal);
        return end < 0 ? text : text[..end];
    }

    /// <summary>Stops listening.</summary>
    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        try
        {
            _accepting.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // Already stopping.
        }
        _stop.Dispose();
    }
}
