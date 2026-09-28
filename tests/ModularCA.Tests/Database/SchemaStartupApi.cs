using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace ModularCA.Tests.Database;

/// <summary>
/// <c>ModularCA.API.Startup.SchemaStartup</c>, reached through the API build output the way the
/// endpoint tests reach controllers: the test project does not reference the host.
/// </summary>
internal static class SchemaStartupApi
{
    private const string Namespace = "ModularCA.API.Startup.";

    private static Type Startup => ApiAssembly.TypeNamed(Namespace + "SchemaStartup");

    /// <summary><c>SchemaStartup.ExitCode</c>: the operator must act.</summary>
    public static int ExitCode => (int)Startup.GetField("ExitCode")!.GetRawConstantValue()!;

    /// <summary><c>SchemaStartup.TempFailExitCode</c>: the service manager retries.</summary>
    public static int TempFailExitCode => (int)Startup.GetField("TempFailExitCode")!.GetRawConstantValue()!;

    /// <summary>
    /// Calls <c>SchemaStartup.EnforceAllAsync</c> with no systemd notifier and returns its exit
    /// code, or null when the process would continue starting.
    /// </summary>
    public static Task<int?> EnforceAllAsync(
        IReadOnlyList<(string Name, DatabaseKind Kind, DbInstance Instance)> targets,
        bool appliesMigrations, SchemaConfig config, CancellationToken ct = default) =>
        EnforceAllAsync(targets, appliesMigrations, config, null, ct);

    /// <summary>
    /// Calls <c>SchemaStartup.EnforceAllAsync</c> with <paramref name="notifier"/>, an
    /// <c>ISystemdNotifier</c> such as <see cref="RecordingNotifier.Create"/> returns.
    /// </summary>
    public static async Task<int?> EnforceAllAsync(
        IReadOnlyList<(string Name, DatabaseKind Kind, DbInstance Instance)> targets,
        bool appliesMigrations, SchemaConfig config, object? notifier, CancellationToken ct = default)
    {
        var targetType = ApiAssembly.TypeNamed(Namespace + "SchemaTarget");
        var array = Array.CreateInstance(targetType, targets.Count);
        for (var i = 0; i < targets.Count; i++)
            array.SetValue(Activator.CreateInstance(targetType, targets[i].Name, targets[i].Kind, targets[i].Instance), i);
        var method = Startup.GetMethod("EnforceAllAsync", BindingFlags.Public | BindingFlags.Static)!;
        return await (Task<int?>)method.Invoke(null, [array, appliesMigrations, config, notifier, ct])!;
    }

    /// <summary>The <c>ISystemdNotifier</c> type <c>EnforceAllAsync</c> takes.</summary>
    public static Type NotifierType =>
        Startup.GetMethod("EnforceAllAsync", BindingFlags.Public | BindingFlags.Static)!.GetParameters()[3].ParameterType;

    /// <summary>Calls <c>SchemaStartup.UseHeartbeatInterval</c> for the calling async flow.</summary>
    public static void UseHeartbeatInterval(TimeSpan? interval) =>
        Startup.GetMethod("UseHeartbeatInterval", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [interval]);

    /// <summary>Calls <c>SchemaStartup.CheckOwnershipAsync</c>, the <c>--db-ownership check</c> verb.</summary>
    public static async Task<int> CheckOwnershipAsync(
        IReadOnlyList<(string Name, DatabaseKind Kind, DbInstance Instance)> targets, CancellationToken ct = default)
    {
        var targetType = ApiAssembly.TypeNamed(Namespace + "SchemaTarget");
        var array = Array.CreateInstance(targetType, targets.Count);
        for (var i = 0; i < targets.Count; i++)
            array.SetValue(Activator.CreateInstance(targetType, targets[i].Name, targets[i].Kind, targets[i].Instance), i);
        var method = Startup.GetMethod("CheckOwnershipAsync", BindingFlags.Public | BindingFlags.Static)!;
        return await (Task<int>)method.Invoke(null, [array, ct])!;
    }

    /// <summary>
    /// Calls <c>SchemaStartup.UseContextFactory</c>: for the calling async flow, the startup check
    /// builds its contexts with <paramref name="factory"/> (kind, connection string, command
    /// timeout), or with the real contexts again when it is null.
    /// </summary>
    public static void UseContextFactory(Func<DatabaseKind, string, int, Microsoft.EntityFrameworkCore.DbContext>? factory) =>
        Startup.GetMethod("UseContextFactory", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [factory]);

    /// <summary>The gate-read connection string the startup check reads with.</summary>
    public static string GateReadConnectionString(DbInstance instance) =>
        (string)Startup.GetMethod("GateReadConnectionString", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [instance])!;

    /// <summary>The migration connection string the control role migrates with.</summary>
    public static string MigrationConnectionString(DbInstance instance, SchemaConfig config) =>
        (string)Startup.GetMethod("MigrationConnectionString", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [instance, config])!;
}

/// <summary>
/// An enabled <c>ISystemdNotifier</c>, built at run time because the test project does not
/// reference the systemd hosting package, that records every notification it is sent.
/// </summary>
public class RecordingNotifier : DispatchProxy
{
    private readonly ConcurrentQueue<string> _sent = new();

    /// <summary>Every notification so far, as the text systemd would receive.</summary>
    public IReadOnlyList<string> Sent => _sent.ToList();

    /// <summary>A new recording notifier, typed as the notifier interface <c>EnforceAllAsync</c> takes.</summary>
    public static object Create() => DispatchProxy.Create(SchemaStartupApi.NotifierType, typeof(RecordingNotifier));

    /// <inheritdoc/>
    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        switch (targetMethod?.Name)
        {
            case "get_IsEnabled":
                return true;
            case "Notify":
                _sent.Enqueue(args?[0]?.ToString() ?? "");
                return null;
            default:
                return null;
        }
    }
}

/// <summary>
/// Replaces the global Serilog logger with one that keeps every event, for the lifetime of the
/// instance, and puts the previous logger back on dispose.
/// </summary>
internal sealed class CapturedSerilog : IDisposable, ILogEventSink
{
    private readonly ILogger _previous = Log.Logger;
    private readonly ConcurrentQueue<LogEvent> _events = new();

    /// <summary>Starts capturing.</summary>
    public CapturedSerilog()
    {
        Log.Logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(this).CreateLogger();
    }

    /// <summary>Every event so far, rendered, with its level.</summary>
    public IReadOnlyList<(LogEventLevel Level, string Text)> Events =>
        _events.Select(e => (e.Level, e.RenderMessage())).ToList();

    /// <summary>Whether an event at <paramref name="level"/> contains <paramref name="text"/>.</summary>
    public bool Has(LogEventLevel level, string text) => Events.Any(e => e.Level == level && e.Text.Contains(text, StringComparison.Ordinal));

    /// <inheritdoc/>
    public void Emit(LogEvent logEvent) => _events.Enqueue(logEvent);

    /// <summary>Restores the previous logger.</summary>
    public void Dispose() => Log.Logger = _previous;
}

/// <summary>
/// A loopback listener that speaks just enough of the PostgreSQL wire protocol to refuse every
/// connection with one error: it declines TLS and GSS encryption, reads the startup message and
/// answers with an ErrorResponse carrying <c>sqlState</c>. Lets the startup check's connect-phase
/// classification run without a server.
/// </summary>
internal sealed class RefusingPostgres : IAsyncDisposable
{
    private const int SslRequestCode = 80877103;
    private const int GssEncRequestCode = 80877104;

    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly string _sqlState;
    private readonly string _message;
    private readonly Task _loop;
    private int _connections;

    /// <summary>Starts listening; every connection is refused with <paramref name="sqlState"/>.</summary>
    public RefusingPostgres(string sqlState, string message)
    {
        _sqlState = sqlState;
        _message = message;
        _listener.Start();
        _loop = AcceptAsync();
    }

    /// <summary>The loopback port it listens on.</summary>
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>How many connections it has answered.</summary>
    public int Connections => Volatile.Read(ref _connections);

    /// <summary>A <c>db.yaml</c> instance pointing at this listener, without TLS.</summary>
    public DbInstance Instance(string database, string username) => new()
    {
        Host = "127.0.0.1", Port = Port, Database = database, Username = username, Password = "not-used", SslMode = "Disable",
    };

    /// <summary>Accepts connections until disposed.</summary>
    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                _ = ServeAsync(client);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <summary>Declines encryption requests, reads the startup message, and sends the error.</summary>
    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                while (true)
                {
                    var length = await ReadInt32Async(stream);
                    var code = await ReadInt32Async(stream);
                    await ReadExactlyAsync(stream, length - 8);
                    if (code is SslRequestCode or GssEncRequestCode)
                    {
                        stream.WriteByte((byte)'N');
                        await stream.FlushAsync(_stop.Token);
                        continue;
                    }
                    break;
                }
                Interlocked.Increment(ref _connections);
                await stream.WriteAsync(ErrorResponse(), _stop.Token);
                await stream.FlushAsync(_stop.Token);
            }
            catch (Exception)
            {
            }
        }
    }

    /// <summary>An ErrorResponse message with severity FATAL, the SQLSTATE and the message.</summary>
    private byte[] ErrorResponse()
    {
        var body = new MemoryStream();
        void Field(char type, string value)
        {
            body.WriteByte((byte)type);
            var bytes = Encoding.UTF8.GetBytes(value);
            body.Write(bytes);
            body.WriteByte(0);
        }
        Field('S', "FATAL");
        Field('V', "FATAL");
        Field('C', _sqlState);
        Field('M', _message);
        body.WriteByte(0);
        var payload = body.ToArray();
        var message = new byte[1 + 4 + payload.Length];
        message[0] = (byte)'E';
        var length = IPAddress.HostToNetworkOrder(4 + payload.Length);
        BitConverter.GetBytes(length).CopyTo(message, 1);
        payload.CopyTo(message, 5);
        return message;
    }

    /// <summary>Reads a big-endian 32-bit integer.</summary>
    private async Task<int> ReadInt32Async(NetworkStream stream)
    {
        var bytes = await ReadExactlyAsync(stream, 4);
        return IPAddress.NetworkToHostOrder(BitConverter.ToInt32(bytes, 0));
    }

    /// <summary>Reads exactly <paramref name="count"/> bytes.</summary>
    private async Task<byte[]> ReadExactlyAsync(NetworkStream stream, int count)
    {
        var buffer = new byte[Math.Max(0, count)];
        await stream.ReadExactlyAsync(buffer, _stop.Token);
        return buffer;
    }

    /// <summary>Stops listening.</summary>
    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        try { await _loop; } catch (Exception) { }
        _stop.Dispose();
    }
}
