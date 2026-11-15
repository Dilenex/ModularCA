using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.HubConnection.Contract;

namespace ModularCA.HubConnection.Server;

/// <summary>Where and how the hub's local connection listens.</summary>
/// <param name="SocketPath">The Unix domain socket's path (<c>MODULARCA__HUB__SOCKET</c>).</param>
/// <param name="SocketMode">The socket file's permission bits (<c>MODULARCA__HUB__SOCKETMODE</c>); 0660 when unset. Not applied on Windows.</param>
/// <param name="LedgerPath">The file the carried-out request identifiers are kept in, or null to keep them in memory only.</param>
public sealed record HubLocalHostOptions(string SocketPath, UnixFileMode SocketMode = HubLocalHostOptions.DefaultSocketMode, string? LedgerPath = null)
{
    /// <summary>The environment variable that names the socket; unset, the instance opens nothing for a hub.</summary>
    public const string SocketVariable = "MODULARCA__HUB__SOCKET";

    /// <summary>The environment variable that sets the socket file's mode, in octal: <c>0660</c>, <c>0600</c>, <c>0666</c>.</summary>
    public const string SocketModeVariable = "MODULARCA__HUB__SOCKETMODE";

    /// <summary>0660: the owner and the group read and write, nobody else.</summary>
    public const UnixFileMode DefaultSocketMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite;

    /// <summary>The longest socket path every platform's <c>sockaddr_un</c> takes.</summary>
    public const int MaxSocketPathLength = 100;

    /// <summary>
    /// Parses a socket mode: three or four octal digits naming read and write bits only
    /// (<c>0600</c>, <c>0660</c>, <c>0666</c>, <c>0620</c>). Null or empty is
    /// <see cref="DefaultSocketMode"/>. Anything else throws <see cref="ArgumentException"/>:
    /// an execute, set-id or sticky bit means nothing on a socket and is taken for a mistake.
    /// </summary>
    /// <param name="text">The value of <see cref="SocketModeVariable"/>.</param>
    public static UnixFileMode ParseSocketMode(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return DefaultSocketMode;
        var digits = text.Trim();
        if (digits.Length is < 3 or > 4 || digits.Any(c => c is < '0' or > '7'))
            throw new ArgumentException($"{SocketModeVariable} is '{text}'; it takes an octal mode such as 0660.");
        var value = Convert.ToInt32(digits, 8);
        if ((value & ~0b110_110_110) != 0 || (value & 0b110_000_000) != 0b110_000_000)
            throw new ArgumentException($"{SocketModeVariable} is '{text}'; it takes read and write bits only, and the owner must have both (0600, 0660, 0666).");
        return (UnixFileMode)value;
    }
}

/// <summary>
/// The listener for the hub alone: its own Kestrel host on a Unix domain socket, with its own
/// pipeline of one step. It shares no listener, route or middleware with the node's HTTPS, HTTP
/// and health listeners, so nothing reachable there reaches a hub request, and a hub request
/// reaches nothing but the operations of <see cref="HubLocalContract.Operations"/>.
/// </summary>
/// <remarks>
/// Each request, in this order:
/// <list type="number">
/// <item>The token. When the instance holds a hash, the request's bearer token is hashed and
/// compared in constant time; a missing or wrong token is answered 401 before the body is read.
/// With no hash the check is off.</item>
/// <item>The list. A method and path that are not an operation are answered 404.</item>
/// <item>The version. A missing or incompatible <see cref="HubLocalContract.ContractHeader"/> is answered 400.</item>
/// <item>For an operation that changes something, the request identifier: required, and a
/// repeat is answered from the ledger without doing anything again.</item>
/// <item>The operation.</item>
/// </list>
/// Every request, served or refused, is handed to <see cref="IHubLocalOperations.AuditAsync"/>.
/// </remarks>
public static class HubLocalHost
{
    private const string NoConfigReloadArgument = "--hostBuilder:reloadConfigOnChange=false";

    /// <summary>
    /// Builds the host. Nothing listens until <see cref="StartAsync"/>.
    /// </summary>
    /// <param name="options">The socket and the ledger.</param>
    /// <param name="operations">What the node does for each request.</param>
    /// <param name="configure">Further host configuration (logging), or null.</param>
    public static WebApplication Build(HubLocalHostOptions options, IHubLocalOperations operations, Action<WebApplicationBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(operations);
        var socketPath = Path.GetFullPath(options.SocketPath);
        if (Encoding.UTF8.GetByteCount(socketPath) > HubLocalHostOptions.MaxSocketPathLength)
            throw new ArgumentException(
                $"{HubLocalHostOptions.SocketVariable} names a path of more than {HubLocalHostOptions.MaxSocketPathLength} bytes ('{socketPath}'); a Unix socket path cannot be that long.");

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [NoConfigReloadArgument] });
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = HubLocalContract.MaxBodyBytes;
            kestrel.Limits.MaxConcurrentConnections = 16;
            kestrel.ListenUnixSocket(socketPath, listen => listen.Protocols = HttpProtocols.Http1);
        });
        configure?.Invoke(builder);

        var app = builder.Build();
        var handler = new Handler(operations, new HubRequestLedger(options.LedgerPath), app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("ModularCA.HubConnection"));
        app.Run(handler.HandleAsync);
        return app;
    }

    /// <summary>
    /// Starts listening: makes the socket's directory if it is missing, removes a socket file a
    /// previous run left, binds, and sets the socket file's mode.
    /// </summary>
    /// <param name="app">The host from <see cref="Build"/>.</param>
    /// <param name="options">The options it was built with.</param>
    /// <param name="cancellationToken">Cancels the start.</param>
    public static async Task StartAsync(WebApplication app, HubLocalHostOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);
        var socketPath = Path.GetFullPath(options.SocketPath);
        if (Path.GetDirectoryName(socketPath) is { Length: > 0 } directory)
            Directory.CreateDirectory(directory);
        // A socket file left by a run that did not stop cleanly would make the bind fail.
        if (File.Exists(socketPath))
            File.Delete(socketPath);

        await app.StartAsync(cancellationToken);

        // The socket is created with the process's umask; a connect needs write permission, so
        // until this line nobody the mode is meant to admit beyond the owner can connect.
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(socketPath, options.SocketMode);
    }

    /// <summary>The operation a method and path name, or null when they name none.</summary>
    /// <param name="method">The HTTP method.</param>
    /// <param name="path">The request path.</param>
    public static string? OperationOf(string method, string? path) => (method.ToUpperInvariant(), path?.TrimEnd('/')) switch
    {
        ("POST", HubLocalContract.Paths.Hello) => HubLocalContract.Operations.Hello,
        ("GET", HubLocalContract.Paths.Health) => HubLocalContract.Operations.HealthRead,
        ("GET", HubLocalContract.Paths.Mode) => HubLocalContract.Operations.ModeRead,
        ("PUT", HubLocalContract.Paths.Mode) => HubLocalContract.Operations.ModeSet,
        ("POST", HubLocalContract.Paths.Backup) => HubLocalContract.Operations.BackupCreate,
        ("PUT", HubLocalContract.Paths.AffiliationToken) => HubLocalContract.Operations.AffiliationTokenReplace,
        _ => null,
    };

    /// <summary>The SHA-256 of a token as the instance compares it: of the UTF-8 bytes of the token with surrounding white space removed.</summary>
    /// <param name="token">The token.</param>
    public static byte[] HashToken(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token.Trim()));

    /// <summary>Parses a SHA-256 written as 64 hex digits, in either case.</summary>
    /// <param name="hex">The text.</param>
    /// <param name="hash">The 32 bytes, when the text is a SHA-256.</param>
    public static bool TryParseHashHex(string? hex, out byte[] hash)
    {
        hash = [];
        var text = hex?.Trim();
        if (text is not { Length: 64 } || !text.All(Uri.IsHexDigit))
            return false;
        hash = Convert.FromHexString(text);
        return true;
    }

    private sealed class Handler(IHubLocalOperations operations, HubRequestLedger ledger, ILogger logger)
    {
        // One changing request at a time: the ledger's look-up and its entry must not interleave.
        private readonly SemaphoreSlim _changes = new(1, 1);

        private sealed class Refused(int status, string code, string message, bool listOperations = false) : Exception(message)
        {
            public int Status { get; } = status;
            public string Code { get; } = code;
            public bool ListOperations { get; } = listOperations;
        }

        public async Task HandleAsync(HttpContext http)
        {
            var request = http.Request;
            var operation = OperationOf(request.Method, request.Path.Value);
            var hash = operations.AffiliationTokenHash;
            var tokenCheck = hash == null ? HubLocalContract.TokenCheckOff : HubLocalContract.TokenCheckEnforced;
            var operatorName = Clean(request.Headers[HubLocalContract.OperatorHeader].ToString());
            var requestId = Clean(request.Headers[HubLocalContract.RequestIdHeader].ToString());
            var statedVersion = Clean(request.Headers[HubLocalContract.ContractHeader].ToString());
            var status = StatusCodes.Status200OK;
            string? refusal = null;
            var replayed = false;
            string body;

            try
            {
                // 1. The token, before anything of the request is read or interpreted.
                if (hash != null)
                {
                    var authorization = request.Headers.Authorization.ToString();
                    if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || authorization.Length <= 7)
                        throw new Refused(401, HubLocalContract.Errors.TokenRequired, "This instance has an affiliation token; send it as Authorization: Bearer.");
                    if (!CryptographicOperations.FixedTimeEquals(HashToken(authorization[7..]), hash))
                        throw new Refused(401, HubLocalContract.Errors.TokenInvalid, "The token is not this instance's affiliation token.");
                }

                // 2. The list.
                if (operation == null)
                    throw new Refused(404, HubLocalContract.Errors.OperationNotListed,
                        $"{request.Method} {request.Path.Value} is not an operation of the hub's local connection.", listOperations: true);

                // 3. The version.
                if (!HubLocalContract.IsCompatible(statedVersion))
                    throw new Refused(400, HubLocalContract.Errors.ContractVersionUnsupported,
                        $"Send {HubLocalContract.ContractHeader} with a version of major {HubLocalContract.MajorVersion}; this instance speaks {HubLocalContract.Version}.", listOperations: true);

                (status, body, replayed) = operation switch
                {
                    HubLocalContract.Operations.HealthRead => (200, Json(await HealthAsync(tokenCheck, http.RequestAborted)), false),
                    HubLocalContract.Operations.ModeRead => (200, Json(operations.ReadMode()), false),
                    HubLocalContract.Operations.Hello => (200, Json(Hello(await ReadAsync<HubHello>(http), tokenCheck)), false),
                    _ => await ChangeAsync(http, operation, requestId, operatorName),
                };
            }
            catch (Refused ex)
            {
                status = ex.Status;
                refusal = ex.Code;
                body = Json(new HubError(ex.Code, ex.Message, HubLocalContract.Version, ex.ListOperations ? HubLocalContract.Operations.All : null));
            }
            catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Hub local connection: {Operation} failed", operation);
                status = 500;
                refusal = operation == HubLocalContract.Operations.BackupCreate ? HubLocalContract.Errors.BackupFailed : HubLocalContract.Errors.InternalError;
                body = Json(new HubError(refusal, "The instance could not carry out the request; its log has the cause.", HubLocalContract.Version));
            }

            try
            {
                await operations.AuditAsync(new HubRequestRecord(
                    operation, request.Method, request.Path.Value ?? string.Empty, status, refusal,
                    requestId, operatorName, statedVersion, replayed, tokenCheck), CancellationToken.None);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Hub local connection: the audit record of {Method} {Path} ({Status}) could not be written", request.Method, request.Path.Value, status);
            }

            http.Response.StatusCode = status;
            http.Response.ContentType = "application/json; charset=utf-8";
            if (replayed)
                http.Response.Headers[HubLocalContract.ReplayedHeader] = "true";
            if (status == 401)
            {
                // The body was not read and is not going to be.
                http.Response.Headers.WWWAuthenticate = "Bearer";
                http.Response.Headers.Connection = "close";
            }
            await http.Response.WriteAsync(body, http.RequestAborted);
        }

        private async Task<HubHealth> HealthAsync(string tokenCheck, CancellationToken cancellationToken)
        {
            var report = await operations.ReadHealthAsync(cancellationToken);
            return new HubHealth(report.Status, operations.ReadMode(), tokenCheck, operations.InstanceVersion,
                HubLocalContract.Version, DateTime.UtcNow, report.Checks);
        }

        private HubHello Hello(HubHello theirs, string tokenCheck)
        {
            if (!HubLocalContract.IsCompatible(theirs.ContractVersion))
                throw new Refused(400, HubLocalContract.Errors.ContractVersionUnsupported,
                    $"The hub states contract version '{theirs.ContractVersion}'; this instance speaks {HubLocalContract.Version}.", listOperations: true);
            return new HubHello(HubLocalContract.Version, HubLocalContract.Operations.All, operations.InstanceVersion, tokenCheck);
        }

        /// <summary>An operation that changes something: done once per request identifier.</summary>
        private async Task<(int Status, string Body, bool Replayed)> ChangeAsync(HttpContext http, string operation, string? requestId, string? operatorName)
        {
            if (requestId == null || !requestId.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '-'))
                throw new Refused(400, HubLocalContract.Errors.RequestIdRequired,
                    $"Send {HubLocalContract.RequestIdHeader}: 1 to {HubLocalContract.MaxHeaderValueLength} letters, digits, '.', '_', ':' or '-'. The same identifier sent again is answered without doing the request twice.");

            var raw = await ReadBodyAsync(http);
            var bodyHash = Convert.ToHexString(SHA256.HashData(raw));

            await _changes.WaitAsync(http.RequestAborted);
            try
            {
                if (ledger.Find(requestId) is { } done)
                {
                    if (done.Operation != operation || done.BodySha256 != bodyHash)
                        throw new Refused(409, HubLocalContract.Errors.RequestIdReused,
                            $"Request identifier '{requestId}' was already used for a different request ({done.Operation}).");
                    return (done.Status, done.ResponseJson, true);
                }

                string json;
                switch (operation)
                {
                    case HubLocalContract.Operations.ModeSet:
                        var set = Parse<HubSetModeRequest>(raw);
                        if (set.Reason is { Length: > 500 })
                            throw new Refused(400, HubLocalContract.Errors.InvalidRequest, "The reason is limited to 500 characters.");
                        try
                        {
                            json = Json(await operations.SetModeAsync(set.Mode ?? string.Empty, set.Reason, operatorName, http.RequestAborted));
                        }
                        catch (ArgumentException ex)
                        {
                            throw new Refused(400, HubLocalContract.Errors.InvalidRequest, ex.Message);
                        }
                        break;
                    case HubLocalContract.Operations.BackupCreate:
                        json = Json(await operations.CreateBackupAsync(operatorName, http.RequestAborted));
                        break;
                    case HubLocalContract.Operations.AffiliationTokenReplace:
                        if (!TryParseHashHex(Parse<HubReplaceTokenRequest>(raw).NewTokenSha256, out var newHash))
                            throw new Refused(400, HubLocalContract.Errors.InvalidRequest, "newTokenSha256 must be the SHA-256 of the new token as 64 hex digits; never the token itself.");
                        await operations.ReplaceAffiliationTokenAsync(newHash, operatorName, http.RequestAborted);
                        json = Json(new HubReplaceTokenResult(HubLocalContract.TokenCheckEnforced));
                        break;
                    default:
                        throw new InvalidOperationException($"No handler for {operation}.");
                }

                ledger.Remember(new HubRequestLedger.Entry(requestId, operation, bodyHash, 200, json, DateTime.UtcNow));
                return (200, json, false);
            }
            finally
            {
                _changes.Release();
            }
        }

        private static async Task<byte[]> ReadBodyAsync(HttpContext http)
        {
            using var buffer = new MemoryStream();
            try
            {
                await http.Request.Body.CopyToAsync(buffer, http.RequestAborted);
            }
            catch (Microsoft.AspNetCore.Http.BadHttpRequestException)
            {
                throw new Refused(400, HubLocalContract.Errors.InvalidRequest, $"The body is limited to {HubLocalContract.MaxBodyBytes} bytes.");
            }
            return buffer.ToArray();
        }

        private static async Task<T> ReadAsync<T>(HttpContext http) => Parse<T>(await ReadBodyAsync(http));

        private static T Parse<T>(byte[] raw)
        {
            try
            {
                return JsonSerializer.Deserialize<T>(raw, HubLocalContract.Json)
                    ?? throw new Refused(400, HubLocalContract.Errors.InvalidRequest, "The body is empty.");
            }
            catch (JsonException)
            {
                throw new Refused(400, HubLocalContract.Errors.InvalidRequest, $"The body is not the JSON this operation takes ({typeof(T).Name}).");
            }
        }

        private static string Json<T>(T value) => JsonSerializer.Serialize(value, HubLocalContract.Json);

        /// <summary>A header value as it is recorded: trimmed, without control characters, cut to the limit; null when empty.</summary>
        private static string? Clean(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            var cleaned = new string(value.Trim().Where(c => !char.IsControl(c)).ToArray());
            if (cleaned.Length > HubLocalContract.MaxHeaderValueLength)
                cleaned = cleaned[..HubLocalContract.MaxHeaderValueLength];
            return cleaned.Length == 0 ? null : cleaned;
        }
    }
}
