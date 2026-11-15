using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using ModularCA.HubConnection.Contract;

namespace ModularCA.HubConnection.Client;

/// <summary>
/// The hub's side of the local connection: a small client over the instance's Unix domain
/// socket. One per instance; safe for concurrent use. A refusal or failure throws
/// <see cref="HubLocalException"/> with the instance's error code.
/// </summary>
public sealed class HubLocalClient : IDisposable
{
    private readonly HttpClient _http;

    /// <summary>Creates a client for the socket at <paramref name="socketPath"/>.</summary>
    /// <param name="socketPath">The instance's socket.</param>
    /// <param name="token">The affiliation token, or null while the instance holds no hash.</param>
    /// <param name="operatorName">The name of the person at the hub, recorded by the instance as the hub's claim; or null.</param>
    /// <param name="timeout">The time allowed for one request; two minutes when null. A backup may need more.</param>
    public HubLocalClient(string socketPath, string? token = null, string? operatorName = null, TimeSpan? timeout = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(socketPath);
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        // The host name is never resolved: the connection is the socket.
        _http = new HttpClient(handler) { BaseAddress = new Uri("http://hub.local"), Timeout = timeout ?? TimeSpan.FromMinutes(2) };
        _http.DefaultRequestHeaders.Add(HubLocalContract.ContractHeader, HubLocalContract.Version);
        if (!string.IsNullOrWhiteSpace(token))
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());
        if (!string.IsNullOrWhiteSpace(operatorName))
            _http.DefaultRequestHeaders.Add(HubLocalContract.OperatorHeader, operatorName.Trim());
    }

    /// <summary>States this side's contract version and operations and returns the instance's.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<HubHello> HelloAsync(CancellationToken cancellationToken = default)
        => SendAsync<HubHello>(HttpMethod.Post, HubLocalContract.Paths.Hello,
            new HubHello(HubLocalContract.Version, HubLocalContract.Operations.All), null, cancellationToken);

    /// <summary>Reads health as the instance sees it.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<HubHealth> ReadHealthAsync(CancellationToken cancellationToken = default)
        => SendAsync<HubHealth>(HttpMethod.Get, HubLocalContract.Paths.Health, null, null, cancellationToken);

    /// <summary>Reads the mode and who set it.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<HubMode> ReadModeAsync(CancellationToken cancellationToken = default)
        => SendAsync<HubMode>(HttpMethod.Get, HubLocalContract.Paths.Mode, null, null, cancellationToken);

    /// <summary>Sets the mode. Send the same <paramref name="requestId"/> again to repeat safely after a lost answer.</summary>
    /// <param name="mode"><c>full</c>, <c>restricted</c> or <c>dr</c>.</param>
    /// <param name="reason">Why, or null.</param>
    /// <param name="requestId">The request's identifier.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<HubMode> SetModeAsync(string mode, string? reason, string requestId, CancellationToken cancellationToken = default)
        => SendAsync<HubMode>(HttpMethod.Put, HubLocalContract.Paths.Mode, new HubSetModeRequest(mode, reason), requestId, cancellationToken);

    /// <summary>Asks for a backup now.</summary>
    /// <param name="requestId">The request's identifier.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<HubBackupResult> CreateBackupAsync(string requestId, CancellationToken cancellationToken = default)
        => SendAsync<HubBackupResult>(HttpMethod.Post, HubLocalContract.Paths.Backup, new { }, requestId, cancellationToken);

    /// <summary>
    /// Replaces the affiliation token. This client's token authorises the request; afterwards
    /// the instance accepts only the token whose hash was sent, so make a new client with it.
    /// </summary>
    /// <param name="newTokenSha256Hex">The SHA-256 of the new token's UTF-8 bytes, as 64 hex digits.</param>
    /// <param name="requestId">The request's identifier.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<HubReplaceTokenResult> ReplaceAffiliationTokenAsync(string newTokenSha256Hex, string requestId, CancellationToken cancellationToken = default)
        => SendAsync<HubReplaceTokenResult>(HttpMethod.Put, HubLocalContract.Paths.AffiliationToken,
            new HubReplaceTokenRequest(newTokenSha256Hex), requestId, cancellationToken);

    /// <summary>
    /// Sends a request as given and returns the raw response, for callers that need the status,
    /// the headers, or a request this client has no method for.
    /// </summary>
    /// <param name="request">The request; its URI is a path such as <c>/hub/v1/health</c>.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<HttpResponseMessage> SendRawAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
        => _http.SendAsync(request, cancellationToken);

    private async Task<T> SendAsync<T>(HttpMethod method, string path, object? body, string? requestId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body != null)
            request.Content = JsonContent.Create(body, body.GetType(), options: HubLocalContract.Json);
        if (requestId != null)
            request.Headers.Add(HubLocalContract.RequestIdHeader, requestId);
        using var response = await _http.SendAsync(request, cancellationToken);
        var text = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            HubError? error = null;
            try { error = JsonSerializer.Deserialize<HubError>(text, HubLocalContract.Json); } catch (JsonException) { }
            throw new HubLocalException((int)response.StatusCode, error?.Error ?? HubLocalContract.Errors.InternalError,
                error?.Message ?? $"The instance answered {(int)response.StatusCode}.");
        }
        return JsonSerializer.Deserialize<T>(text, HubLocalContract.Json)
            ?? throw new HubLocalException((int)response.StatusCode, HubLocalContract.Errors.InternalError, "The instance sent an empty answer.");
    }

    /// <inheritdoc/>
    public void Dispose() => _http.Dispose();
}

/// <summary>A refusal or failure answered by the instance.</summary>
/// <param name="status">The HTTP status.</param>
/// <param name="code">The error code, from <see cref="HubLocalContract.Errors"/>.</param>
/// <param name="message">The instance's message.</param>
public sealed class HubLocalException(int status, string code, string message) : Exception(message)
{
    /// <summary>The HTTP status.</summary>
    public int Status { get; } = status;

    /// <summary>The error code, from <see cref="HubLocalContract.Errors"/>.</summary>
    public string Code { get; } = code;
}
