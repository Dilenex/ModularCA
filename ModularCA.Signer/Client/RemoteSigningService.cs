using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.Extensions.Logging;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Identity;
using Wire = ModularCA.Signer.Wire;

namespace ModularCA.Signer.Client;

/// <summary>
/// How the node reaches a signer in another process: the address, the client certificate the
/// signer's identity CA issued to this node, and the pin of the signer's server certificate.
/// The node accepts no other server, whatever chain it presents, and consults no trust store.
/// </summary>
/// <param name="Endpoint">The signer role's address, <c>https://host:port</c>.</param>
/// <param name="ClientCertificate">The node's client certificate with its private key.</param>
/// <param name="PinnedServerSpki">The signer's server certificate SPKI pin.</param>
public sealed record RemoteSignerOptions(Uri Endpoint, X509Certificate2 ClientCertificate, string PinnedServerSpki)
{
    /// <summary>How long a signature, decryption or key operation may take before the signer counts as unavailable.</summary>
    public TimeSpan CallTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long an export or import of a whole keystore file may take.</summary>
    public TimeSpan TransferTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>How long the connection attempt may take before a call fails as unavailable.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The longest the channel waits between reconnection attempts once the signer has been
    /// found down. The channel backs off from one second up to this; gRPC's default of two
    /// minutes would leave a node refusing enrollment long after its signer came back.
    /// </summary>
    public TimeSpan MaxReconnectBackoff { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>The largest message either direction carries; a whole keystore file crosses on a backup.</summary>
    public const int MaxMessageSize = 64 * 1024 * 1024;
}

/// <summary>
/// <see cref="ISigningService"/> over the wire: the node's side of the signer channel. Every
/// operation is one gRPC call over a channel that reconnects on its own; a refusal the signer
/// sent comes back as the same <see cref="SigningRefusedException"/> it threw, and a signer
/// that cannot be reached, cannot complete the handshake, or does not answer in time is a
/// refusal of its own, <see cref="SigningRefusalReason.SignerUnavailable"/>, which the
/// enrollment filters and the readiness page already turn into service-unavailable.
/// <see cref="HealthAsync"/> never throws for an unreachable signer: it reports
/// <see cref="SignerHealth.Unreachable"/>. Nothing signable is cached here.
/// </summary>
public sealed class RemoteSigningService : ISigningService, IDisposable
{
    private readonly RemoteSignerOptions _options;
    private readonly ILogger<RemoteSigningService> _logger;
    private readonly GrpcChannel _channel;
    private readonly Wire.Signer.SignerClient _client;
    private int _reportedUnreachable;

    /// <summary>
    /// Opens the channel. The pin must normalise and the client certificate must carry its
    /// private key; neither is checked against the signer until the first call.
    /// </summary>
    public RemoteSigningService(RemoteSignerOptions options, ILogger<RemoteSigningService> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        if (SpkiPin.Normalize(options.PinnedServerSpki) == null)
            throw new ArgumentException("Signer.PinnedServerSpki is not a SHA-256 SPKI pin; the node would trust no signer.", nameof(options));
        if (!options.ClientCertificate.HasPrivateKey)
            throw new ArgumentException("Signer.ClientCertificate has no private key; the node cannot authenticate to the signer.", nameof(options));
        if (options.Endpoint.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException($"Signer.Endpoint must be an https:// address, not '{options.Endpoint}'.", nameof(options));

        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = options.ConnectTimeout,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            KeepAlivePingDelay = TimeSpan.FromSeconds(30),
            KeepAlivePingTimeout = TimeSpan.FromSeconds(10),
            KeepAlivePingPolicy = HttpKeepAlivePingPolicy.Always,
            EnableMultipleHttp2Connections = true,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificates = new X509CertificateCollection { options.ClientCertificate },
                // Offered whatever issuers the signer lists: the signer pins the key, not a chain.
                LocalCertificateSelectionCallback = (_, _, _, _, _) => options.ClientCertificate,
                // The pin is the whole decision, as on the signer's side.
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    certificate is X509Certificate2 x509 && SpkiPin.Matches(x509, options.PinnedServerSpki),
            },
        };

        _channel = GrpcChannel.ForAddress(options.Endpoint, new GrpcChannelOptions
        {
            HttpHandler = handler,
            DisposeHttpClient = true,
            MaxReceiveMessageSize = RemoteSignerOptions.MaxMessageSize,
            MaxSendMessageSize = RemoteSignerOptions.MaxMessageSize,
            InitialReconnectBackoff = TimeSpan.FromSeconds(1),
            MaxReconnectBackoff = options.MaxReconnectBackoff,
        });
        _client = new Wire.Signer.SignerClient(_channel);
    }

    /// <inheritdoc />
    public Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync(async options =>
        {
            var response = await _client.SignAsync(new Wire.SignRequest
            {
                Key = Wire.WireMapping.ToWire(key),
                Algorithm = algorithm.Name,
                Data = ByteString.CopyFrom(data),
                Context = Wire.WireMapping.ToWire(context),
            }, options);
            return response.Signature.ToByteArray();
        }, _options.CallTimeout, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// The call was added with the SSH keystore. A signer that predates it has no such method
    /// and answers gRPC <see cref="StatusCode.Unimplemented"/>; that comes back as a refusal,
    /// <see cref="SigningRefusalReason.OperationUnsupported"/>, whose message says the signer
    /// predates the SSH keystore and is upgraded first. It is not reported as unavailable: the
    /// signer answered, and retrying will not help.
    /// </remarks>
    public async Task<byte[]> SignSshCertificateAsync(SshCertificateRequest request, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        if (request.Key == null)
            throw new ArgumentException("The request names no key.", nameof(request));
        try
        {
            return await CallAsync(async options =>
            {
                var response = await _client.SignSshCertificateAsync(Wire.WireMapping.ToWire(request, context), options);
                return response.Certificate.ToByteArray();
            }, _options.CallTimeout, cancellationToken);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.Unimplemented)
        {
            throw new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The signer at {_options.Endpoint} predates the SSH keystore: it has no call that signs an SSH certificate. Upgrade the signer first, then the node.");
        }
    }

    /// <inheritdoc />
    public Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(enveloped);
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync(async options =>
        {
            var response = await _client.DecryptAsync(new Wire.DecryptRequest
            {
                Key = Wire.WireMapping.ToWire(key),
                Enveloped = ByteString.CopyFrom(enveloped),
                Context = Wire.WireMapping.ToWire(context),
            }, options);
            return response.Content.ToByteArray();
        }, _options.CallTimeout, cancellationToken);
    }

    /// <inheritdoc />
    public Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync(async options =>
        {
            var response = await _client.GenerateKeyAsync(new Wire.GenerateKeyRequest
            {
                Spec = Wire.WireMapping.ToWire(spec),
                Context = Wire.WireMapping.ToWire(context),
            }, options);
            return new GeneratedKey(Wire.WireMapping.FromWire(response.Key), response.PublicKeyDer.ToByteArray());
        }, _options.TransferTimeout, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// <see cref="SigningPurpose.SshKeyMigration"/> was added with the SSH keystore. A signer
    /// that predates it cannot read a context that names it and answers gRPC
    /// <see cref="StatusCode.InvalidArgument"/>; for the import of an SSH CA key that comes back
    /// as a refusal, <see cref="SigningRefusalReason.OperationUnsupported"/>, whose message says
    /// the signer predates the SSH keystore and is upgraded first.
    /// </remarks>
    public async Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(context);
        try
        {
            return await ImportAsync(material, context, cancellationToken);
        }
        catch (RpcException ex) when (ex.StatusCode is StatusCode.InvalidArgument or StatusCode.Unimplemented
                                      && context.Purpose == SigningPurpose.SshKeyMigration)
        {
            throw new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The signer at {_options.Endpoint} predates the SSH keystore: it does not take the import of an SSH CA key ({ex.Status.Detail}). Upgrade the signer first, then the node.");
        }
    }

    /// <summary>The import call itself, with the node's copy of a bare key zeroed once the signer has answered.</summary>
    private Task<KeyRef> ImportAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken)
    {
        return CallAsync(async options =>
        {
            var response = await _client.ImportKeyAsync(new Wire.ImportKeyRequest
            {
                Material = Wire.WireMapping.ToWire(material),
                Context = Wire.WireMapping.ToWire(context),
            }, options);
            // The signer zeroes its copy of a bare key once parsed; the node's copy is zeroed
            // here so the material outlives the call on neither side. A keystore file is
            // already wrapped and is left as the in-process signer leaves it.
            if (string.Equals(material.Format, KeyMaterial.Pkcs8, StringComparison.OrdinalIgnoreCase))
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(material.Wrapped);
            return Wire.WireMapping.FromWire(response.Key);
        }, _options.TransferTimeout, cancellationToken);
    }

    /// <inheritdoc />
    public Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync(async options =>
        {
            await _client.CommitKeyAsync(new Wire.CommitKeyRequest
            {
                Key = Wire.WireMapping.ToWire(key),
                CertificateId = certificateId.ToString("D"),
                Context = Wire.WireMapping.ToWire(context),
            }, options);
            return true;
        }, _options.TransferTimeout, cancellationToken);
    }

    /// <inheritdoc />
    public Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(wrap);
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync(async options =>
        {
            var response = await _client.ExportKeyAsync(new Wire.ExportKeyRequest
            {
                Key = Wire.WireMapping.ToWire(key),
                Wrap = Wire.WireMapping.ToWire(wrap),
                Context = Wire.WireMapping.ToWire(context),
            }, options);
            return response.Wrapped.ToByteArray();
        }, _options.TransferTimeout, cancellationToken);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync<IReadOnlyList<KeyInfo>>(async options =>
        {
            var response = await _client.ListKeysAsync(new Wire.ListKeysRequest { Context = Wire.WireMapping.ToWire(context) }, options);
            return response.Keys.Select(Wire.WireMapping.FromWire).ToList();
        }, _options.CallTimeout, cancellationToken);
    }

    /// <inheritdoc />
    public Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync(async options =>
        {
            await _client.RetireKeyAsync(new Wire.RetireKeyRequest
            {
                Key = Wire.WireMapping.ToWire(key),
                Context = Wire.WireMapping.ToWire(context),
            }, options);
            return true;
        }, _options.CallTimeout, cancellationToken);
    }

    /// <inheritdoc />
    public Task<byte[]> WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext context, CancellationToken cancellationToken = default)
        => WrapAsync(kind, string.Empty, secret, context, cancellationToken);

    /// <inheritdoc />
    public Task<byte[]> WrapBoundSecretAsync(SecretKind kind, string binding, byte[] secret, SigningContext context, CancellationToken cancellationToken = default)
    {
        // An empty binding is how the wire says "none", so it cannot also be a binding.
        ArgumentException.ThrowIfNullOrEmpty(binding);
        return WrapAsync(kind, binding, secret, context, cancellationToken);
    }

    private Task<byte[]> WrapAsync(SecretKind kind, string binding, byte[] secret, SigningContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync(async options =>
        {
            var response = await _client.WrapSecretAsync(new Wire.WrapSecretRequest
            {
                Kind = Wire.WireMapping.ToWire(kind),
                Secret = ByteString.CopyFrom(secret),
                Context = Wire.WireMapping.ToWire(context),
                Binding = binding,
            }, options);
            return response.Wrapped.ToByteArray();
        }, _options.CallTimeout, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// The secret comes back in the clear inside the channel, and the node then holds it in
    /// memory, because the node is what has to use it. The channel's mutual TLS is what keeps it
    /// off the wire; nothing keeps it out of the node.
    /// </remarks>
    public Task<byte[]> UnwrapSecretAsync(byte[] wrapped, SigningContext context, CancellationToken cancellationToken = default)
        => UnwrapAsync(wrapped, string.Empty, context, cancellationToken);

    /// <inheritdoc />
    public Task<byte[]> UnwrapBoundSecretAsync(byte[] wrapped, string binding, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(binding);
        return UnwrapAsync(wrapped, binding, context, cancellationToken);
    }

    private Task<byte[]> UnwrapAsync(byte[] wrapped, string binding, SigningContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(wrapped);
        ArgumentNullException.ThrowIfNull(context);
        return CallAsync(async options =>
        {
            var response = await _client.UnwrapSecretAsync(new Wire.UnwrapSecretRequest
            {
                Wrapped = ByteString.CopyFrom(wrapped),
                Context = Wire.WireMapping.ToWire(context),
                Binding = binding,
            }, options);
            return response.Secret.ToByteArray();
        }, _options.CallTimeout, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// A signer that does not answer is reported as <see cref="SignerHealth.Unreachable"/>
    /// rather than thrown: the callers of this are the readiness checks and the enrollment
    /// filter, which need a state to show, not an exception to explain.
    /// </remarks>
    public async Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _client.HealthAsync(new Wire.HealthRequest(), Options(_options.CallTimeout, cancellationToken));
            if (Interlocked.Exchange(ref _reportedUnreachable, 0) == 1)
                _logger.LogInformation("Signer: the signer at {Endpoint} answers again.", _options.Endpoint);
            return Wire.WireMapping.FromWire(response);
        }
        catch (RpcException ex) when (!cancellationToken.IsCancellationRequested)
        {
            ReportUnreachable(ex);
            return SignerHealth.Unreachable();
        }
    }

    /// <inheritdoc />
    public void Dispose() => _channel.Dispose();

    /// <summary>
    /// Runs one call and maps its failure: the refusal the trailer names, the caller's own
    /// cancellation, an unreachable or unresponsive signer as
    /// <see cref="SigningRefusalReason.SignerUnavailable"/>, and anything else as the
    /// <see cref="RpcException"/> it is, since an Internal status after an allowed decision is
    /// the operation failing, not the signer refusing.
    /// </summary>
    private async Task<T> CallAsync<T>(Func<CallOptions, Task<T>> call, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            var result = await call(Options(timeout, cancellationToken));
            if (Interlocked.Exchange(ref _reportedUnreachable, 0) == 1)
                _logger.LogInformation("Signer: the signer at {Endpoint} answers again.", _options.Endpoint);
            return result;
        }
        catch (RpcException ex)
        {
            var refusal = Wire.WireMapping.ToRefusal(ex);
            if (refusal != null)
                throw refusal;
            if (cancellationToken.IsCancellationRequested)
                throw new OperationCanceledException("The signing call was cancelled.", ex, cancellationToken);
            if (IsUnavailable(ex))
            {
                ReportUnreachable(ex);
                throw new SigningRefusedException(SigningRefusalReason.SignerUnavailable,
                    $"The signer at {_options.Endpoint} is unreachable: {ex.Status.Detail}");
            }
            throw;
        }
    }

    private static CallOptions Options(TimeSpan timeout, CancellationToken cancellationToken)
        => new(deadline: DateTime.UtcNow + timeout, cancellationToken: cancellationToken);

    /// <summary>
    /// Whether a failed call means the signer could not be reached or did not answer, rather
    /// than answered with a status of its own: the transport statuses, and any status whose
    /// cause is a connection, socket or handshake failure.
    /// </summary>
    private static bool IsUnavailable(RpcException ex)
    {
        if (ex.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded)
            return true;
        for (var cause = ex.Status.DebugException; cause != null; cause = cause.InnerException)
        {
            if (cause is HttpRequestException or IOException or System.Net.Sockets.SocketException or AuthenticationException)
                return true;
        }
        return false;
    }

    private void ReportUnreachable(RpcException ex)
    {
        if (Interlocked.Exchange(ref _reportedUnreachable, 1) == 0)
            _logger.LogWarning("Signer: the signer at {Endpoint} is unreachable ({Status}): {Detail}", _options.Endpoint, ex.StatusCode, ex.Status.Detail);
    }
}
