using Google.Protobuf;
using Grpc.AspNetCore.Server;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Identity;
using ModularCA.Signer.Wire;

namespace ModularCA.Signer.Server;

/// <summary>
/// The signer role's side of the wire: each operation reads its request, calls the
/// <see cref="ISigningService"/> the host registered (the in-process signer over the unlocked
/// keystore) and writes the result. A <see cref="SigningRefusedException"/> crosses as the
/// status <see cref="WireMapping.ToRpcException"/> describes, so the node's client rethrows the
/// same refusal; a malformed request is <see cref="StatusCode.InvalidArgument"/>; anything else
/// the signer throws after an allowed decision (a CMS envelope that does not open, a keystore
/// file that cannot be written) is <see cref="StatusCode.Internal"/> with the exception's type
/// and message, since the node is the only peer and needs the cause.
/// </summary>
public sealed class SignerGrpcService : Wire.Signer.SignerBase
{
    private readonly ISigningService _signer;
    private readonly ILogger<SignerGrpcService> _logger;

    /// <summary>Creates the adapter over the signer the host registered.</summary>
    public SignerGrpcService(ISigningService signer, ILogger<SignerGrpcService> logger)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public override Task<SignResponse> Sign(SignRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var signature = await _signer.SignAsync(
                WireMapping.FromWire(request.Key),
                SignatureAlgorithm.FromName(request.Algorithm),
                request.Data.ToByteArray(),
                ContextFrom(request.Context, context),
                context.CancellationToken);
            return new SignResponse { Signature = ByteString.CopyFrom(signature) };
        }, "Sign");

    /// <inheritdoc />
    public override Task<DecryptResponse> Decrypt(DecryptRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var content = await _signer.DecryptAsync(
                WireMapping.FromWire(request.Key),
                request.Enveloped.ToByteArray(),
                ContextFrom(request.Context, context),
                context.CancellationToken);
            return new DecryptResponse { Content = ByteString.CopyFrom(content) };
        }, "Decrypt");

    /// <inheritdoc />
    public override Task<GenerateKeyResponse> GenerateKey(GenerateKeyRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var generated = await _signer.GenerateKeyAsync(
                WireMapping.FromWire(request.Spec),
                ContextFrom(request.Context, context),
                context.CancellationToken);
            return new GenerateKeyResponse
            {
                Key = WireMapping.ToWire(generated.Key),
                PublicKeyDer = ByteString.CopyFrom(generated.PublicKeyDer),
            };
        }, "GenerateKey");

    /// <inheritdoc />
    public override Task<CommitKeyResponse> CommitKey(CommitKeyRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            await _signer.CommitKeyAsync(
                WireMapping.FromWire(request.Key),
                WireMapping.ToGuid(request.CertificateId, "certificate_id"),
                ContextFrom(request.Context, context),
                context.CancellationToken);
            return new CommitKeyResponse();
        }, "CommitKey");

    /// <inheritdoc />
    public override Task<ImportKeyResponse> ImportKey(ImportKeyRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var key = await _signer.ImportKeyAsync(
                WireMapping.FromWire(request.Material),
                ContextFrom(request.Context, context),
                context.CancellationToken);
            return new ImportKeyResponse { Key = WireMapping.ToWire(key) };
        }, "ImportKey");

    /// <inheritdoc />
    public override Task<ExportKeyResponse> ExportKey(ExportKeyRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var wrapped = await _signer.ExportKeyAsync(
                WireMapping.FromWire(request.Key),
                WireMapping.FromWire(request.Wrap),
                ContextFrom(request.Context, context),
                context.CancellationToken);
            return new ExportKeyResponse { Wrapped = ByteString.CopyFrom(wrapped) };
        }, "ExportKey");

    /// <inheritdoc />
    public override Task<ListKeysResponse> ListKeys(ListKeysRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var keys = await _signer.ListKeysAsync(ContextFrom(request.Context, context), context.CancellationToken);
            var response = new ListKeysResponse();
            foreach (var key in keys)
                response.Keys.Add(WireMapping.ToWire(key));
            return response;
        }, "ListKeys");

    /// <inheritdoc />
    public override Task<RetireKeyResponse> RetireKey(RetireKeyRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            await _signer.RetireKeyAsync(
                WireMapping.FromWire(request.Key),
                ContextFrom(request.Context, context),
                context.CancellationToken);
            return new RetireKeyResponse();
        }, "RetireKey");

    /// <inheritdoc />
    public override Task<HealthResponse> Health(HealthRequest request, ServerCallContext context)
        => GuardAsync(async () => WireMapping.ToWire(await _signer.HealthAsync(context.CancellationToken)), "Health");

    /// <summary>
    /// Reads the context off the wire and stamps it with the peer's identity: the SPKI pin of
    /// the client certificate on this call's connection, computed here from the certificate
    /// Kestrel admitted, never taken from the request. The wire has no field for it, so a node
    /// cannot name a peer it is not; the signer's audit then records who was on the connection
    /// for every decision. A call with no client certificate (which the listener does not
    /// admit) is stamped with nothing rather than refused here, since admission is the
    /// handshake's decision and the policy does not depend on the peer.
    /// </summary>
    private static Shared.Signing.SigningContext ContextFrom(Wire.SigningContext? wire, ServerCallContext call)
    {
        var context = WireMapping.FromWire(wire);
        var certificate = call.GetHttpContext().Connection.ClientCertificate;
        return certificate == null ? context : context with { PeerIdentity = SpkiPin.Compute(certificate) };
    }

    /// <summary>
    /// Runs one operation and maps what it throws to a status: a refusal to the refusal status,
    /// bad input to InvalidArgument, the caller's own cancellation to Cancelled, anything else
    /// to Internal with the cause named.
    /// </summary>
    private async Task<T> GuardAsync<T>(Func<Task<T>> operation, string name)
    {
        try
        {
            return await operation();
        }
        catch (SigningRefusedException refusal)
        {
            throw WireMapping.ToRpcException(refusal);
        }
        catch (ArgumentException ex)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, ex.Message));
        }
        catch (OperationCanceledException)
        {
            throw new RpcException(new Status(StatusCode.Cancelled, "The call was cancelled."));
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Signer: {Operation} failed after the decision was taken.", name);
            throw new RpcException(new Status(StatusCode.Internal, $"{ex.GetType().Name}: {ex.Message}"));
        }
    }
}
