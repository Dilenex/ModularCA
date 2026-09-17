using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using ModularCA.Shared.Signing;
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
                WireMapping.FromWire(request.Context),
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
                WireMapping.FromWire(request.Context),
                context.CancellationToken);
            return new DecryptResponse { Content = ByteString.CopyFrom(content) };
        }, "Decrypt");

    /// <inheritdoc />
    public override Task<GenerateKeyResponse> GenerateKey(GenerateKeyRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var generated = await _signer.GenerateKeyAsync(
                WireMapping.FromWire(request.Spec),
                WireMapping.FromWire(request.Context),
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
                WireMapping.FromWire(request.Context),
                context.CancellationToken);
            return new CommitKeyResponse();
        }, "CommitKey");

    /// <inheritdoc />
    public override Task<ImportKeyResponse> ImportKey(ImportKeyRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var key = await _signer.ImportKeyAsync(
                WireMapping.FromWire(request.Material),
                WireMapping.FromWire(request.Context),
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
                WireMapping.FromWire(request.Context),
                context.CancellationToken);
            return new ExportKeyResponse { Wrapped = ByteString.CopyFrom(wrapped) };
        }, "ExportKey");

    /// <inheritdoc />
    public override Task<ListKeysResponse> ListKeys(ListKeysRequest request, ServerCallContext context)
        => GuardAsync(async () =>
        {
            var keys = await _signer.ListKeysAsync(WireMapping.FromWire(request.Context), context.CancellationToken);
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
                WireMapping.FromWire(request.Context),
                context.CancellationToken);
            return new RetireKeyResponse();
        }, "RetireKey");

    /// <inheritdoc />
    public override Task<HealthResponse> Health(HealthRequest request, ServerCallContext context)
        => GuardAsync(async () => WireMapping.ToWire(await _signer.HealthAsync(context.CancellationToken)), "Health");

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
