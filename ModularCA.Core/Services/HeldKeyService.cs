using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace ModularCA.Core.Services;

/// <summary>How a held-key delivery ended.</summary>
public enum HeldKeyDeliveryOutcome
{
    /// <summary>The PKCS#12 was produced and the held key deleted.</summary>
    Delivered,

    /// <summary>No such request, or the request does not belong to the caller.</summary>
    NotFound,

    /// <summary>The request has no certificate yet; the key stays held until it does.</summary>
    NotIssued,

    /// <summary>The key already left as PKCS#12 and is not kept; the detail names the date.</summary>
    AlreadyDelivered,

    /// <summary>The CA never held a key for this request: the requester supplied the CSR.</summary>
    NoKeyHeld,

    /// <summary>The password is too short to protect the file.</summary>
    InvalidPassword,
}

/// <summary>
/// The result of <see cref="IHeldKeyService.DeliverAsync"/>: the PKCS#12 and its file name when
/// <see cref="Outcome"/> is <see cref="HeldKeyDeliveryOutcome.Delivered"/>, otherwise a sentence
/// the caller can show for why not.
/// </summary>
/// <param name="Outcome">How the delivery ended.</param>
/// <param name="Pkcs12">The PKCS#12 bytes, when delivered.</param>
/// <param name="FileName">A file name for the download, from the certificate's common name.</param>
/// <param name="Detail">Why the delivery did not happen, for the caller to relay.</param>
public sealed record HeldKeyDelivery(HeldKeyDeliveryOutcome Outcome, byte[]? Pkcs12 = null, string? FileName = null, string? Detail = null);

/// <summary>Who is asking for a delivery, for the audit row and for ownership.</summary>
/// <param name="UserId">The caller's user id.</param>
/// <param name="Username">The caller's user name.</param>
/// <param name="SourceIp">The caller's address, when known.</param>
/// <param name="MustOwnRequest">
/// True for a self-service caller: the request must have been submitted by <paramref name="UserId"/>
/// or it is reported as not found. False for an operator whose right to the certificate the
/// controller has already checked.
/// </param>
public sealed record HeldKeyRequester(Guid UserId, string Username, string? SourceIp, bool MustOwnRequest);

/// <summary>
/// Short custody of a private key the CA generated for a certificate request: wrapped on the
/// request row until the certificate exists and the holder downloads certificate and key as
/// one PKCS#12, then deleted. The key never enters the keystore or the signer.
/// </summary>
public interface IHeldKeyService
{
    /// <summary>
    /// Wraps <paramref name="privateKey"/> onto <paramref name="request"/> in memory; the caller
    /// saves the row. The wrap is bound to the row's id, which must already be set.
    /// </summary>
    void Hold(CertRequestEntity request, AsymmetricKeyParameter privateKey, string algorithm);

    /// <summary>Loads the request, wraps <paramref name="privateKey"/> onto it and saves.</summary>
    Task HoldAsync(Guid requestId, AsymmetricKeyParameter privateKey, string algorithm);

    /// <summary>
    /// Produces the PKCS#12 for an issued request's certificate, chain and held key under
    /// <paramref name="password"/>, deletes the held key and stamps the delivery time in one
    /// save, and audits the delivery. Refuses, with a reason, when the certificate is not
    /// issued, the key was already delivered, or no key was ever held.
    /// </summary>
    Task<HeldKeyDelivery> DeliverAsync(Guid requestId, string password, HeldKeyRequester requester);

    /// <summary>
    /// Deletes the held key from <paramref name="request"/> in memory, undelivered; the caller
    /// saves. Returns whether a key was held.
    /// </summary>
    bool Discard(CertRequestEntity request);

    /// <summary>
    /// Deletes every held key whose request can no longer end in a delivery: the request was
    /// rejected, cancelled or failed, the validity it asked for has passed unissued, or the
    /// issued certificate is revoked or expired. Returns how many were discarded.
    /// </summary>
    Task<int> SweepAsync(DateTime now, CancellationToken cancellationToken = default);
}

/// <summary>
/// The custody, delivery and lifecycle of held request keys. Keys are wrapped with ASP.NET Core
/// Data Protection under <see cref="ProtectorPurpose"/> and the request id, so a wrap is only
/// readable by this node's Data Protection ring and only on the row it was written to.
/// </summary>
public sealed class HeldKeyService : IHeldKeyService
{
    /// <summary>Data Protection purpose for held request keys. Changing it orphans every held key.</summary>
    public const string ProtectorPurpose = "ModularCA.CertificateRequests.HeldPrivateKey";

    /// <summary>The shortest password a PKCS#12 may be protected with.</summary>
    public const int MinimumPasswordLength = 8;

    /// <summary>What a holder sees when the certificate is not issued yet.</summary>
    public const string NotIssuedDetail = "The certificate has not been issued yet; the key is held until it is.";

    /// <summary>What a holder sees when the CA never held a key for the request.</summary>
    public const string NoKeyHeldDetail = "No private key is held for this request: it was made from a key the requester supplied, so the CA has nothing to deliver.";

    /// <summary>Request states in which a held key can never be delivered.</summary>
    private static readonly HashSet<string> EndedStatuses = new(StringComparer.OrdinalIgnoreCase) { "Rejected", "Cancelled", "Failed" };

    private readonly ModularCADbContext _db;
    private readonly IDataProtectionProvider _dataProtection;
    private readonly IAuditService _audit;
    private readonly TimeProvider _time;

    /// <summary>
    /// Initializes a new instance of <see cref="HeldKeyService"/>.
    /// </summary>
    public HeldKeyService(ModularCADbContext db, IDataProtectionProvider dataProtection, IAuditService audit, TimeProvider? time = null)
    {
        _db = db;
        _dataProtection = dataProtection;
        _audit = audit;
        _time = time ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public void Hold(CertRequestEntity request, AsymmetricKeyParameter privateKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(privateKey);
        if (!privateKey.IsPrivate)
            throw new ArgumentException("A public key cannot be held for delivery.", nameof(privateKey));
        if (request.Id == Guid.Empty)
            throw new ArgumentException("The request needs its id before a key can be bound to it.", nameof(request));

        var der = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetDerEncoded();
        try
        {
            request.HeldPrivateKey = ProtectorFor(request.Id).Protect(der);
            request.HeldPrivateKeyAlgorithm = algorithm;
            request.HeldKeyDeliveredAt = null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(der);
        }
    }

    /// <inheritdoc />
    public async Task HoldAsync(Guid requestId, AsymmetricKeyParameter privateKey, string algorithm)
    {
        var request = await _db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == requestId)
            ?? throw new InvalidOperationException($"Certificate request {requestId} was not found to hold its key.");
        Hold(request, privateKey, algorithm);
        await _db.SaveChangesAsync();
    }

    /// <inheritdoc />
    public async Task<HeldKeyDelivery> DeliverAsync(Guid requestId, string password, HeldKeyRequester requester)
    {
        ArgumentNullException.ThrowIfNull(requester);
        if (password == null || password.Length < MinimumPasswordLength)
            return new HeldKeyDelivery(HeldKeyDeliveryOutcome.InvalidPassword,
                Detail: $"A password of at least {MinimumPasswordLength} characters is required to protect the file.");

        var request = await _db.CertificateRequests
            .Include(r => r.IssuedCertificate!).ThenInclude(c => c.SigningProfile)
            .FirstOrDefaultAsync(r => r.Id == requestId);
        if (request == null)
            return new HeldKeyDelivery(HeldKeyDeliveryOutcome.NotFound, Detail: "Certificate request not found.");

        // Ownership is a "not found", not a "forbidden": a request id must not confirm that a
        // request exists to someone it does not belong to.
        if (requester.MustOwnRequest && request.RequestorUserId != requester.UserId)
            return new HeldKeyDelivery(HeldKeyDeliveryOutcome.NotFound, Detail: "Certificate request not found.");

        if (request.HeldKeyDeliveredAt is { } deliveredAt)
            return new HeldKeyDelivery(HeldKeyDeliveryOutcome.AlreadyDelivered, Detail: AlreadyDeliveredDetail(deliveredAt));

        if (request.HeldPrivateKey == null)
            return new HeldKeyDelivery(HeldKeyDeliveryOutcome.NoKeyHeld, Detail: NoKeyHeldDetail);

        var cert = request.IssuedCertificate;
        if (request.IssuedCertificateId == null || cert == null)
            return new HeldKeyDelivery(HeldKeyDeliveryOutcome.NotIssued, Detail: NotIssuedDetail);

        var issuers = await IssuerChainResolver.ResolveAsync(_db, cert, includeChain: true);
        var leaf = CertificateUtil.ParseFromPem(cert.Pem);
        var chain = new List<X509CertificateEntry> { new(leaf) };
        chain.AddRange(issuers.Chain.Select(der => new X509CertificateEntry(new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(der))));

        byte[] pkcs12;
        var der = ProtectorFor(request.Id).Unprotect(request.HeldPrivateKey);
        try
        {
            var privateKey = PrivateKeyFactory.CreateKey(der);
            var store = new Pkcs12StoreBuilder().Build();
            var alias = CertificateUtil.ParseCnFromPem(cert.Pem);
            store.SetKeyEntry(string.IsNullOrWhiteSpace(alias) ? cert.SerialNumber : alias, new AsymmetricKeyEntry(privateKey), chain.ToArray());
            using var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), new SecureRandom());
            pkcs12 = stream.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(der);
        }

        // The delete and the delivery stamp are one save, under the row's concurrency token: two
        // downloads racing for the same key end with one file and one "already delivered".
        var now = _time.GetUtcNow().UtcDateTime;
        request.HeldPrivateKey = null;
        request.HeldKeyDeliveredAt = now;
        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException)
        {
            CryptographicOperations.ZeroMemory(pkcs12);
            return new HeldKeyDelivery(HeldKeyDeliveryOutcome.AlreadyDelivered, Detail: AlreadyDeliveredDetail(now));
        }

        await _audit.LogAsync(AuditActionType.HeldKeyDelivered, requester.UserId, requester.Username,
            "CertificateRequest", request.Id.ToString(),
            new { CertificateSerial = cert.SerialNumber, Algorithm = request.HeldPrivateKeyAlgorithm, ChainLength = issuers.Chain.Count },
            requester.SourceIp,
            certificateAuthorityId: issuers.CaId, tenantId: issuers.TenantId);

        var fileName = CertificateUtil.ParseCnFromPem(cert.Pem);
        return new HeldKeyDelivery(HeldKeyDeliveryOutcome.Delivered, pkcs12,
            $"{(string.IsNullOrWhiteSpace(fileName) ? cert.SerialNumber : fileName)}.pfx");
    }

    /// <inheritdoc />
    public bool Discard(CertRequestEntity request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.HeldPrivateKey == null)
            return false;
        request.HeldPrivateKey = null;
        return true;
    }

    /// <inheritdoc />
    public async Task<int> SweepAsync(DateTime now, CancellationToken cancellationToken = default)
    {
        var held = await _db.CertificateRequests
            .Include(r => r.IssuedCertificate)
            .Where(r => r.HeldPrivateKey != null)
            .ToListAsync(cancellationToken);

        var discarded = 0;
        foreach (var request in held)
        {
            var reason = ReasonToDiscard(request, now);
            if (reason == null)
                continue;
            Discard(request);
            discarded++;
            await _audit.LogAsync(AuditActionType.HeldKeyDiscarded, null, "Scheduler",
                "CertificateRequest", request.Id.ToString(),
                new { Reason = reason, CertificateSerial = request.IssuedCertificate?.SerialNumber, Algorithm = request.HeldPrivateKeyAlgorithm });
        }
        if (discarded > 0)
            await _db.SaveChangesAsync(cancellationToken);
        return discarded;
    }

    /// <summary>
    /// Why a held key can no longer be delivered, or null while it still can. A certificate on
    /// hold is not revoked for this purpose: the hold may be lifted and the holder still needs
    /// the key.
    /// </summary>
    private static string? ReasonToDiscard(CertRequestEntity request, DateTime now)
    {
        if (EndedStatuses.Contains(request.Status))
            return $"request {request.Status.ToLowerInvariant()}";
        var cert = request.IssuedCertificate;
        if (cert == null)
        {
            return request.RequestedNotAfter is { } wanted && wanted <= now
                ? "requested validity passed unissued"
                : null;
        }
        if (cert.Revoked && !string.Equals(cert.RevocationReason, nameof(RevocationReason.CertificateHold), StringComparison.OrdinalIgnoreCase))
            return "certificate revoked";
        if (cert.NotAfter <= now)
            return "certificate expired";
        return null;
    }

    private IDataProtector ProtectorFor(Guid requestId) =>
        _dataProtection.CreateProtector(ProtectorPurpose, requestId.ToString("D"));

    private static string AlreadyDeliveredDetail(DateTime deliveredAt) =>
        $"The private key was delivered on {deliveredAt:yyyy-MM-dd HH:mm} UTC and is not kept.";
}
