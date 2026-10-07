using ModularCA.Shared.Models.Acme;

namespace ModularCA.Shared.Interfaces;

public interface IAcmeOrderService
{
    /// <summary>Creates an order at <paramref name="ca"/>, the CA the account is bound to, recording its label on the order.</summary>
    Task<AcmeOrderDto> CreateAsync(Guid accountId, CreateAcmeOrderRequest request, string baseUrl, ModularCA.Shared.Entities.CertificateAuthorityEntity ca);
    Task<AcmeOrderDto?> GetByIdAsync(Guid orderId, string baseUrl);
    Task<List<AcmeOrderDto>> GetByAccountAsync(Guid accountId, string baseUrl);
    /// <summary>
    /// Finalizes an order at <paramref name="addressedCa"/>, the CA the account is bound to;
    /// an order placed at any other CA is refused.
    /// </summary>
    Task<AcmeOrderDto> FinalizeAsync(Guid orderId, string csrBase64Url, string baseUrl, ModularCA.Shared.Entities.CertificateAuthorityEntity addressedCa);
    Task<string?> DownloadCertificateAsync(Guid orderId);

    /// <summary>
    /// Retrieves the account ID that owns the specified order.
    /// </summary>
    Task<Guid?> GetAccountIdForOrderAsync(Guid orderId);

    /// <summary>
    /// Retrieves the account ID that owns the ACME order associated with the given certificate serial number.
    /// Returns null if no ACME order is linked to that serial.
    /// </summary>
    /// <param name="serialNumber">Serial of the certificate whose owning account is sought.</param>
    /// <param name="presentedDer">
    /// The DER bytes the caller presented, when available. Supplied by ACME revocation so the
    /// stored certificate can be byte-compared against what was actually presented rather than
    /// trusted on a serial match alone. Null skips the comparison.
    /// </param>
    Task<Guid?> GetAccountIdForCertificateSerialAsync(string serialNumber, byte[]? presentedDer = null);

    /// <summary>
    /// Audit findings #28: returns the issued certificate's serial number for an ACME order
    /// so the controller can include it in the <c>AcmeOrderFinalized</c> audit payload without
    /// reaching into the database directly. Returns null if the order has not yet issued a cert.
    /// </summary>
    Task<string?> GetIssuedCertificateSerialForOrderAsync(Guid orderId);

    /// <summary>Honor the scheduler job token.</summary>
    Task ExpireStaleOrdersAsync(CancellationToken cancellationToken = default);
    /// <summary>Honor the scheduler job token.</summary>
    Task<bool> HasStaleOrdersAsync(CancellationToken cancellationToken = default);
}
