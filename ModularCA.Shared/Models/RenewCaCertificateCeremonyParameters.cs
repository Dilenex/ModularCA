namespace ModularCA.Shared.Models;

/// <summary>
/// The parameters of a <c>RenewCaCertificate</c> ceremony, locked when it is opened: which CA,
/// which certificate it had at that moment, and the exact end of validity the approvers agree
/// to. The signer reads them itself before it signs the renewed certificate, so a certificate
/// with another expiry, or for another CA, is not signed under the ceremony.
/// </summary>
public class RenewCaCertificateCeremonyParameters
{
    /// <summary>The operation type of the ceremony that carries these parameters.</summary>
    public const string OperationType = "RenewCaCertificate";

    /// <summary>The CA whose certificate is renewed.</summary>
    public Guid CaId { get; set; }

    /// <summary>The CA's name, for display.</summary>
    public string CaName { get; set; } = string.Empty;

    /// <summary>The CA's current certificate when the ceremony was opened. A CA renewed since then is not renewed again under this ceremony.</summary>
    public Guid CurrentCertificateId { get; set; }

    /// <summary>Serial number of that certificate, for display and audit.</summary>
    public string CurrentSerialNumber { get; set; } = string.Empty;

    /// <summary>The end of validity of the new certificate, UTC, to the second.</summary>
    public DateTime NotAfter { get; set; }

    /// <summary>
    /// What the initiator was told about the validity chosen, for the approvers to read before
    /// they approve: a validity longer than common practice (a notice), and an RSA key under
    /// 3072 bits past 2030 (a warning). The signer does not judge these; it holds the
    /// certificate to the CA, the current certificate and <see cref="NotAfter"/>.
    /// </summary>
    public List<RenewalAdvisory> Advisories { get; set; } = [];

    /// <summary>The reasons of the warnings among <see cref="Advisories"/> that the initiator acknowledged when opening the ceremony.</summary>
    public List<string> Acknowledged { get; set; } = [];

    /// <summary>Space that owns the CA, or null for an instance CA. <see cref="Guid.Empty"/> reads as null.</summary>
    public Guid? SpaceId { get => _spaceId; set => _spaceId = value == Guid.Empty ? null : value; }
    private Guid? _spaceId;
}

/// <summary>One notice or warning about a renewal's validity, as the ceremony keeps it for its approvers.</summary>
public class RenewalAdvisory
{
    /// <summary>The stable code, e.g. <c>CaRsaKeyBelow3072Past2030</c>.</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary><c>notice</c> or <c>warning</c>.</summary>
    public string Severity { get; set; } = string.Empty;

    /// <summary>A few words for a heading.</summary>
    public string? Title { get; set; }

    /// <summary>The sentence the initiator was shown.</summary>
    public string Message { get; set; } = string.Empty;
}
