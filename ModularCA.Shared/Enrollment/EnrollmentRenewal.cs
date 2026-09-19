namespace ModularCA.Shared.Enrollment;

/// <summary>
/// Evidence that a request renews a certificate this system issued, already proven by the
/// protocol that carried it.
/// </summary>
/// <remarks>
/// Proving the evidence is the protocol's own work — MSAE checks that the CMC wrapper was signed
/// by the certificate named, that the certificate is this CA's, unrevoked, unexpired and of the
/// same template; EST re-enrollment builds a chain against the CA and checks the renewal window.
/// What reaches the pipeline is the conclusion, because the checks need the protocol's own wire
/// material and would not generalise. The pipeline uses it to link the new request row to the
/// certificate being replaced.
/// </remarks>
/// <param name="RenewedCertificateId">The stored certificate being renewed.</param>
/// <param name="SerialNumber">Its serial number, for the log line and the audit row.</param>
/// <param name="ProvenByHolderOfKey">
/// Whether the holder of the old certificate's private key signed the request. Always true today;
/// carried so a protocol that renews on a weaker credential has to say so rather than look alike.
/// </param>
public sealed record EnrollmentRenewal(
    Guid RenewedCertificateId,
    string? SerialNumber = null,
    bool ProvenByHolderOfKey = true);
