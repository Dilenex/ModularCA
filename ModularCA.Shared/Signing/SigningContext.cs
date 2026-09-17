namespace ModularCA.Shared.Signing;

/// <summary>
/// Who is asking the signer for an operation, what for, and on whose behalf. The signer decides
/// from this alone whether the operation is allowed, and records it with every decision, so the
/// signer's audit is a complete record of what was signed even if the node's audit is lost.
/// </summary>
/// <param name="Caller">The identity of the caller: the node component today, the node's certificate identity once the signer is remote.</param>
/// <param name="Purpose">What the key is being used for.</param>
/// <param name="TenantId">The tenant the operation is for, when the caller knows it. A mismatch with the key's tenant is refused.</param>
/// <param name="CaId">The <c>CertificateAuthorities</c> row id the operation is for. A CA-owned key signs only for its own CA.</param>
public sealed record SigningContext(string Caller, SigningPurpose Purpose, Guid? TenantId, Guid? CaId)
{
    /// <summary>
    /// A context for an operation that belongs to a CA: the CA's id and tenant are both named so
    /// the signer can hold the key to them.
    /// </summary>
    public static SigningContext ForCa(string caller, SigningPurpose purpose, Guid caId, Guid tenantId)
        => new(caller, purpose, tenantId, caId);
}
