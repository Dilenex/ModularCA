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
/// <param name="CeremonyId">
/// The <c>KeyCeremonies</c> row the operation executes, for a <see cref="SigningPurpose.Ceremony"/>
/// context that has one. The signer verifies against the database that the ceremony exists, is
/// approved and names the same tenant and CA before it generates, commits or imports a key under
/// it; a ceremony that does not, or has expired, is refused as
/// <see cref="SigningRefusalReason.CeremonyNotApproved"/>. Null for a key operation the
/// tenant's policy allows without a ceremony; the signer reads that policy from the tenant the
/// context names (or the tenant of the CA it names) and refuses
/// <see cref="SigningRefusalReason.CeremonyRequired"/> where the tenant requires one.
/// </param>
public sealed record SigningContext(string Caller, SigningPurpose Purpose, Guid? TenantId, Guid? CaId, Guid? CeremonyId = null)
{
    /// <summary>
    /// The identity of the peer the signer received this context from, when the signer runs as
    /// a role: the SPKI pin of the client certificate on the connection, set by the signer's
    /// host after it has read the context off the wire and never carried on the wire itself, so
    /// a caller cannot name a peer it is not. Null in process, where the context never crossed a
    /// connection. It is recorded on every decision and takes no part in any policy: the pin
    /// already admitted the connection, and the policy is on <see cref="Caller"/> and the rest.
    /// </summary>
    public string? PeerIdentity { get; init; }

    /// <summary>
    /// A context for an operation that belongs to a CA: the CA's id and tenant are both named so
    /// the signer can hold the key to them.
    /// </summary>
    public static SigningContext ForCa(string caller, SigningPurpose purpose, Guid caId, Guid tenantId)
        => new(caller, purpose, tenantId, caId);
}
