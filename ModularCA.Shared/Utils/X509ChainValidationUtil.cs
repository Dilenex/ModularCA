using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Single implementation of "does this leaf certificate cryptographically chain to
/// this specific CA certificate?". Every code path in ModularCA that has to prove issuance —
/// the mTLS login/MFA path (<c>ModularCA.API.Services.MtlsChainValidator</c>) and EST
/// re-enrollment (<c>ModularCA.Core.Services.Est.EstService</c>) — routes through here so the
/// two cannot drift apart. A CA product with two different chain validators eventually has one
/// correct validator and one that silently rotted; this type exists so there is only ever one.
/// <para>
/// It lives in <c>ModularCA.Shared</c> rather than <c>ModularCA.API</c> because
/// <c>ModularCA.Core</c> (EST/SCEP/ACME protocol services) cannot reference the API assembly —
/// the dependency runs the other way. Only the pure chain build lives here; the DB lookups that
/// resolve "which certificate is the CA" stay with their respective callers, since they key off
/// different tables (<c>MtlsCredentials.SigningCaId</c> vs <c>SigningProfiles.IssuerId</c>).
/// </para>
/// </summary>
public static class X509ChainValidationUtil
{
    /// <summary>
    /// Builds an <see cref="X509Chain"/> for <paramref name="leafCert"/> using
    /// <paramref name="anchorCert"/> as the one and only trust anchor
    /// (<see cref="X509ChainTrustMode.CustomRootTrust"/>), so a certificate issued by any other
    /// CA — including another CA in the machine trust store, and including a self-signed
    /// certificate that merely *claims* the anchor's Subject in its Issuer field — fails to
    /// build a path and is rejected.
    /// <para>
    /// Returns <c>true</c> only when the chain builds cleanly and terminates at
    /// <paramref name="anchorCert"/>. The anchor may be an intermediate CA, given without its own
    /// issuer: the path then stops at it short of a self-signed root, which the chain engine
    /// reports as a partial chain and which is accepted when it is the only fault
    /// (<see cref="StopsShortOnlyAtAnchor"/>). On failure, <paramref name="chainErrors"/> carries the
    /// joined <see cref="X509ChainStatus"/> text for the caller's audit record.
    /// </para>
    /// <para>
    /// When <paramref name="requireRevocationCheck"/> is <c>true</c> the build performs an online
    /// OCSP/CRL check on everything but the anchor (fail-closed: an unreachable responder fails
    /// the build). When <c>false</c> revocation is not consulted here and the caller is expected
    /// to have its own revocation gate.
    /// </para>
    /// <para>
    /// Off Windows the chain engine checks revocation only for a chain that reaches a self-signed
    /// root, so under an intermediate anchor it would check nothing. There a required revocation
    /// check under an intermediate anchor is refused, as undetermined, rather than passed
    /// unchecked (<see cref="EngineChecksRevocationOnPartialChains"/>).
    /// </para>
    /// <para>
    /// The chain is disposed via <c>using</c>. <see cref="X509Chain"/> holds native
    /// handles and undisposed instances leak them under sustained protocol traffic.
    /// </para>
    /// </summary>
    /// <param name="leafCert">The certificate whose issuance is being proven.</param>
    /// <param name="anchorCert">The CA certificate that must have issued <paramref name="leafCert"/>.</param>
    /// <param name="requireRevocationCheck">When true, perform online revocation checking and fail closed.</param>
    /// <param name="chainErrors">Receives a human-readable failure reason, or <c>null</c> on success.</param>
    /// <returns><c>true</c> when <paramref name="leafCert"/> chains to <paramref name="anchorCert"/>.</returns>
    public static bool ValidateAgainstAnchor(
        X509Certificate2 leafCert,
        X509Certificate2 anchorCert,
        bool requireRevocationCheck,
        out string? chainErrors)
    {
        chainErrors = null;

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(anchorCert);
        chain.ChainPolicy.RevocationMode = requireRevocationCheck
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        var built = chain.Build(leafCert);
        var terminal = chain.ChainElements.Count > 0
            ? chain.ChainElements[^1].Certificate
            : null;
        var terminatesAtAnchor = terminal != null &&
            string.Equals(terminal.Thumbprint, anchorCert.Thumbprint, StringComparison.OrdinalIgnoreCase);

        var stopsShortAtAnchor = !built && terminatesAtAnchor && StopsShortOnlyAtAnchor(chain);
        if (stopsShortAtAnchor && requireRevocationCheck && !EngineChecksRevocationOnPartialChains)
        {
            chainErrors = $"{X509ChainStatusFlags.RevocationStatusUnknown}:revocation cannot be checked on this platform " +
                "for a chain that ends at an intermediate CA, and a revocation check is required.";
            return false;
        }

        if (!built && !stopsShortAtAnchor)
        {
            chainErrors = string.Join("; ",
                chain.ChainStatus.Select(s => $"{s.Status}:{s.StatusInformation?.Trim()}"));
            if (string.IsNullOrWhiteSpace(chainErrors))
                chainErrors = "Chain build failed with no reported status.";
            return false;
        }

        // Confirm the path actually terminated at the anchor we supplied. For a self-signed anchor
        // CustomRootTrust with a single trust-store entry already guarantees this; for an
        // intermediate anchor it is the check that makes the partial chain acceptable above. It
        // also keeps a future ChainPolicy edit (e.g. re-enabling system trust) from silently
        // widening what counts as "issued by this CA".
        if (!terminatesAtAnchor)
        {
            chainErrors = "Chain did not terminate at the expected CA certificate.";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Whether the chain engine consults revocation for a chain that stops short of a self-signed
    /// root. Windows does, and reports each element's status. The OpenSSL-backed engine does not:
    /// it processes revocation only once the chain is complete, so a partial chain comes back with
    /// no revocation status at all, which must not be read as "not revoked".
    /// </summary>
    private static bool EngineChecksRevocationOnPartialChains => OperatingSystem.IsWindows();

    /// <summary>Revocation statuses that mean "could not be determined", as opposed to "revoked".</summary>
    private const X509ChainStatusFlags RevocationUndetermined =
        X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation;

    /// <summary>
    /// True when the chain failed only because it stops at an intermediate anchor. The chain engine
    /// reports <see cref="X509ChainStatusFlags.PartialChain"/> whenever the path ends at a
    /// certificate that is not self-signed, which is always the case when the custom trust anchor
    /// is an intermediate CA whose own issuer is not supplied. With revocation checking on, it also
    /// checks the anchor itself, whose CRL it cannot verify without that issuer, and reports the
    /// anchor's revocation status as undetermined.
    /// </summary>
    /// <remarks>
    /// Accepted: <see cref="X509ChainStatusFlags.PartialChain"/>, on the chain and on the anchor
    /// element (Windows reports it for the chain alone; the OpenSSL-backed engine also puts it on
    /// the certificate whose issuer it could not find, which is the anchor), plus an undetermined
    /// revocation status on the anchor element alone, which keeps the contract that revocation covers
    /// everything but the anchor (what <see cref="X509RevocationFlag.ExcludeRoot"/> gives a
    /// self-signed anchor). Every other status fails, on any element: a bad signature, an expired
    /// or not-yet-valid certificate, a usage or constraint violation, an explicit revocation, and
    /// an undetermined revocation status on any certificate below the anchor.
    /// </remarks>
    /// <param name="chain">The chain after <see cref="X509Chain.Build(X509Certificate2)"/>; its last element is the anchor.</param>
    private static bool StopsShortOnlyAtAnchor(X509Chain chain)
    {
        var chainFlags = Flags(chain.ChainStatus);
        if ((chainFlags & X509ChainStatusFlags.PartialChain) == 0)
            return false;
        if ((chainFlags & ~(X509ChainStatusFlags.PartialChain | RevocationUndetermined)) != 0)
            return false;

        var elements = chain.ChainElements;
        for (var i = 0; i < elements.Count; i++)
        {
            var tolerated = i == elements.Count - 1
                ? RevocationUndetermined | X509ChainStatusFlags.PartialChain
                : X509ChainStatusFlags.NoError;
            if ((Flags(elements[i].ChainElementStatus) & ~tolerated) != 0)
                return false;
        }
        return true;
    }

    /// <summary>The union of the flags in <paramref name="statuses"/>.</summary>
    /// <param name="statuses">Chain or element statuses.</param>
    private static X509ChainStatusFlags Flags(X509ChainStatus[] statuses)
        => statuses.Aggregate(X509ChainStatusFlags.NoError, (all, s) => all | s.Status);
}
