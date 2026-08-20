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
    /// <paramref name="anchorCert"/>. On failure, <paramref name="chainErrors"/> carries the
    /// joined <see cref="X509ChainStatus"/> text for the caller's audit record.
    /// </para>
    /// <para>
    /// When <paramref name="requireRevocationCheck"/> is <c>true</c> the build performs an online
    /// OCSP/CRL check on everything but the anchor (fail-closed: an unreachable responder fails
    /// the build). When <c>false</c> revocation is not consulted here and the caller is expected
    /// to have its own revocation gate.
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

        if (!chain.Build(leafCert))
        {
            chainErrors = string.Join("; ",
                chain.ChainStatus.Select(s => $"{s.Status}:{s.StatusInformation?.Trim()}"));
            if (string.IsNullOrWhiteSpace(chainErrors))
                chainErrors = "Chain build failed with no reported status.";
            return false;
        }

        // Belt-and-braces: confirm the path actually terminated at the anchor we supplied.
        // CustomRootTrust with a single trust-store entry already guarantees this, but the
        // assertion is free and it keeps a future ChainPolicy edit (e.g. re-enabling system
        // trust) from silently widening what counts as "issued by this CA".
        var terminal = chain.ChainElements.Count > 0
            ? chain.ChainElements[^1].Certificate
            : null;
        if (terminal == null ||
            !string.Equals(terminal.Thumbprint, anchorCert.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            chainErrors = "Chain did not terminate at the expected CA certificate.";
            return false;
        }

        return true;
    }
}
