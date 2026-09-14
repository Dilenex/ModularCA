using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Core.Services.Est;

/// <summary>
/// Decides whether a client certificate presented on the EST subdomain was issued under a CA that
/// currently has EST enabled.
/// </summary>
/// <remarks>
/// <para>
/// This is the only place an EST client certificate's chain is checked. <c>EstService</c> reads the
/// certificate's CN and SANs and binds the CSR to them, but never validates that the certificate
/// was issued by anything — it trusts the transport to have done that. So if this returns true for
/// an unvalidated certificate, a self-signed <c>CN=root-admin</c> enrolls as <c>CN=root-admin</c>,
/// and every binding check downstream confirms the forgery against itself.
/// </para>
/// <para>
/// Written as a static over an explicit anchor set rather than reading configuration or a database
/// so the rules below can be tested directly. The caller supplies the anchors.
/// </para>
/// </remarks>
public static class EstClientCertValidator
{
    /// <summary>id-kp-clientAuth, RFC 5280 section 4.2.1.12.</summary>
    public const string ClientAuthEkuOid = "1.3.6.1.5.5.7.3.2";

    /// <summary>
    /// Validates a presented client certificate against the EST trust anchors.
    /// </summary>
    /// <param name="clientCert">The certificate presented in the TLS handshake.</param>
    /// <param name="estCaCerts">
    /// Certificates of the CAs that currently have EST enabled. A chain that does not pass through
    /// one of these is rejected even if it is otherwise valid.
    /// </param>
    /// <param name="intermediates">
    /// Additional certificates needed to complete a chain — the issuers above an EST-enabled
    /// intermediate. These help a chain terminate; they do not by themselves authorise anything.
    /// </param>
    /// <returns><c>true</c> when the certificate chains to an EST-enabled CA.</returns>
    public static bool IsIssuedByEstCa(
        X509Certificate2? clientCert,
        IReadOnlyList<X509Certificate2> estCaCerts,
        IReadOnlyList<X509Certificate2>? intermediates = null)
    {
        if (clientCert == null)
            return false;

        // Fail closed on an empty anchor set. Nothing can be validated against zero anchors, so
        // returning true here would mean any self-signed certificate completes the handshake and
        // the transport gate becomes decorative — with EstService's identity binding then
        // validating the certificate against its own forged contents.
        if (estCaCerts.Count == 0)
            return false;

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        foreach (var ca in estCaCerts)
            chain.ChainPolicy.CustomTrustStore.Add(ca);

        // An EST-enabled CA is frequently an intermediate. CustomRootTrust wants the chain to
        // terminate at something in the custom store, so the issuers above it go in as well —
        // otherwise a perfectly good device certificate fails with PartialChain. Admitting the
        // root as a terminator does not widen what is authorised: the thumbprint check below still
        // requires the chain to pass through an EST-enabled CA, so a sibling intermediate under the
        // same root is not accepted.
        if (intermediates != null)
        {
            foreach (var issuer in intermediates)
            {
                chain.ChainPolicy.CustomTrustStore.Add(issuer);
                chain.ChainPolicy.ExtraStore.Add(issuer);
            }
        }

        // Only certificates usable for client authentication. Without this, any certificate the
        // EST CA has issued is a client identity, including TLS server certificates obtained via
        // ACME: a tenant holding DNS:host.example presents that certificate and enrolls an
        // EST-profile certificate for the same name. A certificate with no EKU extension still
        // passes, as RFC 5280 section 4.2.1.12 makes absence mean unrestricted.
        chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid(ClientAuthEkuOid));

        // Revocation matches the mTLS handshake policy: Offline consults the locally cached CRL
        // only, so no network fetch happens inside the handshake budget. The Ignore*Unknown flags
        // are deliberate — with a cold CRL cache Offline reports RevocationStatusUnknown and every
        // handshake would fail for a reason unrelated to the client's standing. An explicit Revoked
        // status is still fatal.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.IgnoreEndRevocationUnknown
            | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
            | X509VerificationFlags.IgnoreRootRevocationUnknown;

        if (!chain.Build(clientCert))
            return false;

        // The chain is valid, but valid under what? With a shared root, every certificate the
        // organisation has ever issued builds a valid chain, including ones from CAs that have EST
        // turned off and ones issued for entirely different purposes. Requiring the EST-enabled CA
        // to be the DIRECT issuer is what makes "EST enabled on this CA" mean something at the
        // transport layer. An earlier version accepted the EST CA anywhere in the chain, which
        // meant enabling EST on a root admitted every subordinate CA's certificates, login and
        // web-TLS intermediates included. RFC 7030 section 4.2.2 says re-enrollment authenticates
        // with a certificate "previously issued by this CA", and "by" is the direct issuer.
        var anchorThumbprints = new HashSet<string>(
            estCaCerts.Select(c => c.Thumbprint), StringComparer.OrdinalIgnoreCase);

        var elements = chain.ChainElements;
        if (elements.Count == 0)
            return false;

        // The leaf may itself be an EST CA certificate (a CA re-enrolling), which has no issuer
        // element above it to check.
        if (anchorThumbprints.Contains(elements[0].Certificate.Thumbprint))
            return true;

        return elements.Count >= 2
            && anchorThumbprints.Contains(elements[1].Certificate.Thumbprint);
    }
}
