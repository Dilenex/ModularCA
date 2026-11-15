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
    /// Proves that <paramref name="leafCert"/> was issued by <paramref name="anchorCert"/>, with
    /// no issuer certificates for the anchor: the same as
    /// <see cref="ValidateAgainstAnchor(X509Certificate2, X509Certificate2, IReadOnlyCollection{X509Certificate2}?, bool, out string?)"/>
    /// with none supplied.
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
        => ValidateAgainstAnchor(leafCert, anchorCert, anchorIssuers: null, requireRevocationCheck, out chainErrors);

    /// <summary>
    /// Proves that <paramref name="leafCert"/> was issued by <paramref name="anchorCert"/>, and,
    /// when <paramref name="requireRevocationCheck"/> is set, that it is not revoked.
    /// <para>
    /// Issuance is always decided the same way: an <see cref="X509Chain"/> is built with
    /// <paramref name="anchorCert"/> as the one and only trust anchor
    /// (<see cref="X509ChainTrustMode.CustomRootTrust"/>), so a certificate issued by any other
    /// CA — including another CA in the machine trust store, another CA under the same root, and a
    /// self-signed certificate that merely *claims* the anchor's Subject in its Issuer field —
    /// fails to build a path and is rejected. The anchor may be an intermediate CA: the path then
    /// stops at it short of a self-signed root, which the chain engine reports as a partial chain
    /// and which is accepted when it is the only fault (<see cref="StopsShortOnlyAtAnchor"/>).
    /// <paramref name="anchorIssuers"/> plays no part in this decision, so supplying it cannot
    /// make a certificate count as issued by the anchor that would not have counted without it.
    /// </para>
    /// <para>
    /// When <paramref name="requireRevocationCheck"/> is <c>false</c> revocation is not consulted
    /// here, <paramref name="anchorIssuers"/> is not used, and the caller is expected to have its
    /// own revocation gate.
    /// </para>
    /// <para>
    /// When it is <c>true</c> the leaf's status must be positively established by an online
    /// CRL/OCSP check (fail-closed: a leaf that is revoked, or whose status cannot be determined,
    /// fails). How the check is made depends on what the caller could supply:
    /// </para>
    /// <list type="bullet">
    ///   <item>
    ///     A self-signed anchor, or an intermediate anchor with <paramref name="anchorIssuers"/>
    ///     reaching a self-signed root: the chain is complete, and every chain engine checks
    ///     revocation on it. Under an intermediate anchor this is a second build, made only after
    ///     issuance is proven (so no revocation URL is fetched for a certificate the anchor did not
    ///     issue), trusting the supplied root and required to pass through the anchor as the
    ///     leaf's direct issuer (<see cref="CheckRevocationThroughIssuers"/>).
    ///   </item>
    ///   <item>
    ///     An intermediate anchor without usable issuers (none supplied, or they do not lead from
    ///     the anchor to a self-signed root, or the completed chain has some other fault above
    ///     the anchor): only the chain that stops at the anchor is left, and no engine has been
    ///     seen to check a leaf's revocation on one. The required check therefore fails closed,
    ///     as undetermined, on every platform: on Windows by the engine's own report, and
    ///     elsewhere, where the engine reports nothing at all for such a chain, by this method's
    ///     refusal (<see cref="EngineReportsRevocationOnPartialChains"/>).
    ///   </item>
    /// </list>
    /// <para>
    /// What revocation covers. The leaf: always, and never tolerantly. The CA certificates above
    /// it, the anchor included, when the chain was completed with <paramref name="anchorIssuers"/>:
    /// a revocation that is established fails the validation, while a status that cannot be
    /// determined (no CRL or OCSP responder named, or none reachable) does not. That keeps the
    /// earlier contract — the anchor is the caller's chosen trust anchor, and an unreachable CRL for
    /// it, typically one published by an offline root, must not stop every sign-in beneath it —
    /// and adds only refusals. The self-signed root is not checked
    /// (<see cref="X509RevocationFlag.ExcludeRoot"/>).
    /// </para>
    /// <para>
    /// On failure, <paramref name="chainErrors"/> carries the joined <see cref="X509ChainStatus"/>
    /// text for the caller's audit record. Chains are disposed via <c>using</c>:
    /// <see cref="X509Chain"/> holds native handles and undisposed instances leak them under
    /// sustained protocol traffic.
    /// </para>
    /// </summary>
    /// <param name="leafCert">The certificate whose issuance is being proven.</param>
    /// <param name="anchorCert">The CA certificate that must have issued <paramref name="leafCert"/>.</param>
    /// <param name="anchorIssuers">
    /// The certificates above <paramref name="anchorCert"/>, up to and including its self-signed
    /// root, in any order; <c>null</c> or empty when the caller does not have them. Used only to
    /// complete the chain for the revocation check. They are not taken on trust as a path: the
    /// engine verifies every signature, and a set that does not lead from the anchor to a
    /// self-signed root is the same as none.
    /// </param>
    /// <param name="requireRevocationCheck">When true, perform online revocation checking and fail closed.</param>
    /// <param name="chainErrors">Receives a human-readable failure reason, or <c>null</c> on success.</param>
    /// <returns>
    /// <c>true</c> when <paramref name="leafCert"/> chains to <paramref name="anchorCert"/> and,
    /// if required, its revocation check ran and found it not revoked.
    /// </returns>
    public static bool ValidateAgainstAnchor(
        X509Certificate2 leafCert,
        X509Certificate2 anchorCert,
        IReadOnlyCollection<X509Certificate2>? anchorIssuers,
        bool requireRevocationCheck,
        out string? chainErrors)
    {
        if (!requireRevocationCheck || anchorIssuers is not { Count: > 0 } || IsSelfIssued(anchorCert))
            return BuildToAnchor(leafCert, anchorCert, requireRevocationCheck, out chainErrors);

        // Issuance first, with no network access: the revocation build below fetches the URLs the
        // leaf names, and those are only worth fetching for a certificate the anchor issued.
        if (!BuildToAnchor(leafCert, anchorCert, requireRevocationCheck: false, out chainErrors))
            return false;

        return CheckRevocationThroughIssuers(leafCert, anchorCert, anchorIssuers, out chainErrors) switch
        {
            CompletedChainRevocation.NotRevoked => true,
            CompletedChainRevocation.Refused => false,
            _ => BuildToAnchor(leafCert, anchorCert, requireRevocationCheck: true, out chainErrors),
        };
    }

    /// <summary>
    /// The chain build with <paramref name="anchorCert"/> as the only trust anchor: the single
    /// decision of "issued by this CA", and, with <paramref name="requireRevocationCheck"/>, the
    /// revocation check on that same chain. Under an intermediate anchor the chain is partial:
    /// a required revocation check then passes only if the engine reports every certificate below
    /// the anchor as checked, and where the engine reports nothing for such a chain the check is
    /// refused here as undetermined (<see cref="EngineReportsRevocationOnPartialChains"/>).
    /// </summary>
    /// <param name="leafCert">The certificate whose issuance is being proven.</param>
    /// <param name="anchorCert">The CA certificate that must have issued <paramref name="leafCert"/>.</param>
    /// <param name="requireRevocationCheck">When true, perform online revocation checking and fail closed.</param>
    /// <param name="chainErrors">Receives a human-readable failure reason, or <c>null</c> on success.</param>
    /// <returns><c>true</c> when the chain builds cleanly and terminates at <paramref name="anchorCert"/>.</returns>
    private static bool BuildToAnchor(
        X509Certificate2 leafCert,
        X509Certificate2 anchorCert,
        bool requireRevocationCheck,
        out string? chainErrors)
    {
        chainErrors = null;

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        // Never fetch a missing issuer from the address a certificate names (CA Issuers). The
        // certificates to build with are the ones handed in. A real instance's certificates name
        // that address, and an engine that follows it completes the chain past an intermediate
        // anchor to a root nobody said to trust, which then fails every certificate under it.
        // This turns off only the download of issuer certificates, not of CRLs or OCSP answers.
        chain.ChainPolicy.DisableCertificateDownloads = true;
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
        if (stopsShortAtAnchor && requireRevocationCheck && !EngineReportsRevocationOnPartialChains)
        {
            chainErrors = $"{X509ChainStatusFlags.RevocationStatusUnknown}:revocation cannot be checked on this platform " +
                "for a chain that ends at an intermediate CA whose own issuers are not available, and a revocation check is required.";
            return false;
        }

        if (!built && !stopsShortAtAnchor)
        {
            chainErrors = DescribeStatus(chain);
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

    /// <summary>What a revocation check on a chain completed with the anchor's issuers established.</summary>
    private enum CompletedChainRevocation
    {
        /// <summary>
        /// The chain could not be completed cleanly through the anchor to a supplied root, so it
        /// says nothing either way and the caller falls back to the chain that stops at the anchor.
        /// </summary>
        Inconclusive,

        /// <summary>The check ran on the complete chain: the leaf is not revoked, and no CA above it is known to be.</summary>
        NotRevoked,

        /// <summary>The leaf is revoked or its status could not be determined, or a CA above it is revoked.</summary>
        Refused,
    }

    /// <summary>
    /// The revocation check for a leaf already proven to be issued by an intermediate
    /// <paramref name="anchorCert"/>, on a chain completed with <paramref name="anchorIssuers"/>
    /// so that it reaches a self-signed root, which is the only kind of chain every engine checks
    /// revocation on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The self-signed certificates among <paramref name="anchorIssuers"/> are the trust anchors of
    /// this build; the anchor and the rest are offered as intermediates. The result is used only
    /// when the built chain is exactly the one meant: its first element is the leaf, its second is
    /// <paramref name="anchorCert"/> itself (compared by encoding, so a different certificate for
    /// the same name, or a sibling CA under the same root, does not stand in for it), it ends at
    /// one of the supplied self-signed certificates, and the engine does not call it partial.
    /// Anything else is <see cref="CompletedChainRevocation.Inconclusive"/>.
    /// </para>
    /// <para>
    /// On that chain: <see cref="X509ChainStatusFlags.Revoked"/> on any element refuses; any
    /// status at all on the leaf refuses; an undetermined revocation status on a CA certificate
    /// above the leaf is tolerated; and any other status anywhere (an expired root, a constraint
    /// violation above the anchor) makes the chain inconclusive rather than good, so
    /// <see cref="CompletedChainRevocation.NotRevoked"/> is only ever returned for a chain that is
    /// otherwise clean.
    /// </para>
    /// </remarks>
    /// <param name="leafCert">The certificate whose revocation status is wanted.</param>
    /// <param name="anchorCert">The intermediate CA certificate that issued it.</param>
    /// <param name="anchorIssuers">The certificates above the anchor, in any order.</param>
    /// <param name="chainErrors">Receives the failure reason when the result is <see cref="CompletedChainRevocation.Refused"/>.</param>
    private static CompletedChainRevocation CheckRevocationThroughIssuers(
        X509Certificate2 leafCert,
        X509Certificate2 anchorCert,
        IReadOnlyCollection<X509Certificate2> anchorIssuers,
        out string? chainErrors)
    {
        chainErrors = null;

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        // Never fetch a missing issuer from the address a certificate names (CA Issuers). The
        // certificates to build with are the ones handed in. A real instance's certificates name
        // that address, and an engine that follows it completes the chain past an intermediate
        // anchor to a root nobody said to trust, which then fails every certificate under it.
        // This turns off only the download of issuer certificates, not of CRLs or OCSP answers.
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ExtraStore.Add(anchorCert);
        var roots = new List<X509Certificate2>();
        foreach (var issuer in anchorIssuers)
        {
            if (SameCertificate(issuer, anchorCert) || SameCertificate(issuer, leafCert))
                continue;
            if (IsSelfIssued(issuer))
            {
                roots.Add(issuer);
                chain.ChainPolicy.CustomTrustStore.Add(issuer);
            }
            else
            {
                chain.ChainPolicy.ExtraStore.Add(issuer);
            }
        }
        if (roots.Count == 0)
            return CompletedChainRevocation.Inconclusive;

        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.Build(leafCert);

        var elements = chain.ChainElements;
        var chainFlags = Flags(chain.ChainStatus);
        var isTheIntendedChain = elements.Count >= 3
            && SameCertificate(elements[0].Certificate, leafCert)
            && SameCertificate(elements[1].Certificate, anchorCert)
            && roots.Any(root => SameCertificate(root, elements[^1].Certificate))
            && (chainFlags & X509ChainStatusFlags.PartialChain) == 0;
        if (!isTheIntendedChain)
            return CompletedChainRevocation.Inconclusive;

        var leafFlags = Flags(elements[0].ChainElementStatus);
        var aboveLeafFlags = X509ChainStatusFlags.NoError;
        for (var i = 1; i < elements.Count; i++)
            aboveLeafFlags |= Flags(elements[i].ChainElementStatus);
        var allFlags = chainFlags | leafFlags | aboveLeafFlags;

        if ((allFlags & X509ChainStatusFlags.Revoked) != 0 || (leafFlags & RevocationUndetermined) != 0)
        {
            chainErrors = DescribeStatus(chain);
            return CompletedChainRevocation.Refused;
        }

        // The engine reports each element's faults on the chain as well, so the chain's own flags
        // are held to what the elements above the leaf may carry.
        if (leafFlags != X509ChainStatusFlags.NoError || ((chainFlags | aboveLeafFlags) & ~RevocationUndetermined) != 0)
            return CompletedChainRevocation.Inconclusive;

        return CompletedChainRevocation.NotRevoked;
    }

    /// <summary>Whether <paramref name="certificate"/> names itself as its issuer, as a root does.</summary>
    /// <param name="certificate">The certificate to look at.</param>
    private static bool IsSelfIssued(X509Certificate2 certificate)
        => certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);

    /// <summary>Whether two certificate objects are the same certificate, by their DER encoding.</summary>
    /// <param name="a">One certificate.</param>
    /// <param name="b">The other.</param>
    private static bool SameCertificate(X509Certificate2 a, X509Certificate2 b)
        => a.RawDataMemory.Span.SequenceEqual(b.RawDataMemory.Span);

    /// <summary>The chain's statuses as text for an audit record.</summary>
    /// <param name="chain">The chain after <see cref="X509Chain.Build(X509Certificate2)"/>.</param>
    private static string DescribeStatus(X509Chain chain)
    {
        var text = string.Join("; ",
            chain.ChainStatus.Select(s => $"{s.Status}:{s.StatusInformation?.Trim()}"));
        return string.IsNullOrWhiteSpace(text) ? "Chain build failed with no reported status." : text;
    }

    /// <summary>
    /// Whether the chain engine reports a revocation status for each element of a chain that stops
    /// short of a self-signed root, so that the absence of one can be read as "checked and good".
    /// Windows does report: in practice (Windows 11, .NET 10) it marks the leaf's status as
    /// undetermined without fetching its CRL, which fails closed. The OpenSSL-backed engine does
    /// not: it processes revocation only once the chain is complete, so a partial chain comes back
    /// with no revocation status at all, which must not be read as "not revoked".
    /// </summary>
    private static bool EngineReportsRevocationOnPartialChains => OperatingSystem.IsWindows();

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
