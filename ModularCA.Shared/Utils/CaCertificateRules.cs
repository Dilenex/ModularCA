using ModularCA.Shared.Errors;
using Org.BouncyCastle.Asn1.X509;

namespace ModularCA.Shared.Utils;

/// <summary>
/// The extension rules a certificate must satisfy when <c>basicConstraints.cA</c> is TRUE,
/// enforced at the moment of signing.
/// </summary>
/// <remarks>
/// <para>
/// These rules previously existed in only one of the two places that build CA certificates.
/// <c>BouncyCastleCertificateAuthority</c> — used by
/// bootstrap for the self-signed root — refused an EKU-bearing or encipherment-bearing CA, while
/// <c>CertificateBuilderService</c> — used by the admin API for every runtime-created
/// intermediate — emitted whatever the resolved profile asked for. So the defect that was fixed
/// for roots remained reachable one level down: an operator who put an EKU on a CA-flagged cert
/// profile got a non-compliant intermediate, silently, and every leaf beneath it failed
/// EKU-nesting in Windows CryptoAPI with <c>CERT_E_WRONG_USAGE</c>.
/// </para>
/// <para>
/// Extensions cannot be corrected after issuance — they are inside the signature — so both
/// builders now call this one class. A future third builder that forgets to is the failure mode
/// this consolidation exists to prevent; see the callers listed on each method.
/// </para>
/// </remarks>
public static class CaCertificateRules
{
    /// <summary>
    /// The key-usage bits a CA certificate must never assert: a CA key signs certificates and
    /// CRLs, it does not encipher keys or perform key agreement.
    /// </summary>
    /// <remarks>
    /// RFC 5480 §3 forbids <c>keyEncipherment</c> outright for <c>id-ecPublicKey</c>, and RFC 8410
    /// §5 does the same for Ed25519 — which is what the default install uses, so this is the
    /// common case rather than an exotic one.
    /// </remarks>
    public const int ForbiddenCaKeyUsageMask =
        KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment | KeyUsage.KeyAgreement;

    /// <summary>
    /// The key-usage bits a CA certificate must always assert, per RFC 5280 §4.2.1.3. A CA
    /// certificate without <c>keyCertSign</c> makes every chain it signs fail path validation.
    /// </summary>
    public const int RequiredCaKeyUsageMask = KeyUsage.KeyCertSign | KeyUsage.CrlSign;

    /// <summary>
    /// Refuses a CA certificate whose key usages include <see cref="ForbiddenCaKeyUsageMask"/>.
    /// No-op when <paramref name="isCa"/> is false.
    /// </summary>
    /// <param name="isCa">Whether the certificate being built is a CA.</param>
    /// <param name="keyUsageFlags">The resolved <see cref="KeyUsage"/> bit flags.</param>
    /// <param name="requestedNames">
    /// The usage names the flags were resolved from, quoted in the exception so the operator can
    /// find the offending profile entry.
    /// </param>
    /// <exception cref="ConfigurationValidationException">A forbidden bit is set on a CA certificate.</exception>
    public static void EnsureKeyUsagesPermitted(bool isCa, int keyUsageFlags, IEnumerable<string> requestedNames)
    {
        if (!isCa || (keyUsageFlags & ForbiddenCaKeyUsageMask) == 0)
            return;

        throw new ConfigurationValidationException(
            "A CA certificate must not assert keyEncipherment, dataEncipherment or keyAgreement. "
            + "Requested: " + string.Join(", ", requestedNames)
            + ". A CA key signs certificates and CRLs; RFC 5480 §3 forbids keyEncipherment "
            + "for EC keys and RFC 8410 §5 for Ed25519.",
            ErrorCodes.CaKeyUsageForbidden);
    }

    /// <summary>
    /// Refuses a CA certificate that would carry an ExtendedKeyUsage extension. No-op when
    /// <paramref name="isCa"/> is false or no EKUs were resolved.
    /// </summary>
    /// <remarks>
    /// An EKU on a CA constrains every certificate beneath it (RFC 5280 §4.2.1.12), and CA/B
    /// Forum BR §7.1.2.1.2 forbids <c>extKeyUsage</c> on a root outright. What the CA is permitted
    /// to <em>issue</em> is a separate question, carried by the signing profile's
    /// <c>AllowedEKUs</c>, and is unaffected by this rule.
    /// </remarks>
    /// <param name="isCa">Whether the certificate being built is a CA.</param>
    /// <param name="extendedKeyUsages">The resolved EKU OIDs or friendly names.</param>
    /// <exception cref="ConfigurationValidationException">A CA certificate would carry an EKU.</exception>
    public static void EnsureNoExtendedKeyUsage(bool isCa, IEnumerable<string> extendedKeyUsages)
    {
        if (!isCa)
            return;

        var requested = extendedKeyUsages as IReadOnlyCollection<string> ?? extendedKeyUsages.ToList();
        if (requested.Count == 0)
            return;

        throw new ConfigurationValidationException(
            "A CA certificate must not carry an ExtendedKeyUsage extension. Requested: "
            + string.Join(", ", requested)
            + ". An EKU on a CA constrains every certificate beneath it; put the permitted "
            + "issuance EKUs on the signing profile instead.",
            ErrorCodes.CaExtendedKeyUsageForbidden);
    }

    /// <summary>
    /// Returns <paramref name="keyUsageFlags"/> with <see cref="RequiredCaKeyUsageMask"/> set when
    /// building a CA certificate, and reports which bits had to be added.
    /// </summary>
    /// <remarks>
    /// Adding these is by-design correctness rather than an error: a CA profile that simply does
    /// not restate the implied CA bits (or has had them intersected away by profile inheritance)
    /// still describes a valid CA, and the certificate is always built correctly. Callers log the
    /// <paramref name="addedBits"/> at debug level so the expected normalisation does not emit a
    /// misleading warning on every CA creation.
    /// </remarks>
    /// <param name="isCa">Whether the certificate being built is a CA.</param>
    /// <param name="keyUsageFlags">The resolved <see cref="KeyUsage"/> bit flags.</param>
    /// <param name="addedBits">The mask of bits this call had to add; zero when none were missing.</param>
    /// <returns>The flags to emit.</returns>
    public static int ApplyRequiredKeyUsages(bool isCa, int keyUsageFlags, out int addedBits)
    {
        if (!isCa)
        {
            addedBits = 0;
            return keyUsageFlags;
        }

        addedBits = RequiredCaKeyUsageMask & ~keyUsageFlags;
        return keyUsageFlags | RequiredCaKeyUsageMask;
    }
}
