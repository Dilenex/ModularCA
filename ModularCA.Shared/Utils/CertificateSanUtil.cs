using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Answers whether a server certificate presents a given hostname.
/// </summary>
/// <remarks>
/// Used at startup to check that every SNI-gated hostname is actually covered by the certificate
/// the listener serves. A gated name missing from the SANs fails as a hostname mismatch before any
/// client-certificate exchange happens, which sends the operator to the authentication
/// configuration to debug a naming problem.
/// </remarks>
public static class CertificateSanUtil
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    /// <summary>
    /// Determines whether the certificate presents the given hostname, honouring wildcards.
    /// </summary>
    /// <param name="certificate">The server certificate.</param>
    /// <param name="hostname">The hostname a client will connect to.</param>
    /// <returns><c>true</c> when a DNS SAN matches.</returns>
    /// <remarks>
    /// Only DNS SANs are consulted. The Subject CN is deliberately ignored: RFC 2818 deprecated it
    /// for hostname verification and every current client — browsers, curl, .NET, Go — refuses a
    /// certificate whose name appears only there, so treating a CN match as coverage would suppress
    /// the warning in exactly the case that still fails.
    /// </remarks>
    public static bool CoversHostname(X509Certificate2? certificate, string? hostname)
    {
        if (certificate == null || string.IsNullOrWhiteSpace(hostname))
            return false;

        var host = hostname.Trim().TrimEnd('.');

        foreach (var dnsName in GetDnsNames(certificate))
        {
            if (Matches(dnsName, host))
                return true;
        }

        return false;
    }

    /// <summary>Extracts the DNS entries from the certificate's Subject Alternative Name extension.</summary>
    public static IReadOnlyList<string> GetDnsNames(X509Certificate2 certificate)
    {
        var names = new List<string>();

        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != SubjectAlternativeNameOid)
                continue;

            try
            {
                // Read the GeneralNames SEQUENCE directly rather than via X509SubjectAlternativeNameExtension,
                // whose EnumerateDnsNames throws on a SAN carrying entry types it does not model
                // (otherName, for instance — this product issues UPN SANs). A startup diagnostic
                // must not be the thing that takes the process down.
                var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
                var sequence = reader.ReadSequence();

                while (sequence.HasData)
                {
                    var tag = sequence.PeekTag();

                    // dNSName is context-specific [2], primitive, IA5String.
                    if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
                        names.Add(sequence.ReadCharacterString(UniversalTagNumber.IA5String, tag));
                    else
                        sequence.ReadEncodedValue();
                }
            }
            catch (AsnContentException)
            {
                // A malformed SAN yields no names rather than an exception out of a diagnostic.
            }
        }

        return names;
    }

    /// <summary>
    /// Matches one SAN entry against a hostname, honouring a leading wildcard label.
    /// </summary>
    private static bool Matches(string sanEntry, string host)
    {
        var san = sanEntry.Trim().TrimEnd('.');
        if (san.Length == 0)
            return false;

        if (!san.StartsWith("*.", StringComparison.Ordinal))
            return string.Equals(san, host, StringComparison.OrdinalIgnoreCase);

        // A wildcard covers exactly one label (RFC 6125 section 6.4.3): "*.example.com" matches
        // "est.example.com" but not "example.com" and not "a.b.example.com". Getting this wrong in
        // the permissive direction would silence the warning for a certificate that clients reject.
        var suffix = san[1..];
        if (!host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            return false;

        var label = host[..^suffix.Length];
        return label.Length > 0 && !label.Contains('.');
    }
}
