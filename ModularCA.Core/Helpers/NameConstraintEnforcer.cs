using ModularCA.Shared.Errors;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace ModularCA.Core.Helpers;

/// <summary>
/// Enforces the NameConstraints extension (RFC 5280 §4.2.1.10) of every CA certificate in a
/// certification path on the names of a certificate about to be issued under it, through
/// BouncyCastle's <see cref="PkixNameConstraintValidator"/>: the subject DN (when not empty), the
/// subject's emailAddress attributes as rfc822 names, and every subject alternative name.
/// </summary>
/// <remarks>
/// <para>
/// Each CA's constraints are checked on their own. A name inside the permitted subtrees of every
/// CA and outside the excluded subtrees of all of them is exactly a name inside the intersection
/// of the permitted subtrees and outside their union, which is the state RFC 5280 §6.1.4 (g)
/// accumulates, and checking per CA lets a refusal name the CA and the subtree.
/// </para>
/// <para>
/// DNS matching is BouncyCastle's, which is the rule the console and <see cref="NameConstraintRules"/>
/// describe: <c>example.com</c> covers the host and every subdomain, <c>.example.com</c> the
/// subdomains only, on label boundaries, ignoring case.
/// </para>
/// </remarks>
public static class NameConstraintEnforcer
{
    /// <summary>The name constraints one CA certificate of the path carries.</summary>
    /// <param name="CaSubject">The CA certificate's subject, for messages.</param>
    /// <param name="Permitted">Its permitted subtrees; empty when it has none.</param>
    /// <param name="Excluded">Its excluded subtrees; empty when it has none.</param>
    public sealed record CaConstraints(string CaSubject, IReadOnlyList<GeneralSubtree> Permitted, IReadOnlyList<GeneralSubtree> Excluded);

    /// <summary>One name of the certificate being issued, in the form its check takes.</summary>
    private sealed record SubjectName(string Label, int Tag, GeneralName? General, Asn1Sequence? Dn, string? SubjectEmail);

    /// <summary>
    /// The constraints of each certificate in <paramref name="path"/> that carries any, in path order.
    /// </summary>
    /// <exception cref="InvalidOperationException">A certificate carries a NameConstraints extension that cannot be parsed.</exception>
    public static List<CaConstraints> Collect(IEnumerable<X509Certificate> path)
    {
        var result = new List<CaConstraints>();
        foreach (var ca in path)
            if (Read(ca) is { } constraints)
                result.Add(constraints);
        return result;
    }

    /// <summary>
    /// The constraints <paramref name="ca"/> carries, or null when it has no NameConstraints
    /// extension. An extension that cannot be parsed throws: a constraint that cannot be read is
    /// one no certificate can be shown to satisfy, so issuance under it is refused.
    /// </summary>
    /// <exception cref="InvalidOperationException">The extension cannot be parsed.</exception>
    public static CaConstraints? Read(X509Certificate ca)
    {
        var ext = ca.GetExtensionValue(X509Extensions.NameConstraints);
        if (ext == null)
            return null;
        try
        {
            var nc = NameConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(ext));
            return new CaConstraints(ca.SubjectDN.ToString(), Subtrees(nc.PermittedSubtrees), Subtrees(nc.ExcludedSubtrees));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"The CA certificate '{ca.SubjectDN}' carries a NameConstraints extension that cannot be parsed, so compliance "
                + "cannot be verified. Issuance is refused rather than proceeding unconstrained.", ex);
        }
    }

    private static List<GeneralSubtree> Subtrees(Asn1Sequence? sequence)
    {
        var list = new List<GeneralSubtree>();
        if (sequence != null)
            foreach (var element in sequence)
                list.Add(GeneralSubtree.GetInstance(element));
        return list;
    }

    /// <summary>
    /// Refuses, with a <see cref="CertificatePolicyViolationException"/> carrying
    /// <see cref="ErrorCodes.NameConstraintViolation"/>, a certificate whose subject DN, subject
    /// emailAddress or SAN falls outside the permitted subtrees or inside the excluded subtrees of
    /// any CA in <paramref name="constraints"/>. The message names the offending name, the CA and
    /// the subtrees concerned.
    /// </summary>
    /// <param name="constraints">The constraints of the path, from <see cref="Collect"/>.</param>
    /// <param name="subject">The subject DN of the certificate being issued.</param>
    /// <param name="sans">Its SANs as stored, <c>TYPE:value</c>.</param>
    /// <exception cref="InvalidOperationException">A SAN entry cannot be parsed (<see cref="SanGeneralNames.Parse"/>).</exception>
    public static void Enforce(IReadOnlyList<CaConstraints> constraints, X509Name subject, IEnumerable<string> sans)
    {
        if (constraints.Count == 0)
            return;

        var names = NamesOf(subject, sans);
        foreach (var ca in constraints)
        {
            var validator = Validator(ca.Permitted, ca.Excluded);
            foreach (var name in names)
            {
                if (!Passes(() => CheckPermitted(validator, name)))
                {
                    var permitted = ca.Permitted.Where(s => s.Base.TagNo == name.Tag).Select(s => Describe(s.Base));
                    throw Violation($"{name.Label} is not within the permitted {TypeLabel(name.Tag)} subtrees "
                        + $"[{string.Join(", ", permitted)}] of CA '{ca.CaSubject}'.");
                }
                if (!Passes(() => CheckExcluded(validator, name)))
                {
                    var culprit = ca.Excluded.Where(s => s.Base.TagNo == name.Tag)
                        .FirstOrDefault(s => !Passes(() => CheckExcluded(Validator([], [s]), name)));
                    throw Violation($"{name.Label} falls within the excluded subtree "
                        + $"{(culprit != null ? Describe(culprit.Base) : TypeLabel(name.Tag))} of CA '{ca.CaSubject}'.");
                }
            }
        }
    }

    /// <summary>The names <see cref="Enforce"/> checks: subject DN and its emailAddress values when the subject is not empty, then every SAN.</summary>
    private static List<SubjectName> NamesOf(X509Name subject, IEnumerable<string> sans)
    {
        var names = new List<SubjectName>();
        var dn = Asn1Sequence.GetInstance(subject.ToAsn1Object());
        if (dn.Count > 0)
        {
            names.Add(new SubjectName($"Subject DN '{subject}'", GeneralName.DirectoryName, null, dn, null));
            foreach (var email in subject.GetValueList(X509Name.EmailAddress))
                names.Add(new SubjectName($"Subject emailAddress '{email}'", GeneralName.Rfc822Name, null, null, email));
        }
        foreach (var entry in sans)
        {
            if (string.IsNullOrWhiteSpace(entry))
                continue;
            var general = SanGeneralNames.Parse(entry, out var type, out var value);
            names.Add(new SubjectName($"SAN {type}:{value}", general.TagNo, general, null, null));
        }
        return names;
    }

    private static PkixNameConstraintValidator Validator(IReadOnlyList<GeneralSubtree> permitted, IReadOnlyList<GeneralSubtree> excluded)
    {
        var validator = new PkixNameConstraintValidator();
        if (permitted.Count > 0)
            validator.IntersectPermittedSubtree(new DerSequence(permitted.ToArray<Asn1Encodable>()));
        foreach (var subtree in excluded)
            validator.AddExcludedSubtree(subtree);
        return validator;
    }

    private static void CheckPermitted(PkixNameConstraintValidator validator, SubjectName name)
    {
        if (name.Dn != null) validator.CheckPermittedDN(name.Dn);
        else if (name.SubjectEmail != null) validator.CheckPermittedEmail(name.SubjectEmail);
        else validator.CheckPermittedName(name.General!);
    }

    private static void CheckExcluded(PkixNameConstraintValidator validator, SubjectName name)
    {
        if (name.Dn != null) validator.CheckExcludedDN(name.Dn);
        else if (name.SubjectEmail != null) validator.CheckExcludedEmail(name.SubjectEmail);
        else validator.CheckExcludedName(name.General!);
    }

    private static bool Passes(Action check)
    {
        try
        {
            check();
            return true;
        }
        catch (PkixNameConstraintValidatorException)
        {
            return false;
        }
    }

    private static CertificatePolicyViolationException Violation(string message)
        => new([$"[NameConstraints] {message}"], ErrorCodes.NameConstraintViolation);

    private static string TypeLabel(int tag) => tag switch
    {
        GeneralName.DnsName => "DNS",
        GeneralName.IPAddress => "IP",
        GeneralName.Rfc822Name => "EMAIL",
        GeneralName.UniformResourceIdentifier => "URI",
        GeneralName.DirectoryName => "DN",
        GeneralName.OtherName => "otherName",
        _ => $"[{tag}]",
    };

    /// <summary>A subtree's base in the <c>TYPE:value</c> form signing profiles store it in.</summary>
    public static string Describe(GeneralName name) => name.TagNo switch
    {
        GeneralName.DirectoryName => $"DN:{X509Name.GetInstance(name.Name)}",
        GeneralName.IPAddress when name.Name is Asn1OctetString octets => $"IP:{IpRange(octets.GetOctets())}",
        _ => $"{TypeLabel(name.TagNo)}:{name.Name}",
    };

    /// <summary>An IP subtree's address and mask as <c>address/prefix</c>, or <c>address/mask</c> when the mask is not contiguous.</summary>
    private static string IpRange(byte[] octets)
    {
        if (octets.Length is not (8 or 32))
            return Convert.ToHexString(octets);
        var half = octets.Length / 2;
        var address = new System.Net.IPAddress(octets[..half]);
        var mask = octets[half..];
        var prefix = 0;
        var ended = false;
        foreach (var b in mask)
            for (var bit = 7; bit >= 0; bit--)
            {
                var set = ((b >> bit) & 1) == 1;
                if (set && ended)
                    return $"{address}/{new System.Net.IPAddress(mask)}";
                if (set) prefix++;
                else ended = true;
            }
        return $"{address}/{prefix}";
    }
}
