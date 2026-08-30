using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers the subject DN length rule that stops a certificate being signed and then lost.
/// <para>
/// <c>Certificates.SubjectDN</c> was varchar(255) while <c>CertRequestEntity.Subject</c> allowed
/// 1024 and <c>DnComponentSanitizer</c> permitted CN 64 + O 128 + OU 128 and 128 per remaining
/// RDN. A subject well inside every application rule therefore exceeded the column; MySQL 8
/// defaults to STRICT_TRANS_TABLES, so the INSERT failed with error 1406 <em>after</em> signing.
/// The certificate existed, signed by the production CA, with no row — so it could never appear in
/// a CRL, never be revoked, and OCSP would never find it.
/// </para>
/// </summary>
public class SubjectDnLengthTests
{
    private static string Dn(int cn, int o, int ou)
        => $"CN={new string('c', cn)},O={new string('o', o)},OU={new string('u', ou)}";

    /// <summary>
    /// The case from the review: every component at its permitted maximum. It must now be
    /// storable, because it was always issuable.
    /// </summary>
    [Fact]
    public void A_subject_with_every_component_at_its_maximum_fits()
    {
        var dn = Dn(DnComponentSanitizer.CommonNameMaxLength,
                    DnComponentSanitizer.OrganizationMaxLength,
                    DnComponentSanitizer.OrganizationMaxLength);

        Assert.True(dn.Length > 255, $"expected the historical failure case to exceed 255; was {dn.Length}");
        DnComponentSanitizer.ValidateSubjectDnLength(dn, CertificateEntity.SubjectDnMaxLength);
    }

    /// <summary>
    /// The storage limit must not be narrower than what can be requested, or the same class of
    /// failure returns with a longer subject.
    /// </summary>
    [Fact]
    public void Storage_is_not_narrower_than_the_request_field()
    {
        var requestSubjectMaxLength = typeof(CertRequestEntity)
            .GetProperty(nameof(CertRequestEntity.Subject))!
            .GetCustomAttributes(typeof(System.ComponentModel.DataAnnotations.MaxLengthAttribute), false)
            .Cast<System.ComponentModel.DataAnnotations.MaxLengthAttribute>()
            .Single().Length;

        Assert.True(CertificateEntity.SubjectDnMaxLength >= requestSubjectMaxLength,
            $"Certificates.SubjectDN holds {CertificateEntity.SubjectDnMaxLength} but a request may "
            + $"carry {requestSubjectMaxLength}; the difference is silently unissuable.");
    }

    /// <summary>Exactly at the limit is storable — an off-by-one here costs a lost certificate.</summary>
    [Fact]
    public void A_dn_exactly_at_the_limit_is_accepted()
    {
        var dn = new string('x', CertificateEntity.SubjectDnMaxLength);
        DnComponentSanitizer.ValidateSubjectDnLength(dn, CertificateEntity.SubjectDnMaxLength);
    }

    /// <summary>
    /// Beyond the limit must be refused, and refused with an explanation an operator can act on.
    /// </summary>
    [Fact]
    public void A_dn_over_the_limit_is_refused_before_signing()
    {
        var dn = new string('x', CertificateEntity.SubjectDnMaxLength + 1);

        var ex = Assert.Throws<InvalidOperationException>(
            () => DnComponentSanitizer.ValidateSubjectDnLength(dn, CertificateEntity.SubjectDnMaxLength));

        Assert.Contains(dn.Length.ToString(), ex.Message);
        Assert.Contains("Shorten the subject", ex.Message);
    }

    /// <summary>An ordinary subject is unaffected.</summary>
    [Fact]
    public void A_normal_subject_is_unaffected()
        => DnComponentSanitizer.ValidateSubjectDnLength("CN=host.example.test,O=Example", CertificateEntity.SubjectDnMaxLength);
}
