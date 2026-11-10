using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers the rule that decides which usages a certificate profile may name.
/// <para>
/// It was two hardcoded arrays inside the API's FluentValidation class — eight key usages and
/// seven extended key usages, written as string literals. Anything outside them was refused at
/// profile creation however the <c>OIDOptions</c> catalog was configured, so the catalog was
/// decorative for this path and the CA had a fixed ceiling on what it could ever be told to
/// issue. Most immediately that meant no Kerberos KDC authentication, so no domain controller
/// certificate, so no Windows smart-card logon — a chain of consequence with no obvious
/// connection to a seven-line array.
/// </para>
/// </summary>
public class CertProfileUsageValidationTests
{
    /// <summary>The catalog rows a stock install carries after seeding.</summary>
    private static readonly (string? Oid, string? FriendlyName)[] ExtendedCatalog =
    [
        ("1.3.6.1.5.5.7.3.1", "serverAuth"),
        ("1.3.6.1.5.5.7.3.2", "clientAuth"),
        ("1.3.6.1.5.5.7.3.9", "OCSPSigning"),
        ("1.3.6.1.4.1.311.20.2.2", "smartcardLogon"),
        ("1.3.6.1.5.2.3.5", "kdcAuthentication"),
    ];

    private static readonly (string? Oid, string? FriendlyName)[] StandardCatalog =
    [
        ("2.5.29.15.0", "digitalSignature"),
        ("2.5.29.15.1", "nonRepudiation"),
        ("2.5.29.15.2", "keyEncipherment"),
    ];

    // ── the usages this unblocks ─────────────────────────────────────────────

    [Fact]
    public void A_smart_card_logon_profile_is_accepted()
    {
        // The card's own certificate. The catalog and the certificate builder have always
        // supported this OID; the validator's array was the only thing refusing it.
        var check = CertProfileUsageValidation.CheckExtendedKeyUsages(
            "1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.20.2.2", ExtendedCatalog);

        Assert.True(check.IsValid);
        Assert.Empty(check.Unknown);
    }

    [Fact]
    public void A_domain_controller_profile_is_accepted()
    {
        // The other half of smart-card logon, and the half that gets forgotten: without a KDC
        // certificate the DC rejects PKINIT with KDC_ERR_PADATA_TYPE_NOSUPP, which reads as a
        // problem with the card.
        var check = CertProfileUsageValidation.CheckExtendedKeyUsages(
            "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.5.2.3.5", ExtendedCatalog);

        Assert.True(check.IsValid);
    }

    // ── spelling tolerance ───────────────────────────────────────────────────

    [Theory]
    [InlineData("smartcardLogon")]
    [InlineData("smartcardlogon")]
    [InlineData("SmartcardLogon")]
    [InlineData("1.3.6.1.4.1.311.20.2.2")]
    public void A_usage_resolves_by_oid_or_by_catalog_name(string spelling)
    {
        // A profile field may legitimately hold either form — the bootstrap seeder writes OIDs,
        // the catalog also carries a friendly name — so the validator must accept both or it
        // rejects profiles the issuance path would have resolved.
        Assert.True(CertProfileUsageValidation.CheckExtendedKeyUsages(spelling, ExtendedCatalog).IsValid);
    }

    [Fact]
    public void Whitespace_around_entries_is_ignored()
    {
        Assert.True(CertProfileUsageValidation
            .CheckExtendedKeyUsages(" clientAuth , smartcardLogon ", ExtendedCatalog).IsValid);
    }

    // ── what must still be refused ───────────────────────────────────────────

    [Fact]
    public void A_usage_the_catalog_does_not_have_is_refused()
    {
        // Opening the gate is not removing it. An OID with no catalog row is silently DROPPED at
        // issuance, so accepting it here would produce a profile that looks configured and issues
        // certificates missing the usage the operator asked for.
        var check = CertProfileUsageValidation.CheckExtendedKeyUsages(
            "1.3.6.1.5.5.7.3.2,2.16.840.1.101.3.6.8", ExtendedCatalog);

        Assert.False(check.IsValid);
        Assert.Equal(["2.16.840.1.101.3.6.8"], check.Unknown);
    }

    [Fact]
    public void The_message_names_what_was_unknown_and_where_to_fix_it()
    {
        var check = CertProfileUsageValidation.CheckExtendedKeyUsages("1.2.3.4", ExtendedCatalog);
        var message = CertProfileUsageValidation.DescribeFailure("ExtendedKeyUsages", check);

        Assert.Contains("1.2.3.4", message, StringComparison.Ordinal);
        Assert.Contains("OID Options", message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnyExtendedKeyUsage_is_refused_even_if_someone_catalogues_it()
    {
        // RFC 5280 4.2.1.12 and CA/B BR 7.1.2.2 both bar it from subscriber certificates, and
        // IssuanceValidationService throws on it — so a profile carrying it could only ever fail
        // at first use. Refused independently of the catalog.
        (string? Oid, string? FriendlyName)[] catalogWithAny =
            [..ExtendedCatalog, ("2.5.29.37.0", "anyExtendedKeyUsage")];

        var check = CertProfileUsageValidation.CheckExtendedKeyUsages("2.5.29.37.0", catalogWithAny);

        Assert.False(check.IsValid);
        Assert.True(check.ContainsForbidden);
        Assert.Contains("forbidden", CertProfileUsageValidation.DescribeFailure("ExtendedKeyUsages", check),
            StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_extended_list_is_valid()
    {
        // A profile need not constrain EKUs at all; the validator only runs this rule when the
        // field is non-empty, and the rule itself must agree.
        Assert.True(CertProfileUsageValidation.CheckExtendedKeyUsages("", ExtendedCatalog).IsValid);
    }

    // ── key usages take the same treatment ───────────────────────────────────

    [Fact]
    public void Key_usages_resolve_against_the_catalog_too()
    {
        Assert.True(CertProfileUsageValidation
            .CheckKeyUsages("digitalSignature,nonRepudiation", StandardCatalog).IsValid);
    }

    [Fact]
    public void A_key_usage_outside_the_catalog_is_refused()
    {
        var check = CertProfileUsageValidation.CheckKeyUsages("digitalSignature,teleport", StandardCatalog);
        Assert.False(check.IsValid);
        Assert.Equal(["teleport"], check.Unknown);
    }

    [Fact]
    public void An_empty_catalog_accepts_nothing()
    {
        // Fail closed. A catalog that failed to seed must not become a wildcard.
        Assert.False(CertProfileUsageValidation.CheckExtendedKeyUsages("clientAuth", []).IsValid);
        Assert.False(CertProfileUsageValidation.CheckKeyUsages("digitalSignature", []).IsValid);
    }

    // ── the forms the field really arrives in ────────────────────────────────

    /// <summary>
    /// A profile is stored, and returned, as a JSON array; the console sends a comma-separated
    /// list. Both are read, to the same entries.
    /// </summary>
    [Theory]
    [InlineData("[\"clientAuth\",\"smartcardLogon\"]")]
    [InlineData("[ \"clientAuth\" , \" smartcardLogon \" ]")]
    [InlineData("clientAuth, smartcardLogon")]
    [InlineData("clientAuth,smartcardLogon,")]
    [InlineData("[\"clientAuth\",null,\"\",\"smartcardLogon\"]")]
    public void A_field_is_read_as_a_JSON_array_or_a_comma_separated_list(string field)
    {
        Assert.Equal(["clientAuth", "smartcardLogon"], CertProfileUsageValidation.ParseField(field));
        Assert.True(CertProfileUsageValidation.CheckExtendedKeyUsages(field, ExtendedCatalog).IsValid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("[]")]
    [InlineData("null")]
    public void An_empty_field_in_any_form_has_no_entries(string? field)
    {
        Assert.Empty(CertProfileUsageValidation.ParseField(field));
        Assert.True(CertProfileUsageValidation.CheckKeyUsages(field, StandardCatalog).IsValid);
        Assert.True(CertProfileUsageValidation.CheckExtendedKeyUsages(field, ExtendedCatalog).IsValid);
    }

    /// <summary>
    /// The comma split of the removed validators read a JSON array as entries like
    /// <c>["clientAuth"</c>, which resolve to nothing; the unknown entry is named as it was sent.
    /// </summary>
    [Fact]
    public void An_unknown_entry_of_a_JSON_array_is_named_without_brackets_or_quotes()
    {
        var check = CertProfileUsageValidation.CheckExtendedKeyUsages("[\"clientAuth\",\"teleportAuth\"]", ExtendedCatalog);

        Assert.False(check.IsValid);
        Assert.Equal(["teleportAuth"], check.Unknown);
        Assert.Equal("ExtendedKeyUsages contains teleportAuth, which is not in the OID catalog. "
            + "Add it under Admin → OID Options, or use an existing OID or friendly name.",
            CertProfileUsageValidation.DescribeFailure("ExtendedKeyUsages", check));
    }

    [Fact]
    public void A_key_usage_array_is_checked_against_the_standard_rows()
    {
        Assert.True(CertProfileUsageValidation.CheckKeyUsages("[\"digitalSignature\",\"Key Encipherment\",\"2.5.29.15.1\"]", StandardCatalog).IsValid);

        var check = CertProfileUsageValidation.CheckKeyUsages("[\"digitalSignature\",\"clientAuth\",\"clientAuth\"]", StandardCatalog);
        Assert.Equal(["clientAuth"], check.Unknown);
    }

    [Fact]
    public void AnyExtendedKeyUsage_is_refused_by_a_name_that_resolves_to_it_too()
    {
        (string? Oid, string? FriendlyName)[] catalogWithAny =
            [..ExtendedCatalog, ("2.5.29.37.0", "anyExtendedKeyUsage")];

        var check = CertProfileUsageValidation.CheckExtendedKeyUsages("[\"clientAuth\",\"Any Extended Key Usage\"]", catalogWithAny);

        Assert.True(check.ContainsForbidden);
        Assert.False(check.IsValid);
        Assert.Empty(check.Unknown);
    }

    // ── an update excuses what the profile already stores ────────────────────

    [Fact]
    public void Entries_the_profile_already_stores_are_not_checked_again()
    {
        const string stored = "[\"clientAuth\",\"1.2.3.4\",\"2.5.29.37.0\"]";

        Assert.True(CertProfileUsageValidation.CheckExtendedKeyUsages(stored, ExtendedCatalog, stored).IsValid);
        Assert.True(CertProfileUsageValidation.CheckExtendedKeyUsages("clientAuth, 1.2.3.4, serverAuth", ExtendedCatalog, stored).IsValid);

        var added = CertProfileUsageValidation.CheckExtendedKeyUsages("clientAuth, 1.2.3.4, 1.2.3.5", ExtendedCatalog, stored);
        Assert.Equal(["1.2.3.5"], added.Unknown);

        // Without the stored field, a create, everything is checked.
        var create = CertProfileUsageValidation.CheckExtendedKeyUsages(stored, ExtendedCatalog);
        Assert.Equal(["1.2.3.4"], create.Unknown);
        Assert.True(create.ContainsForbidden);

        Assert.True(CertProfileUsageValidation.CheckKeyUsages("digitalSignature, legacySign", StandardCatalog, "[\"legacySign\"]").IsValid);
        Assert.False(CertProfileUsageValidation.CheckKeyUsages("digitalSignature, legacySign", StandardCatalog).IsValid);
    }
}

/// <summary>
/// The seeded OID catalog has to carry the usages a smart-card deployment needs, because a usage
/// absent from it is dropped at issuance rather than rejected.
/// </summary>
public class DefaultOidCatalogTests
{
    private static Dictionary<string, string> DefaultEkus() =>
        YamlOIDLoader.GetDefaultOIDConfig().OID.ExtendedKeyUsage!;

    [Theory]
    [InlineData("smartcardLogon", "1.3.6.1.4.1.311.20.2.2")]
    [InlineData("kdcAuthentication", "1.3.6.1.5.2.3.5")]
    [InlineData("clientAuth", "1.3.6.1.5.5.7.3.2")]
    public void The_built_in_catalog_carries_the_usage(string friendlyName, string oid)
    {
        var ekus = DefaultEkus();
        Assert.True(ekus.ContainsKey(friendlyName), $"{friendlyName} missing from the default OID catalog");
        Assert.Equal(oid, ekus[friendlyName]);
    }

    [Fact]
    public void The_built_in_catalog_does_not_offer_anyExtendedKeyUsage()
    {
        Assert.DoesNotContain(CertProfileUsageValidation.AnyExtendedKeyUsageOid, DefaultEkus().Values);
    }
}
