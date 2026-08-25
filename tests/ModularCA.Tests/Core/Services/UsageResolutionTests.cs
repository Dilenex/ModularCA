using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers usage resolution in <see cref="IssuanceValidationService"/>.
/// <para>
/// The same usage reaches issuance under three spellings depending on who wrote the profile: the
/// bootstrap seeder stores OIDs, the OIDOptions catalog also carries a friendly name, and the admin
/// UI's cert-profile editor used to write display labels. Only the OID matched the original
/// exact-match filter, so any cert profile edited in the UI was issued with no ExtendedKeyUsage and
/// no KeyUsage extension at all — silently, for manual issuance and every protocol alike.
/// </para>
/// </summary>
public class UsageResolutionTests
{
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    private static ModularCA.Database.ModularCADbContext Seeded()
    {
        var db = InMemoryDbContextFactory.Create();
        db.OIDOptions.AddRange(
            new OIDOptionEntity { OID = ServerAuthOid, FriendlyName = "serverAuth", KeyUsage = "Extended" },
            new OIDOptionEntity { OID = ClientAuthOid, FriendlyName = "clientAuth", KeyUsage = "Extended" },
            new OIDOptionEntity { OID = "2.5.29.15.0", FriendlyName = "digitalSignature", KeyUsage = "Standard" },
            new OIDOptionEntity { OID = "2.5.29.15.2", FriendlyName = "keyEncipherment", KeyUsage = "Standard" });
        db.SaveChanges();
        return db;
    }

    private static IssuanceValidationService Service(ModularCA.Database.ModularCADbContext db)
        => new(db, NullLogger<IssuanceValidationService>.Instance);

    [Theory]
    [InlineData("[\"1.3.6.1.5.5.7.3.1\"]")]   // OID — what the seeder writes
    [InlineData("[\"serverAuth\"]")]           // catalog friendly name
    [InlineData("[\"Server Auth\"]")]          // display label the admin UI used to persist
    [InlineData("[\"SERVERAUTH\"]")]           // case/separator insensitivity
    public void Extended_usages_resolve_from_any_spelling(string certProfileEkus)
    {
        using var db = Seeded();
        var result = Service(db).SetupAllowedExtendedOids(certProfileEkus, "[]");
        Assert.Equal(new[] { ServerAuthOid }, result);
    }

    [Theory]
    [InlineData("[\"digitalSignature\"]")]
    [InlineData("[\"Digital Signature\"]")]    // the label the UI used to persist
    [InlineData("[\"2.5.29.15.0\"]")]          // by OID
    public void Standard_usages_resolve_from_any_spelling(string certProfileKeyUsages)
    {
        using var db = Seeded();
        var result = Service(db).SetupAllowedStandardOids(certProfileKeyUsages);
        Assert.Equal(new[] { "digitalSignature" }, result);
    }

    [Fact]
    public void Signing_profile_still_restricts_even_across_spellings()
    {
        // Cert profile asks for both as labels; signing profile permits only clientAuth as an OID.
        // Both sides canonicalise, so the intersection must still bite.
        using var db = Seeded();
        var result = Service(db).SetupAllowedExtendedOids(
            "[\"Server Auth\",\"Client Auth\"]",
            $"[\"{ClientAuthOid}\"]");
        Assert.Equal(new[] { ClientAuthOid }, result);
    }

    [Fact]
    public void A_profile_whose_every_eku_is_unresolvable_refuses_to_issue()
    {
        // This test used to assert Assert.Empty(result) and was named
        // "Unknown_usages_are_dropped_not_emitted" — it certified a fail-open as correct.
        // CertificateBuilderService emits the ExtendedKeyUsage extension only when the list is
        // non-empty, and a certificate with NO EKU extension is unconstrained (RFC 5280
        // §4.2.1.12: absence means any purpose). So a single misspelled EKU in a profile
        // silently widened the certificate to everything — the opposite of what the profile asked.
        using var db = Seeded();

        var ex = Assert.Throws<CertificatePolicyViolationException>(
            () => Service(db).SetupAllowedExtendedOids("[\"1.2.3.4.5.6.7.8\"]", "[]"));

        Assert.Contains("1.2.3.4.5.6.7.8", ex.Message, StringComparison.Ordinal);
        Assert.Contains("every purpose", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_signing_profile_that_removes_every_requested_eku_refuses_to_issue()
    {
        // The same hazard by a different route: the EKUs resolve fine, then the signing
        // profile's AllowedEKUs intersects them away to nothing. Emitting no extension here
        // would hand back a certificate MORE permissive than either profile allows.
        using var db = Seeded();

        Assert.Throws<CertificatePolicyViolationException>(
            () => Service(db).SetupAllowedExtendedOids(
                $"[\"{ServerAuthOid}\"]", $"[\"{ClientAuthOid}\"]"));
    }

    [Fact]
    public void A_profile_that_requests_no_ekus_is_still_unconstrained_deliberately()
    {
        // The legitimate empty case, kept distinct from the two above: a profile that lists no
        // extended key usages is asking for no EKU restriction — typically a CA profile — and
        // must keep working.
        using var db = Seeded();

        Assert.Empty(Service(db).SetupAllowedExtendedOids("[]", "[]"));
    }

    [Fact]
    public void AnyExtendedKeyUsage_is_still_rejected_outright()
    {
        // RFC 5280 4.2.1.12 / CAB BR 7.1.2.2 — must not become resolvable by the new lookup.
        using var db = Seeded();
        var ex = Assert.Throws<InvalidOperationException>(
            () => Service(db).SetupAllowedExtendedOids("[\"2.5.29.37.0\"]", "[]"));
        Assert.Contains("anyExtendedKeyUsage", ex.Message);
    }

    [Fact]
    public void Empty_cert_profile_list_yields_no_usages()
    {
        using var db = Seeded();
        Assert.Empty(Service(db).SetupAllowedExtendedOids("[]", $"[\"{ServerAuthOid}\"]"));
    }
}
