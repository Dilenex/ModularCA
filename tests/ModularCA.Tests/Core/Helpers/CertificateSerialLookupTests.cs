using ModularCA.Core.Helpers;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Helpers;

/// <summary>
/// Covers <see cref="CertificateSerialLookup"/>, which exists because a serial number is unique
/// only within an issuer — the unique index on <c>Certificates</c> is <c>(SerialNumber, Issuer)</c>.
/// The behaviour that matters is the ambiguous case: two issuers minting the same serial must never
/// resolve to an arbitrary row, because callers use the result to authorize and to revoke.
/// </summary>
public class CertificateSerialLookupTests
{
    private static CertificateEntity Cert(string serial, string issuer) => new()
    {
        CertificateId = Guid.NewGuid(),
        SerialNumber = serial,
        Issuer = issuer,
        SubjectDN = $"CN=leaf-{issuer}",
        Pem = "",
        NotBefore = DateTime.UtcNow.AddDays(-1),
        NotAfter = DateTime.UtcNow.AddDays(30),
    };

    [Fact]
    public async Task Resolves_the_row_when_the_serial_is_unique()
    {
        using var db = InMemoryDbContextFactory.Create();
        var only = Cert("0A0B", "CN=Issuer One");
        db.Certificates.Add(only);
        db.Certificates.Add(Cert("FFFF", "CN=Issuer One"));
        await db.SaveChangesAsync();

        var result = await db.Certificates.ResolveBySerialAsync("0A0B");

        Assert.Equal(SerialResolution.Found, result.Outcome);
        Assert.Equal(only.CertificateId, result.Certificate!.CertificateId);
    }

    /// <summary>
    /// The table stores minimal hex. A serial written as OpenSSL prints it and as the consoles
    /// show it (a leading zero, lower case, separators) names the same certificate.
    /// </summary>
    [Theory]
    [InlineData("02C06C00")]
    [InlineData("02c06c00")]
    [InlineData("02:C0:6C:00")]
    [InlineData("2C06C00")]
    public async Task A_serial_written_with_a_leading_zero_or_separators_finds_the_stored_row(string written)
    {
        using var db = InMemoryDbContextFactory.Create();
        var stored = Cert("2C06C00", "CN=Issuer One");
        db.Certificates.AddRange(stored, Cert("C06C00", "CN=Issuer One"));
        await db.SaveChangesAsync();

        var result = await db.Certificates.ResolveBySerialAsync(written);
        Assert.Equal(SerialResolution.Found, result.Outcome);
        Assert.Equal(stored.CertificateId, result.Certificate!.CertificateId);
        Assert.Equal(stored.CertificateId, db.Certificates.ResolveBySerialOrNull(written)!.CertificateId);
    }

    [Fact]
    public async Task A_row_stored_exactly_as_written_wins_over_the_stored_form()
    {
        using var db = InMemoryDbContextFactory.Create();
        var exact = Cert("0A0B", "CN=Issuer One");
        db.Certificates.AddRange(exact, Cert("A0B", "CN=Issuer Two"));
        await db.SaveChangesAsync();

        var result = await db.Certificates.ResolveBySerialAsync("0A0B");
        Assert.Equal(exact.CertificateId, result.Certificate!.CertificateId);
    }

    [Fact]
    public async Task Reports_NotFound_for_an_unknown_serial()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Certificates.Add(Cert("0A0B", "CN=Issuer One"));
        await db.SaveChangesAsync();

        var result = await db.Certificates.ResolveBySerialAsync("DEAD");

        Assert.Equal(SerialResolution.NotFound, result.Outcome);
        Assert.Null(result.Certificate);
    }

    [Fact]
    public async Task Reports_Ambiguous_when_two_issuers_share_a_serial()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Certificates.Add(Cert("0A0B", "CN=Issuer One"));
        db.Certificates.Add(Cert("0A0B", "CN=Issuer Two"));
        await db.SaveChangesAsync();

        var result = await db.Certificates.ResolveBySerialAsync("0A0B");

        Assert.Equal(SerialResolution.Ambiguous, result.Outcome);
        Assert.Null(result.Certificate);
    }

    [Fact]
    public async Task Ambiguity_is_resolved_by_narrowing_on_the_issuer()
    {
        using var db = InMemoryDbContextFactory.Create();
        var one = Cert("0A0B", "CN=Issuer One");
        var issuerOneCertId = Guid.NewGuid();
        one.IssuerCertificateId = issuerOneCertId;
        var two = Cert("0A0B", "CN=Issuer Two");
        two.IssuerCertificateId = Guid.NewGuid();
        db.Certificates.AddRange(one, two);
        await db.SaveChangesAsync();

        // The extension composes onto any IQueryable, which is the intended escape hatch for
        // callers that know their issuer.
        var scoped = await db.Certificates
            .Where(c => c.IssuerCertificateId == issuerOneCertId)
            .ResolveBySerialAsync("0A0B");

        Assert.Equal(SerialResolution.Found, scoped.Outcome);
        Assert.Equal(one.CertificateId, scoped.Certificate!.CertificateId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Blank_serials_are_NotFound_rather_than_matching_everything(string? serial)
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Certificates.Add(Cert("0A0B", "CN=Issuer One"));
        await db.SaveChangesAsync();

        var result = await db.Certificates.ResolveBySerialAsync(serial);

        Assert.Equal(SerialResolution.NotFound, result.Outcome);
    }

    [Fact]
    public async Task OrNull_overload_collapses_ambiguity_to_null_so_callers_fail_closed()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Certificates.Add(Cert("0A0B", "CN=Issuer One"));
        db.Certificates.Add(Cert("0A0B", "CN=Issuer Two"));
        await db.SaveChangesAsync();

        Assert.Null(await db.Certificates.ResolveBySerialOrNullAsync("0A0B"));
    }

    [Fact]
    public void Synchronous_overload_agrees_with_the_async_one()
    {
        using var db = InMemoryDbContextFactory.Create();
        var only = Cert("0A0B", "CN=Issuer One");
        db.Certificates.Add(only);
        db.Certificates.Add(Cert("BEEF", "CN=Issuer One"));
        db.Certificates.Add(Cert("BEEF", "CN=Issuer Two"));
        db.SaveChanges();

        Assert.Equal(only.CertificateId, db.Certificates.ResolveBySerialOrNull("0A0B")!.CertificateId);
        Assert.Null(db.Certificates.ResolveBySerialOrNull("BEEF"));
        Assert.Null(db.Certificates.ResolveBySerialOrNull("NOPE"));
    }
}
