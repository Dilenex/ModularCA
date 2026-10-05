using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Tests.TestUtils;
using Xunit;
using static ModularCA.Tests.Core.Services.IssuingCaRefusalTests;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Reissue SAN overrides: an absent (null) list keeps the certificate's SANs, an empty list
/// replaces them with none. Removing every SAN is refused (400, before the predecessor is
/// revoked) where a certificate without SANs is not valid: a TLS server certificate, or one with
/// an empty subject.
/// </summary>
public class ReissueSanOverrideTests
{
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";

    [Fact]
    public void An_empty_override_replaces_the_sans_and_an_absent_one_keeps_them()
    {
        const string original = "[\"DNS:a.example\"]";

        Assert.Equal("[]", CertificateIssuanceService.ApplySanOverrides(original, "[]"));
        Assert.Equal(original, CertificateIssuanceService.ApplySanOverrides(original, null));
        Assert.Equal(original, CertificateIssuanceService.ApplySanOverrides(original, " "));
        Assert.Equal(original, CertificateIssuanceService.ApplySanOverrides(original, "not json"));
        Assert.Equal("[\"DNS:b.example\"]", CertificateIssuanceService.ApplySanOverrides(original, "[\"DNS:b.example\"]"));
    }

    [Fact]
    public void A_certificate_without_sans_is_refused_only_where_it_is_not_valid()
    {
        var server = Assert.Throws<InvalidRequestException>(
            () => CertificateIssuanceService.EnsureSanlessCertificateIsValid("CN=web", [ClientAuth, ServerAuth]));
        Assert.Equal(ErrorCodes.SanOverrideInvalid, server.Code);
        Assert.Equal(400, server.Status);
        Assert.Throws<InvalidRequestException>(() => CertificateIssuanceService.EnsureSanlessCertificateIsValid("", [ClientAuth]));

        CertificateIssuanceService.EnsureSanlessCertificateIsValid("CN=client", [ClientAuth]);
        CertificateIssuanceService.EnsureSanlessCertificateIsValid("CN=anything", []);
    }

    /// <summary>
    /// Through the real reissue: clearing every SAN of a serverAuth certificate is refused before
    /// the predecessor is revoked (the revocation service is null, so reaching it would throw a
    /// NullReferenceException instead).
    /// </summary>
    [Fact]
    public async Task Reissuing_a_tls_server_certificate_with_no_sans_is_refused_before_revocation()
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, CaState.Healthy, forReissue: true);
        UseEkus(db, ServerAuth);

        var ex = await Assert.ThrowsAsync<InvalidRequestException>(
            () => Service(db, s.CaCert).ReissueCertificateAsync(null, null, s.CsrId, null, null, newSans: []));

        Assert.Equal(ErrorCodes.SanOverrideInvalid, ex.Code);
        Assert.False((await db.Certificates.AsNoTracking().FirstAsync(c => c.CertificateId == s.Predecessor!.CertificateId)).Revoked);
    }

    /// <summary>A client certificate may lose its SANs: the reissue goes past the check.</summary>
    [Fact]
    public async Task Reissuing_a_client_certificate_with_no_sans_gets_past_the_check()
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, CaState.Healthy, forReissue: true);
        UseEkus(db, ClientAuth);

        var ex = await Record.ExceptionAsync(
            () => Service(db, s.CaCert).ReissueCertificateAsync(null, null, s.CsrId, null, null, newSans: []));

        Assert.False(ex is InvalidRequestException { Code: ErrorCodes.SanOverrideInvalid }, ex?.ToString());
    }

    private static void UseEkus(ModularCADbContext db, params string[] oids)
    {
        foreach (var (oid, name) in new[] { (ServerAuth, "serverAuth"), (ClientAuth, "clientAuth") })
            if (!db.OIDOptions.Any(o => o.OID == oid))
                db.OIDOptions.Add(new OIDOptionEntity { OID = oid, FriendlyName = name, KeyUsage = "Extended" });
        db.CertProfiles.Single(p => p.Name == "TLS Server").ExtendedKeyUsages = System.Text.Json.JsonSerializer.Serialize(oids);
        db.SaveChanges();
    }
}
