using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A CA is identified by its id or its certificate, never by a value another CA can share or a
/// row that merely mentions it: a CRL is served by its configuration's CA certificate, not its
/// issuer DN, an enrollment token takes its CA from its signing profile's issuer, not from a
/// protocol configuration naming the profile, and an ACME revocation is audited under the CA it
/// was made at.
/// </summary>
public class CaIdentityResolutionTests
{
    /// <summary>
    /// Two CAs share a subject DN, and the other one's CRL has the higher number (CRL numbers
    /// are allocated per issuer name). The CRL served for a CA is its own; the issuer-DN fallback
    /// served the other CA's.
    /// </summary>
    [Fact]
    public async Task A_cas_crl_is_its_own_when_another_ca_shares_its_subject_dn()
    {
        using var db = InMemoryDbContextFactory.Create();
        CertificateEntity CaCert() => new()
        {
            CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N"), SubjectDN = "CN=Shared CA", Issuer = "CN=Shared CA", IsCA = true,
        };
        var mine = CaCert();
        var theirs = CaCert();
        db.Certificates.AddRange(mine, theirs);
        var myConfig = new CrlConfigurationEntity { CaCertificateId = mine.CertificateId, UpdateInterval = "0 */6 * * *" };
        var theirConfig = new CrlConfigurationEntity { CaCertificateId = theirs.CertificateId, UpdateInterval = "0 */6 * * *" };
        db.CrlConfigurations.AddRange(myConfig, theirConfig);
        db.Crls.AddRange(
            new CrlEntity { IssuerName = "CN=Shared CA", TaskId = myConfig.TaskId, CrlNumber = 1, RawData = [1], ThisUpdate = DateTime.UtcNow },
            new CrlEntity { IssuerName = "CN=Shared CA", TaskId = theirConfig.TaskId, CrlNumber = 2, RawData = [2], ThisUpdate = DateTime.UtcNow },
            new CrlEntity { IssuerName = "CN=Shared CA", TaskId = theirConfig.TaskId, CrlNumber = 3, IsDelta = true, RawData = [3], ThisUpdate = DateTime.UtcNow });
        await db.SaveChangesAsync();
        var crls = new CrlService(db, null!, NullLogger<CrlService>.Instance, null!, null!, null!,
            System.Reflection.DispatchProxy.Create<ISigningService, SpaceIsolationMatrixTests.NoOpProxy>());

        Assert.Equal([1], (await crls.GetLatestCrlRawAsync(mine.CertificateId))!.Der);
        Assert.Null(await crls.GetLatestDeltaCrlRawAsync(mine.CertificateId));
        Assert.Equal([2], (await crls.GetLatestCrlRawAsync(theirs.CertificateId))!.Der);
    }

    /// <summary>
    /// An enrollment token is stamped with the CA its signing profile issues from, the CA
    /// <c>RequireCaCapability</c> authorized the caller against. It took the CA of whichever
    /// protocol configuration named the profile, here another space's CA's stale one.
    /// </summary>
    [Fact]
    public async Task A_token_takes_its_ca_from_the_signing_profiles_issuer()
    {
        using var db = InMemoryDbContextFactory.Create();
        var issuerCert = Guid.NewGuid();
        var issuer = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Issuer", Label = "issuer", CertificateId = issuerCert, SpaceId = Guid.NewGuid() };
        var other = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Other", Label = "other", CertificateId = Guid.NewGuid(), SpaceId = Guid.NewGuid() };
        var profile = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "issuer-signing", IssuerId = issuerCert };
        db.CertificateAuthorities.AddRange(other, issuer);
        db.SigningProfiles.Add(profile);
        db.CaProtocolConfigs.Add(new CaProtocolConfigEntity { CaId = other.Id, Protocol = "EST", SigningProfileId = profile.Id });
        await db.SaveChangesAsync();

        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminEnrollmentTokenController");
        var controller = Microsoft.Extensions.DependencyInjection.ActivatorUtilities.CreateInstance(new SpaceIsolationMatrixTests.Resolver(db), type);
        var task = (Task)type.GetMethod("ResolveCaFromProfilesAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(controller, [profile.Id, null, null])!;
        await task;
        var resolved = ((Guid CaId, Guid? SpaceId)?)task.GetType().GetProperty("Result")!.GetValue(task);

        Assert.Equal((issuer.Id, issuer.SpaceId), resolved);
    }

    /// <summary>
    /// The <c>CertificateRevoked</c> ACME audit row names the CA the revocation was made at, by
    /// label and id, as the other ACME audit rows do. It carried neither, so a CA-scoped auditor
    /// never saw ACME revocations.
    /// </summary>
    [Fact]
    public async Task An_acme_revocation_is_audited_under_its_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Open CA", Label = "open", SpaceId = Guid.NewGuid() };
        var account = new AcmeAccountEntity { JwkJson = "{}", JwkThumbprint = "t", CertificateAuthorityId = ca.Id };
        var leaf = TestCaMaterial.CreateCa("CN=leaf.example.com");
        var der = leaf.Certificate.GetEncoded();
        var cert = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = CertificateUtil.FormatSerialNumber(leaf.Certificate.SerialNumber),
            SubjectDN = leaf.SubjectDn, Issuer = "CN=Open CA", RawCertificate = der, Pem = "x",
        };
        db.CertificateAuthorities.Add(ca);
        db.AcmeAccounts.Add(account);
        db.Certificates.Add(cert);
        db.AcmeOrders.Add(new AcmeOrderEntity { AccountId = account.Id, CertificateId = cert.CertificateId, CaLabel = "open" });
        await db.SaveChangesAsync();

        var audit = new RecordingProtocolAudit();
        var services = new SpaceIsolationMatrixTests.Resolver(db);
        services.Add(typeof(IProtocolAuditService), audit);
        services.Add(typeof(IAcmeOrderService), new ModularCA.Core.Services.Acme.AcmeOrderService(db, audit, null!, null!));
        services.Add(typeof(ICertificateRevocationService),
            System.Reflection.DispatchProxy.Create<ICertificateRevocationService, SpaceIsolationMatrixTests.NoOpProxy>());
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Acme.AcmeOrderController");
        var controller = Microsoft.Extensions.DependencyInjection.ActivatorUtilities.CreateInstance(services, type);
        var http = new DefaultHttpContext { RequestServices = services };
        var certificate = Convert.ToBase64String(der).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        http.Items["AcmeJws"] = new AcmeJwsPayload { AccountId = account.Id, Payload = JsonSerializer.Serialize(new { certificate, reason = 4 }) };
        http.Items[(string)ApiAssembly.TypeNamed("ModularCA.API.Filters.AcmeJwsActionFilter").GetField("AddressedCaItem")!.GetValue(null)!] = ca;
        type.GetProperty("ControllerContext")!.SetValue(controller, new ControllerContext { HttpContext = http });

        var result = await (Task<IActionResult>)type.GetMethod("RevokeCert")!.Invoke(controller, [])!;

        Assert.IsType<OkResult>(result);
        var row = Assert.Single(audit.Acme, a => a.Operation == "CertificateRevoked");
        Assert.Equal("open", row.CaLabel);
        Assert.Equal(ca.Id, row.CaId);
        Assert.Equal(ca.SpaceId, row.SpaceId);
    }

    /// <summary>
    /// A protocol configuration saved before the foreign-profile refusal may name another CA's
    /// signing profile. SCEP, EST and CMP take their profiles from
    /// <see cref="CaResolverService.ResolveAsync"/> (SCEP and CMP hand the result to the pipeline,
    /// EST lets the pipeline call it), and ACME's finalize reaches it through the pipeline, so the
    /// addressed CA is the one that issues or nothing does.
    /// </summary>
    [Theory]
    [InlineData("SCEP")]
    [InlineData("EST")]
    [InlineData("CMP")]
    [InlineData("ACME")]
    public async Task A_legacy_protocol_config_naming_another_cas_profile_is_refused(string protocol)
    {
        using var db = InMemoryDbContextFactory.Create();
        CertificateAuthorityEntity Ca(string label) => new()
        {
            Id = Guid.NewGuid(), Name = label, Label = label, IsEnabled = true, CertificateId = Guid.NewGuid(),
        };
        var mine = Ca("mine");
        var other = Ca("other");
        var othersProfile = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "other-signing", IssuerId = other.CertificateId };
        db.CertificateAuthorities.AddRange(mine, other);
        db.SigningProfiles.Add(othersProfile);
        db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
        {
            CaId = mine.Id, Protocol = protocol, IsEnabled = true, SigningProfileId = othersProfile.Id, CertProfileId = Guid.NewGuid(),
        });
        await db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => new CaResolverService(db).ResolveAsync("mine", protocol));
        Assert.Contains("does not issue from this CA", ex.Message);
    }

    /// <summary>Records ACME protocol audit rows with their scope; the other protocols' methods are not expected.</summary>
    private sealed class RecordingProtocolAudit : IProtocolAuditService
    {
        public List<(string Operation, string? CaLabel, Guid? CaId, Guid? SpaceId)> Acme { get; } = [];

        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null)
        {
            Acme.Add((operation, caLabel, certificateAuthorityId, spaceId));
            return Task.CompletedTask;
        }

        public Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm,
            string? keySize, string? templateName, string? caLabel, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            string? callerPrincipal = null, string? realm = null, string? authMethod = null)
            => throw new NotSupportedException();
        public Task LogEstAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogScepAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? revocationReason, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => throw new NotSupportedException();
    }
}
