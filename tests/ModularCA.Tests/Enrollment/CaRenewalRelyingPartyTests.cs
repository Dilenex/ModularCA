using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Est;
using ModularCA.Shared.Entities;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Cms;
using Xunit;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace ModularCA.Tests.Enrollment;

/// <summary>
/// What clients of a renewed CA meet: the protocol configuration still resolves, the CA bundle
/// carries the current certificate, and a client certificate issued before the renewal is still
/// found, and still found revoked, whichever of the CA's certificates the validator holds.
/// </summary>
public sealed class CaRenewalRelyingPartyTests
{
    private static X509Certificate2 Net(X509Certificate certificate) => X509CertificateLoader.LoadCertificate(certificate.GetEncoded());

    /// <summary>No refusal: null (nothing to say) or the value that says so.</summary>
    private static bool Accepted(MtlsCredentialRefusal? refusal) => refusal is null or MtlsCredentialRefusal.None;

    [Fact]
    public async Task The_est_bundle_carries_the_current_certificate_and_the_chain_above_it()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Bundle Root", null, null);
        var issuing = await w.CreateIntermediateAsync(root, "Bundle Issuing", null, null);
        var rootCert = world.Certificate(root.CertificateId);
        var before = world.Certificate(issuing.CertificateId);

        var after = (await world.RenewAsync(issuing, years: 4)).Certificate;

        using var db = w.World.OpenDb();
        // Every protocol's configuration is held to "its signing profile issues from this CA": it still does.
        var resolver = new CaResolverService(db);
        foreach (var protocol in await db.CaProtocolConfigs.Where(p => p.CaId == issuing.Id && p.IsEnabled).Select(p => p.Protocol).ToListAsync())
        {
            var context = await resolver.ResolveAsync(issuing.Label, protocol);
            Assert.Equal(issuing.Id, context.Ca!.Id);
        }

        var est = new EstService(db, w.World.Keystore, resolver, null!, null!, new StubSecurityPolicyService(new SecurityPolicyEntity()), null!, NullLogger<EstService>.Instance);
        var bundle = new CmsSignedData(await est.GetCaCertsAsync(issuing.Label)).GetCertificates().EnumerateMatches(null).ToList();

        Assert.Contains(bundle, c => c.GetEncoded().AsSpan().SequenceEqual(after.GetEncoded()));
        Assert.Contains(bundle, c => c.GetEncoded().AsSpan().SequenceEqual(rootCert.GetEncoded()));
        Assert.DoesNotContain(bundle, c => c.GetEncoded().AsSpan().SequenceEqual(before.GetEncoded()));
    }

    /// <summary>SCEP GetCACert, for an RSA CA (SCEP runs on no other): the current certificate and the chain above it.</summary>
    [Fact]
    public async Task The_scep_ca_certificate_answer_carries_the_current_certificate()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.Creation.CreateRootAsync("Scep Root", "Acme", null, null, null, "US", "RSA", 3072, 6, null, w.SpaceId);
        var issuing = await w.Creation.CreateIntermediateAsync(root, w.Db.Certificates.Single(c => c.CertificateId == root.CertificateId),
            "Scep Issuing", "Acme", null, null, null, "US", "RSA", 3072, 2, null, w.SpaceId);
        var rootCert = world.Certificate(root.CertificateId);
        var before = world.Certificate(issuing.CertificateId);
        var after = (await world.RenewAsync(issuing, years: 5)).Certificate;

        using var db = w.World.OpenDb();
        var scep = new ModularCA.Core.Services.Scep.ScepService(db, w.World.Keystore, new CaResolverService(db),
            ModularCA.Tests.Api.InstanceCeremonyEndpointTests.Fake<ModularCA.Shared.Interfaces.IProtocolAuditService>.Create(), null!,
            NullLogger<ModularCA.Core.Services.Scep.ScepService>.Instance, w.Signer);
        var (data, isPkcs7) = await scep.GetCaCertAsync(issuing.Label);

        Assert.True(isPkcs7);
        var bundle = new CmsSignedData(data).GetCertificates().EnumerateMatches(null).ToList();
        Assert.Contains(bundle, c => c.GetEncoded().AsSpan().SequenceEqual(after.GetEncoded()));
        Assert.Contains(bundle, c => c.GetEncoded().AsSpan().SequenceEqual(rootCert.GetEncoded()));
        Assert.DoesNotContain(bundle, c => c.GetEncoded().AsSpan().SequenceEqual(before.GetEncoded()));
    }

    /// <summary>
    /// The chain the shared enrollment pipeline hands back with an issued certificate (ACME's
    /// download, EST and SCEP answers, MSAE and CMP responses take theirs from the same walk of
    /// the signing profile): the current certificate, then what is above it.
    /// </summary>
    [Fact]
    public async Task The_enrollment_pipelines_chain_names_the_current_certificate_and_what_is_above_it()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Pipeline Root", null, null);
        var issuing = await w.CreateIntermediateAsync(root, "Pipeline Issuing", null, null);
        var rootCert = world.Certificate(root.CertificateId);
        var after = (await world.RenewAsync(issuing, years: 4)).Certificate;

        using var db = w.World.OpenDb();
        var profile = db.SigningProfiles.Single(p => p.IssuerId == world.Ca(issuing.Id).CertificateId);
        var pipeline = new ModularCA.Core.Services.Enrollment.EnrollmentPipeline(db, null!, null!, null!, null!, null!, null!,
            NullLogger<ModularCA.Core.Services.Enrollment.EnrollmentPipeline>.Instance);
        var chain = await (Task<IReadOnlyList<string>>)typeof(ModularCA.Core.Services.Enrollment.EnrollmentPipeline)
            .GetMethod("ChainAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .Invoke(pipeline, [profile, CancellationToken.None])!;

        Assert.Equal(new[] { after.SerialNumber, rootCert.SerialNumber },
            chain.Select(pem => ModularCA.Shared.Utils.CertificateUtil.ParseFromPem(pem).SerialNumber).ToArray());

        // CMP's caPubs and the XCEP policy answer take the CA row's current certificate directly.
        Assert.Equal(after.GetEncoded(), db.Certificates.Single(c => c.CertificateId == db.CertificateAuthorities.Single(a => a.Id == issuing.Id).CertificateId).RawCertificate);
    }

    /// <summary>
    /// A request to a path that requires a client certificate, through the real mTLS middleware,
    /// with <paramref name="anchor"/> as the CA certificate the validator is configured with.
    /// Returns the status and whether the request reached the application.
    /// </summary>
    private static async Task<(int Status, bool Reached)> ThroughMtlsAsync(X509Certificate anchor, X509Certificate client, ModularCA.Database.ModularCADbContext db)
    {
        const string ns = "ModularCA.API.";
        var reached = false;
        Microsoft.AspNetCore.Http.RequestDelegate next = _ => { reached = true; return Task.CompletedTask; };
        var config = new ModularCA.Shared.Models.Config.SystemConfig { Mtls = { Enabled = true, RequiredPaths = ["/api/v1/admin"] } };
        var anchors = Activator.CreateInstance(ModularCA.Tests.Roles.ApiAssembly.TypeNamed(ns + "Startup.MtlsTrustAnchors"))!;
        ((List<X509Certificate2>)anchors.GetType().GetProperty("Certificates")!.GetValue(anchors)!).Add(Net(anchor));
        var middleware = Activator.CreateInstance(ModularCA.Tests.Roles.ApiAssembly.TypeNamed(ns + "Middleware.MtlsMiddleware"), [next, config, anchors])!;

        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions.AddSingleton(services, db);
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext
        {
            RequestServices = Microsoft.Extensions.DependencyInjection.ServiceCollectionContainerBuilderExtensions.BuildServiceProvider(services),
        };
        context.Request.Path = "/api/v1/admin/users";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
        context.Connection.ClientCertificate = Net(client);
        await (Task)middleware.GetType().GetMethod("InvokeAsync")!.Invoke(middleware, [context])!;
        return (context.Response.StatusCode, reached);
    }

    /// <summary>
    /// mTLS through the middleware: a client certificate issued before the renewal and one issued
    /// after are both let through, whether the validator holds the old CA certificate or the new
    /// one, and one that was revoked is refused under either.
    /// </summary>
    [Fact]
    public async Task The_mtls_middleware_admits_old_and_new_client_certificates_under_either_ca_certificate_and_refuses_a_revoked_one()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Middleware Root", null, null);
        var oldRoot = world.Certificate(root.CertificateId);
        var (_, oldLeaf) = await world.LeafAsync(root, "mtls-before");
        var (revokedRow, revokedLeaf) = await world.LeafAsync(root, "mtls-before-revoked");
        var newRoot = (await world.RenewAsync(root)).Certificate;
        var (_, newLeaf) = await world.LeafAsync(root, "mtls-after");
        var tracked = w.Db.Certificates.Single(c => c.CertificateId == revokedRow.CertificateId);
        tracked.Revoked = true;
        tracked.RevocationDate = DateTime.UtcNow;
        tracked.RevocationReason = "KeyCompromise";
        w.Db.SaveChanges();

        foreach (var anchor in new[] { oldRoot, newRoot })
        {
            using var db = w.World.OpenDb();
            foreach (var leaf in new[] { oldLeaf, newLeaf })
            {
                var (status, reached) = await ThroughMtlsAsync(anchor, leaf, db);
                Assert.True(reached, $"{leaf.SubjectDN} under CA serial {anchor.SerialNumber.ToString(16)} was answered {status}");
            }
            var refused = await ThroughMtlsAsync(anchor, revokedLeaf, db);
            Assert.False(refused.Reached);
            Assert.Equal(403, refused.Status);
        }
    }

    /// <summary>
    /// EST re-enrollment's judgment of the client certificate (the step that decides whether the
    /// presented certificate may re-enroll, through the real resolver): one issued before the
    /// renewal is accepted against the CA's current certificate, and a revoked or retired one
    /// from before the renewal is refused.
    /// </summary>
    [Fact]
    public async Task Est_re_enrollment_accepts_a_client_certificate_from_before_the_renewal_and_refuses_a_revoked_one()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Est Root", null, null);
        var (_, oldLeaf) = await world.LeafAsync(root, "est-before");
        var (revokedRow, revokedLeaf) = await world.LeafAsync(root, "est-before-revoked");
        var (retiredRow, retiredLeaf) = await world.LeafAsync(root, "est-before-retired");
        var renewed = await world.RenewAsync(root);
        var (_, newLeaf) = await world.LeafAsync(root, "est-after");
        var revoked = w.Db.Certificates.Single(c => c.CertificateId == revokedRow.CertificateId);
        revoked.Revoked = true;
        revoked.RevocationDate = DateTime.UtcNow;
        revoked.RevocationReason = "KeyCompromise";
        w.Db.Certificates.Single(c => c.CertificateId == retiredRow.CertificateId).RetiredAt = DateTime.UtcNow;
        w.Db.SaveChanges();

        using var db = w.World.OpenDb();
        var est = new EstService(db, w.World.Keystore, new CaResolverService(db), null!, null!,
            new StubSecurityPolicyService(new SecurityPolicyEntity { RequireMtlsOcspCheck = false }), null!, NullLogger<EstService>.Instance);
        var verify = typeof(EstService).GetMethod("VerifyPresentedCertificateAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        async Task<string?> RejectionAsync(X509Certificate client)
        {
            Func<string, Task> reject = reason => throw new InvalidOperationException(reason);
            try
            {
                var issuer = await (Task<Guid>)verify.Invoke(est, [Net(client), root.Label, reject])!;
                Assert.Equal(renewed.Renewed.CertificateId, issuer);     // verified against the CA's current certificate
                return null;
            }
            catch (InvalidOperationException ex)
            {
                return ex.Message;
            }
        }

        Assert.Null(await RejectionAsync(oldLeaf));
        Assert.Null(await RejectionAsync(newLeaf));
        Assert.Contains("revoked", await RejectionAsync(revokedLeaf));
        Assert.Contains("retired", await RejectionAsync(retiredLeaf));
    }

    [Fact]
    public async Task A_client_certificate_from_before_the_renewal_is_found_and_found_revoked_under_either_ca_certificate()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Client Root", null, null);
        var oldRoot = world.Certificate(root.CertificateId);
        var (_, oldLeaf) = await world.LeafAsync(root, "client-before");
        var (oldRevokedRow, oldRevoked) = await world.LeafAsync(root, "client-before-revoked");

        var newRoot = (await world.RenewAsync(root)).Certificate;
        var (_, newLeaf) = await world.LeafAsync(root, "client-after");
        var tracked = w.Db.Certificates.Single(c => c.CertificateId == oldRevokedRow.CertificateId);
        tracked.Revoked = true;
        tracked.RevocationDate = DateTime.UtcNow;
        tracked.RevocationReason = "KeyCompromise";
        w.Db.SaveChanges();

        using var db = w.World.OpenDb();
        // The issuer in the validated chain is whichever CA certificate the validator holds.
        foreach (var held in new[] { oldRoot, newRoot })
        {
            Assert.True(Accepted(await MtlsCredentialStatus.PresentedCertificateRefusalAsync(db, Net(oldLeaf), Net(held))));
            Assert.True(Accepted(await MtlsCredentialStatus.PresentedCertificateRefusalAsync(db, Net(newLeaf), Net(held))));
            Assert.Equal(MtlsCredentialRefusal.CertificateRevoked, await MtlsCredentialStatus.PresentedCertificateRefusalAsync(db, Net(oldRevoked), Net(held)));
        }

        // A disabled CA is refused through its earlier certificate too.
        w.Db.CertificateAuthorities.Single(c => c.Id == root.Id).IsEnabled = false;
        w.Db.SaveChanges();
        using var after = w.World.OpenDb();
        Assert.False(Accepted(await MtlsCredentialStatus.PresentedCertificateRefusalAsync(after, Net(oldLeaf), Net(oldRoot))));
        Assert.False(Accepted(await MtlsCredentialStatus.PresentedCertificateRefusalAsync(after, Net(oldLeaf), Net(newRoot))));
    }
}
