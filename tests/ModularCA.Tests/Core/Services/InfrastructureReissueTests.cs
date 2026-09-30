using System.Reflection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Reissuing a CA's OCSP responder is an operator's action on an existing CA, not a ceremony: it
/// succeeds where the CA's tenant requires key ceremonies, with the real signer judging every key
/// operation. From 0.3.0 the new responder key was generated under a ceremony context naming no
/// ceremony, which that requirement refused.
/// </summary>
public sealed class InfrastructureReissueTests
{
    [Fact]
    public async Task A_responder_is_reissued_where_the_tenant_requires_key_ceremonies()
    {
        var world = SignerTestWorld.Create();
        var caId = world.CaEcId;
        using (var seed = world.OpenDb())
        {
            seed.Tenants.Single(t => t.Id == world.TenantB).RequireKeyCeremony = true;
            seed.SigningProfiles.Add(new SigningProfileEntity { Name = "ca-ec signing", AllowedAlgorithms = "[]", IssuerId = world["ca-ec"].Ref.CertificateId });
            seed.CertProfiles.Add(new CertProfileEntity
            {
                Name = "OCSP Responder Certificate Profile",
                KeyUsages = "[\"Digital Signature\"]",
                ExtendedKeyUsages = "[\"1.3.6.1.5.5.7.3.9\"]",
                AllowedKeySizes = "[]",
                AllowedSignatureAlgorithms = "[]",
            });
            await seed.SaveChangesAsync();
        }

        var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence);
        using var db = world.OpenDb();
        var service = new CaCreationService(
            db,
            Fake<ICrlService>.Create(),
            Fake<ICaServiceUrlService>.Create(),
            new CsrService(db, new HeldKeyService(db, new EphemeralDataProtectionProvider(), new RecordingAuditService())),
            new SignerIssuance(db, signer),
            new SystemConfig(),
            NullLogger<CaCreationService>.Instance,
            Fake<IQuotaService>.Create(),
            signer);

        await service.ReissueInfrastructureCertsAsync(caId, reissueOcsp: true, reissueTsa: false);

        using var check = world.OpenDb();
        var responderId = check.CertificateAuthorities.Single(c => c.Id == caId).OcspResponderCertificateId;
        Assert.NotNull(responderId);
        var ocsp = SigningContext.ForCa("reissue-test", SigningPurpose.Ocsp, caId, world.TenantB);
        var responder = Assert.Single(await signer.ListKeysAsync(ocsp), k => k.Key.CertificateId == responderId);
        Assert.Equal(KeyKind.OcspResponder, responder.Kind);
        Assert.Single(world.Persistence.Appended);

        var keyRows = check.SignerAudit.Where(r => r.Operation == "GenerateKey" || r.Operation == "CommitKey").ToList();
        Assert.Equal(2, keyRows.Count);
        Assert.All(keyRows, r => Assert.Equal(SignerAuditEntity.AllowedOutcome, r.Outcome));
        Assert.All(keyRows, r => Assert.Equal(nameof(SigningPurpose.Infrastructure), r.Purpose));
        Assert.All(keyRows, r => Assert.Equal(caId, r.CaId));
    }

    /// <summary>A service whose every call succeeds and returns defaults.</summary>
    public class Fake<T> : DispatchProxy where T : class
    {
        /// <summary>Creates the fake.</summary>
        public static T Create() => Create<T, Fake<T>>();

        /// <inheritdoc />
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            var type = targetMethod!.ReturnType;
            if (type == typeof(void)) return null;
            if (type == typeof(Task)) return Task.CompletedTask;
            if (type == typeof(Task<bool>)) return Task.FromResult(true);
            if (type == typeof(bool)) return true;
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>))
            {
                var inner = type.GetGenericArguments()[0];
                var value = inner.IsValueType ? Activator.CreateInstance(inner) : null;
                return typeof(Task).GetMethod(nameof(Task.FromResult))!.MakeGenericMethod(inner).Invoke(null, [value]);
            }
            return type.IsValueType ? Activator.CreateInstance(type) : null;
        }
    }

    /// <summary>
    /// Issues the requested certificate with the CA key through the signer, under the context
    /// the caller names, and links it to its request as issuance does.
    /// </summary>
    private sealed class SignerIssuance(ModularCADbContext db, ISigningService signer) : ICertificateIssuanceService
    {
        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            X509Certificate caCert, KeyRef caKey, SigningContext caSigningContext, CancellationToken cancellationToken = default)
        {
            var request = db.CertificateRequests.Single(c => c.Id == csrId);
            using var reader = new StringReader(request.CSR);
            var csr = (Pkcs10CertificationRequest)new PemReader(reader).ReadObject();

            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
            gen.SetIssuerDN(caCert.SubjectDN);
            gen.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
            gen.SetNotBefore(notBefore ?? DateTime.UtcNow.AddMinutes(-1));
            gen.SetNotAfter(notAfter ?? DateTime.UtcNow.AddDays(1));
            gen.SetPublicKey(csr.GetPublicKey());
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
            var cert = gen.Generate(new SigningServiceSignatureFactory(signer, caKey, SignatureAlgorithm.ForPublicKey(caCert.GetPublicKey()), caSigningContext));

            var pem = CertificateUtil.ConvertDerToPem(cert.GetEncoded(), "CERTIFICATE");
            var row = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(),
                SerialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber),
                SubjectDN = cert.SubjectDN.ToString(),
                Issuer = cert.IssuerDN.ToString(),
                Pem = pem,
                RawCertificate = cert.GetEncoded(),
                NotBefore = cert.NotBefore,
                NotAfter = cert.NotAfter,
            };
            db.Certificates.Add(row);
            request.IssuedCertificateId = row.CertificateId;
            request.Status = "Issued";
            db.SaveChanges();
            return Task.FromResult(new IssuanceResult(pem));
        }

        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public Task<IssuanceResult> IssueCaCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public Task<IssuanceResult> ReissueCertificateAsync(Guid? certId, string? certSN, Guid? csrId,
            DateTime? notBefore, DateTime? notAfter, string? newSubjectDn = null, List<string>? newSans = null,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten)
            => throw new NotSupportedException();
    }
}
