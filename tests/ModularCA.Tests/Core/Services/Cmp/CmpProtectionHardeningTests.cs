using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Cmp;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Core.Services.Cmp;

/// <summary>
/// Drives <see cref="CmpService.ProcessRequestAsync"/> with PBMAC-protected and malformed messages
/// to pin what the responder refuses before it looks a credential up: PBMAC parameters it would
/// not derive a key under, PBMAC at a CA that requires signatures (read from that CA's own row),
/// the failInfo bits the refusal carries, and the CMP audit row each refusal now writes.
/// </summary>
public class CmpProtectionHardeningTests
{
    private const string PbmOid = "1.2.840.113533.7.66.13";
    private static readonly AlgorithmIdentifier Sha256 = new(NistObjectIdentifiers.IdSha256);
    private static readonly AlgorithmIdentifier Sha1 = new(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
    private static readonly AlgorithmIdentifier HmacSha1 = new(new DerObjectIdentifier("1.3.6.1.5.5.8.1.2"), DerNull.Instance);
    private static readonly AlgorithmIdentifier HmacSha256 = new(PkcsObjectIdentifiers.IdHmacWithSha256, DerNull.Instance);
    private static readonly AlgorithmIdentifier HmacMd5 = new(new DerObjectIdentifier("1.3.6.1.5.5.8.1.1"), DerNull.Instance);

    /// <summary>Records CMP audit rows; other protocols are unexpected here.</summary>
    private sealed class RecordingAudit : IProtocolAuditService
    {
        public List<(string MessageType, bool Success, string? Error, string? CaLabel, Guid? CaId)> Entries { get; } = [];

        public Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? revocationReason, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
        {
            Entries.Add((messageType, success, errorMessage, caLabel, certificateAuthorityId));
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
        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null)
            => throw new NotSupportedException();
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => throw new NotSupportedException();
    }

    private sealed record Harness(ModularCADbContext Db, CmpService Service, RecordingAudit Audit, Guid StrictCaId, Guid LaxCaId,
        ISigningService Signer, string LaxSubjectDn);

    /// <summary>
    /// Two CMP-enabled CAs over one key: "lax" accepts PBMAC, "strict" requires signatures. The
    /// lax CA's row is written first, which is the row the old label-blind lookup read for the
    /// label-less route.
    /// </summary>
    private static Harness Build()
    {
        var databaseName = $"cmp-{Guid.NewGuid():N}";
        var db = InMemoryDbContextFactory.Create(databaseName);
        var materials = new List<TestCaMaterial>();

        Guid AddCa(string label, bool isDefault, bool requireSignature)
        {
            var ca = TestCaMaterial.CreateCa($"CN={label} CMP CA, O=ModularCA");
            materials.Add(ca);
            var certificateId = Guid.NewGuid();
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = certificateId,
                SerialNumber = CertificateUtil.FormatSerialNumber(ca.Certificate.SerialNumber),
                SubjectDN = ca.SubjectDn,
                Issuer = ca.SubjectDn,
                IsCA = true,
                Pem = CertificateUtil.ConvertDerToPem(ca.Certificate.GetEncoded(), "CERTIFICATE"),
                RawCertificate = ca.Certificate.GetEncoded(),
                NotBefore = ca.Certificate.NotBefore,
                NotAfter = ca.Certificate.NotAfter,
            });
            var caId = Guid.NewGuid();
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = caId, Name = label, Label = label, IsDefault = isDefault, IsEnabled = true,
                CertificateId = certificateId, SpaceId = Guid.NewGuid(),
            });
            var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = $"{label}-signing", IssuerId = certificateId };
            var certProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = $"{label}-device", ValidityPeriodMax = "P30D" };
            db.SigningProfiles.Add(signing);
            db.CertProfiles.Add(certProfile);
            db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
            {
                Id = Guid.NewGuid(), CaId = caId, Protocol = "CMP", IsEnabled = true,
                SigningProfileId = signing.Id, CertProfileId = certProfile.Id,
                CmpRequireSignature = requireSignature,
            });
            db.SaveChanges();
            return caId;
        }

        var lax = AddCa("lax", isDefault: false, requireSignature: false);
        var strict = AddCa("strict", isDefault: true, requireSignature: true);

        var keystore = new TestKeystore(materials.Select(m => m.AsSigner()).ToArray());
        var audit = new RecordingAudit();
        var signer = TestSigner.Over(keystore, databaseName);
        var service = new CmpService(db, keystore,
            InstanceCeremonyEndpointTests.Fake<ICertificateRevocationService>.Create(),
            new CaResolverService(db), audit,
            InstanceCeremonyEndpointTests.Fake<IEnrollmentPipeline>.Create(),
            new EnrollmentTokenServiceStub(),
            NullLogger<CmpService>.Instance,
            signer);
        return new Harness(db, service, audit, strict, lax, signer, materials[0].SubjectDn);
    }

    /// <summary>A PBMAC-protected genm under the given parameters; the MAC itself is never reached.</summary>
    private static byte[] PbmacMessage(AlgorithmIdentifier owf, AlgorithmIdentifier mac, int iterations)
    {
        var random = new SecureRandom();
        byte[] Bytes(int n) { var b = new byte[n]; random.NextBytes(b); return b; }

        var header = new PkiHeaderBuilder(PkiHeader.CMP_2000,
                new GeneralName(new X509Name("CN=device")), new GeneralName(new X509Name("CN=Lab CMP CA")))
            .SetMessageTime(new DerGeneralizedTime(DateTime.UtcNow))
            .SetTransactionID(new DerOctetString(Bytes(16)))
            .SetSenderNonce(new DerOctetString(Bytes(16)))
            .SetSenderKID(new DerOctetString(System.Text.Encoding.UTF8.GetBytes("no-such-reference")))
            .SetProtectionAlg(new AlgorithmIdentifier(new DerObjectIdentifier(PbmOid),
                new PbmParameter(Bytes(16), owf, iterations, mac)))
            .Build();
        var body = new PkiBody(PkiBody.TYPE_GEN_MSG,
            new GenMsgContent(new InfoTypeAndValue(new DerObjectIdentifier("1.3.6.1.5.5.7.4.17"))));
        return new PkiMessage(header, body, new DerBitString(Bytes(32))).GetDerEncoded();
    }

    /// <summary>The PKIStatusInfo of an error message, and the RFC 4210 bit numbers its failInfo sets.</summary>
    private static (string Text, List<int> FailBits) ReadError(byte[] response)
    {
        var message = PkiMessage.GetInstance(Asn1Object.FromByteArray(response));
        Assert.Equal(PkiBody.TYPE_ERROR, message.Body.Type);
        var status = ErrorMsgContent.GetInstance(message.Body.Content).PkiStatusInfo;
        var bytes = status.FailInfo.GetBytes();
        var bits = new List<int>();
        for (var i = 0; i < bytes.Length * 8; i++)
            if ((bytes[i / 8] & (0x80 >> (i % 8))) != 0) bits.Add(i);
        return (status.StatusString[0].GetString(), bits);
    }

    [Theory]
    [InlineData("sha1-owf")]
    [InlineData("hmac-md5")]
    [InlineData("iterations")]
    public async Task Pbmac_parameters_outside_the_allow_list_are_refused_with_bad_alg_and_audited(string variant)
    {
        var h = Build();
        var message = variant switch
        {
            "sha1-owf" => PbmacMessage(Sha1, HmacSha256, 1000),
            "hmac-md5" => PbmacMessage(Sha256, HmacMd5, 1000),
            _ => PbmacMessage(Sha256, HmacSha256, 500_000),
        };

        var (text, bits) = ReadError(await h.Service.ProcessRequestAsync(message, "lax", "10.0.0.5"));

        Assert.Equal([0], bits); // badAlg
        Assert.StartsWith("PBMAC", text);
        var row = Assert.Single(h.Audit.Entries);
        Assert.Equal("Error", row.MessageType);
        Assert.False(row.Success);
        Assert.Contains("badAlg", row.Error);
        Assert.Equal(h.LaxCaId, row.CaId);
    }

    /// <summary>
    /// What <c>openssl cmp -secret</c> sends by default: SHA-256 as the one-way function,
    /// HMAC-SHA1, 500 iterations. It passes the parameter check and fails only on the unknown
    /// reference, as before.
    /// </summary>
    [Fact]
    public async Task Openssl_default_pbmac_parameters_are_accepted()
    {
        var h = Build();

        var (text, bits) = ReadError(await h.Service.ProcessRequestAsync(PbmacMessage(Sha256, HmacSha1, 500), "lax", "10.0.0.5"));

        Assert.StartsWith("PBMAC verification failed", text);
        Assert.Equal([2], bits); // badRequest
    }

    /// <summary>
    /// PBMAC at a CA that requires signature protection is refused on that CA's own setting, on
    /// the label-less route too, where the old lookup read whichever CMP row came first (here the
    /// lax CA's) and let the request through to credential lookup.
    /// </summary>
    [Theory]
    [InlineData("strict")]
    [InlineData(null)]
    public async Task Pbmac_at_a_ca_requiring_signatures_is_refused_on_that_cas_own_setting(string? label)
    {
        var h = Build();

        var (text, bits) = ReadError(await h.Service.ProcessRequestAsync(PbmacMessage(Sha256, HmacSha1, 500), label, "10.0.0.5"));

        Assert.Equal("This CA requires signature-based CMP protection; PBMAC is not accepted.", text);
        Assert.Equal([1], bits); // badMessageCheck
        Assert.Equal(h.StrictCaId, Assert.Single(h.Audit.Entries).CaId);
    }

    [Fact]
    public async Task The_signature_requirement_is_read_from_the_cas_own_row()
    {
        var h = Build();
        Assert.True(await CmpService.CaRequiresCmpSignatureAsync(h.Db, h.StrictCaId));
        Assert.False(await CmpService.CaRequiresCmpSignatureAsync(h.Db, h.LaxCaId));
        Assert.False(await CmpService.CaRequiresCmpSignatureAsync(h.Db, Guid.NewGuid()));
    }

    /// <summary>An unreadable message is answered and audited, where it used to be answered only.</summary>
    [Fact]
    public async Task An_unreadable_message_is_answered_with_bad_data_format_and_audited()
    {
        var h = Build();

        var (_, bits) = ReadError(await h.Service.ProcessRequestAsync([0x30, 0x03, 0x02, 0x01, 0x00], "lax", "10.0.0.5"));

        Assert.Equal([5], bits); // badDataFormat
        var row = Assert.Single(h.Audit.Entries);
        Assert.Equal("Error", row.MessageType);
        Assert.Contains("Invalid CMP PKIMessage encoding", row.Error);
        Assert.Equal("lax", row.CaLabel);
    }

    /// <summary>
    /// The failInfo bits go out as RFC 4210 numbers them. BouncyCastle's integer constructor takes
    /// its own masks, so the bit numbers passed to it set other bits: badRequest went out as
    /// wrongAuthority, badAlg as nothing.
    /// </summary>
    [Theory]
    [InlineData(0, PkiFailureInfo.BadAlg)]
    [InlineData(1, PkiFailureInfo.BadMessageCheck)]
    [InlineData(2, PkiFailureInfo.BadRequest)]
    [InlineData(3, PkiFailureInfo.BadTime)]
    [InlineData(5, PkiFailureInfo.BadDataFormat)]
    [InlineData(6, PkiFailureInfo.WrongAuthority)]
    [InlineData(9, PkiFailureInfo.BadPop)]
    [InlineData(23, PkiFailureInfo.NotAuthorized)]
    [InlineData(25, PkiFailureInfo.SystemFailure)]
    public void Fail_info_bits_are_numbered_as_rfc_4210_numbers_them(int bit, int bouncyCastleMask)
        => Assert.Equal(new PkiFailureInfo(bouncyCastleMask), CmpService.FailureInfo(bit));

    /// <summary>
    /// A bit in the third octet is encoded in three content octets with no unused bits for
    /// notAuthorized (23), and in four with six unused bits for systemFailure (25).
    /// </summary>
    [Theory]
    [InlineData(23, new byte[] { 0x03, 0x04, 0x00, 0x00, 0x00, 0x01 })]
    [InlineData(25, new byte[] { 0x03, 0x05, 0x06, 0x00, 0x00, 0x00, 0x40 })]
    public void High_fail_info_bits_have_the_der_length_and_padding_they_need(int bit, byte[] der)
        => Assert.Equal(der, CmpService.FailureInfo(bit).GetDerEncoded());

    /// <summary>
    /// A revocation the caller may not make is refused with notAuthorized (bit 23). It went out as
    /// bit 6, which RFC 4210 names wrongAuthority.
    /// </summary>
    [Fact]
    public async Task An_unauthorised_revocation_carries_not_authorized_on_the_wire()
    {
        var h = Build();
        var laxCa = await h.Db.CertificateAuthorities.SingleAsync(c => c.Id == h.LaxCaId);
        var tokens = new EnrollmentTokenService(h.Db, h.Signer);
        var (_, secret) = await tokens.GenerateCmpSharedSecretAsync(
            Guid.NewGuid(), "rr-device", TimeSpan.FromHours(1), 0, h.LaxCaId, laxCa.SpaceId);

        var targetSerial = new Org.BouncyCastle.Math.BigInteger("0A1B2C3D", 16);
        h.Db.Certificates.Add(new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = CertificateUtil.FormatSerialNumber(targetSerial),
            SubjectDN = "CN=admin-mtls, O=ModularCA",
            Issuer = h.LaxSubjectDn,
            Pem = "-",
            NotBefore = DateTime.UtcNow.AddDays(-1),
            NotAfter = DateTime.UtcNow.AddDays(30),
        });
        await h.Db.SaveChangesAsync();

        var request = PbmacRevocationRequest(System.Text.Encoding.UTF8.GetBytes(secret), "rr-device", targetSerial, h.LaxSubjectDn);
        var response = PkiMessage.GetInstance(Asn1Object.FromByteArray(
            await h.Service.ProcessRequestAsync(request, "lax", "10.0.0.5")));

        Assert.Equal(PkiBody.TYPE_REVOCATION_REP, response.Body.Type);
        var status = Assert.Single(RevRepContent.GetInstance(response.Body.Content).GetStatus());
        Assert.Equal(2, status.Status.IntValueExact); // rejection
        Assert.Equal(new byte[] { 0x03, 0x04, 0x00, 0x00, 0x00, 0x01 }, status.FailInfo.GetDerEncoded());
        Assert.Equal("Not authorized to revoke this certificate.", status.StatusString[0].GetString());
    }

    /// <summary>
    /// A PBMAC-protected rr for one serial, MACed with <paramref name="secret"/> under SHA-256 and
    /// HMAC-SHA256, the way a conforming client derives the key.
    /// </summary>
    private static byte[] PbmacRevocationRequest(byte[] secret, string reference, Org.BouncyCastle.Math.BigInteger serial, string issuerDn)
    {
        var random = new SecureRandom();
        byte[] Bytes(int n) { var b = new byte[n]; random.NextBytes(b); return b; }

        var salt = Bytes(16);
        const int iterations = 1000;
        var header = new PkiHeaderBuilder(PkiHeader.CMP_2000,
                new GeneralName(new X509Name("CN=device")), new GeneralName(new X509Name(issuerDn)))
            .SetMessageTime(new DerGeneralizedTime(DateTime.UtcNow))
            .SetTransactionID(new DerOctetString(Bytes(16)))
            .SetSenderNonce(new DerOctetString(Bytes(16)))
            .SetSenderKID(new DerOctetString(System.Text.Encoding.UTF8.GetBytes(reference)))
            .SetProtectionAlg(new AlgorithmIdentifier(new DerObjectIdentifier(PbmOid),
                new PbmParameter(salt, Sha256, iterations, HmacSha256)))
            .Build();
        var template = new Org.BouncyCastle.Asn1.Crmf.CertTemplateBuilder()
            .SetSerialNumber(new DerInteger(serial))
            .SetIssuer(new X509Name(issuerDn))
            .Build();
        var body = new PkiBody(PkiBody.TYPE_REVOCATION_REQ, new RevReqContent(new RevDetails(template)));

        var key = CmpService.DerivePbmKey(secret, salt, Sha256, iterations);
        var mac = MacUtilities.GetMac(HmacSha256.Algorithm);
        mac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
        var protectedPart = new DerSequence(header, body).GetDerEncoded();
        mac.BlockUpdate(protectedPart, 0, protectedPart.Length);
        var tag = new byte[mac.GetMacSize()];
        mac.DoFinal(tag, 0);
        return new PkiMessage(header, body, new DerBitString(tag)).GetDerEncoded();
    }

    /// <summary>The PBMAC refusal names exactly the algorithms the check accepts.</summary>
    [Fact]
    public void The_pbmac_refusal_lists_the_accepted_algorithms()
    {
        Assert.EndsWith("use SHA-224, SHA-256, SHA-384 or SHA-512.", CmpService.PbmParametersProblem(Sha1, HmacSha256, 1000));
        Assert.EndsWith("use HMAC with SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512.", CmpService.PbmParametersProblem(Sha256, HmacMd5, 1000));
        Assert.Null(CmpService.PbmParametersProblem(new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224), HmacSha256, 1000));
        Assert.Null(CmpService.PbmParametersProblem(Sha256, new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha224, DerNull.Instance), 1000));
        Assert.Null(CmpService.PbmParametersProblem(Sha256, new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha1, DerNull.Instance), 1000));
    }

    [Fact]
    public void The_pbmac_parameter_check_bounds_algorithms_and_iterations()
    {
        Assert.Null(CmpService.PbmParametersProblem(Sha256, HmacSha1, 500));
        Assert.Null(CmpService.PbmParametersProblem(Sha256, HmacSha256, CmpService.MaxPbmIterations));
        Assert.NotNull(CmpService.PbmParametersProblem(Sha256, HmacSha256, CmpService.MaxPbmIterations + 1));
        Assert.NotNull(CmpService.PbmParametersProblem(Sha256, HmacSha256, 0));
        Assert.NotNull(CmpService.PbmParametersProblem(Sha1, HmacSha1, 1000));
        Assert.NotNull(CmpService.PbmParametersProblem(Sha256, HmacMd5, 1000));
        Assert.NotNull(CmpService.PbmParametersProblem(DerNull.Instance));
    }
}
