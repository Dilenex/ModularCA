using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Ocsp;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Xunit;

namespace ModularCA.Tests.Core.Services.Ocsp;

/// <summary>
/// End-to-end cover for the OCSP responder: a real CA key, a real DER OCSPRequest, and the
/// signed DER response parsed back.
/// <para>
/// This component had no tests at all, which is how it came to report every CA certificate as
/// revoked. The status lookup carried a <c>.Where(c =&gt; !c.IsCA)</c> on the premise that "OCSP
/// is for subscriber certs" — but RFC 6960 covers everything an issuer has issued, and
/// intermediates are exactly what relying parties check when they follow the AIA on a leaf. The
/// filter meant the query found no row, fell into the "never issued" branch, and since the signer
/// matched, answered <c>revoked(certificateHold)</c> under the extended-revoke extension. Any
/// client checking an intermediate rejected the whole chain.
/// </para>
/// <para>
/// A wrong "good" is the worst answer an OCSP responder can give and a wrong "revoked" is the
/// most disruptive, so these assert the exact status rather than merely that a response came
/// back.
/// </para>
/// </summary>
public class OcspResponderTests
{
    private static readonly BigInteger LeafSerial = new("112233445566", 16);
    private static readonly BigInteger IntermediateSerial = new("AABBCCDDEE", 16);
    private static readonly BigInteger NeverIssuedSerial = new("DEADBEEF", 16);

    /// <summary>
    /// Seeds the rows the responder needs: a CertificateAuthorities row whose Certificate's
    /// SubjectDN matches the signer, plus one Certificates row per certificate under test.
    /// </summary>
    private static (ModularCA.Database.ModularCADbContext Db, OcspResponderService Service) Build(
        TestCaMaterial ca,
        Action<ModularCA.Database.ModularCADbContext, Guid> seedCertificates,
        SecurityPolicyEntity? policy = null)
    {
        var db = InMemoryDbContextFactory.Create();

        var caCertId = Guid.NewGuid();
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = caCertId,
            SerialNumber = CertificateUtil.FormatSerialNumber(ca.Certificate.SerialNumber),
            SubjectDN = ca.SubjectDn,
            Issuer = ca.SubjectDn,
            IsCA = true,
            Pem = CertificateUtil.ConvertDerToPem(ca.Certificate.GetEncoded(), "CERTIFICATE"),
            RawCertificate = ca.Certificate.GetEncoded(),
            NotBefore = ca.Certificate.NotBefore,
            NotAfter = ca.Certificate.NotAfter,
        });

        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(),
            Name = "test-ca",
            Label = "test-ca",
            IsEnabled = true,
            CertificateId = caCertId,
        });

        seedCertificates(db, caCertId);
        db.SaveChanges();

        var service = new OcspResponderService(
            db,
            new TestKeystore(ca.AsSigner()),
            NullLogger<OcspResponderService>.Instance,
            new StubSecurityPolicyService(policy ?? DefaultPolicy()));

        return (db, service);
    }

    /// <summary>
    /// SecurityPolicyEntity.AllowCaDirectSigning defaults to FALSE, so without a delegated
    /// responder the resolver correctly answers "unauthorized" rather than reaching for the CA's
    /// own key. These tests exercise status determination, not responder provisioning, so they
    /// opt into CA-direct signing explicitly — which is also a useful reminder that a deployment
    /// with neither a delegated responder nor this flag answers nothing at all.
    /// </summary>
    private static SecurityPolicyEntity DefaultPolicy() => new() { AllowCaDirectSigning = true };

    /// <summary>Adds a Certificates row for a certificate this CA issued.</summary>
    private static CertificateEntity Row(TestCaMaterial ca, Guid caCertId, BigInteger serial,
        string subject, bool isCa, bool revoked = false, DateTime? revokedAt = null)
        => new()
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = CertificateUtil.FormatSerialNumber(serial),
            SubjectDN = subject,
            Issuer = ca.SubjectDn,
            IssuerCertificateId = caCertId,
            IsCA = isCa,
            Revoked = revoked,
            RevocationDate = revokedAt,
            NotBefore = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        };

    /// <summary>Runs a request through the responder and returns the single certificate status.</summary>
    private static async Task<object?> StatusForAsync(OcspResponderService service, TestCaMaterial ca, BigInteger serial)
    {
        var der = ca.BuildOcspRequest(serial);
        var result = new OcspProcessingResult();

        var responseDer = await service.ProcessOcspRequestAsync(der, "test-ca", result);

        var resp = new OcspResp(responseDer);
        Assert.Equal(OcspRespStatus.Successful, resp.Status);

        var basic = (BasicOcspResp)resp.GetResponseObject();
        var single = Assert.Single(basic.Responses);
        return single.GetCertStatus();   // null == good
    }

    // ── The regression ───────────────────────────────────────────────────────

    /// <summary>
    /// An unrevoked intermediate must answer <c>good</c>. Before the fix this returned
    /// <c>revoked</c>, so any client following AIA up the chain rejected it.
    /// </summary>
    [Fact]
    public async Task Unrevoked_intermediate_CA_is_reported_good()
    {
        var ca = TestCaMaterial.CreateCa();
        var (db, service) = Build(ca, (d, caId) =>
            d.Certificates.Add(Row(ca, caId, IntermediateSerial, "CN=Test Intermediate", isCa: true)));

        using (db)
        {
            var status = await StatusForAsync(service, ca, IntermediateSerial);
            Assert.Null(status);   // good
        }
    }

    /// <summary>A revoked intermediate must still answer revoked — the fix must not over-correct.</summary>
    [Fact]
    public async Task Revoked_intermediate_CA_is_reported_revoked()
    {
        var ca = TestCaMaterial.CreateCa();
        var revokedAt = new DateTime(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        var (db, service) = Build(ca, (d, caId) =>
            d.Certificates.Add(Row(ca, caId, IntermediateSerial, "CN=Test Intermediate",
                isCa: true, revoked: true, revokedAt: revokedAt)));

        using (db)
        {
            var status = await StatusForAsync(service, ca, IntermediateSerial);
            var revoked = Assert.IsType<RevokedStatus>(status);
            Assert.Equal(revokedAt, revoked.RevocationTime.ToUniversalTime());
        }
    }

    // ── Baseline behaviour that must not regress ─────────────────────────────

    [Fact]
    public async Task Unrevoked_leaf_is_reported_good()
    {
        var ca = TestCaMaterial.CreateCa();
        var (db, service) = Build(ca, (d, caId) =>
            d.Certificates.Add(Row(ca, caId, LeafSerial, "CN=leaf.example.test", isCa: false)));

        using (db)
        {
            Assert.Null(await StatusForAsync(service, ca, LeafSerial));
        }
    }

    [Fact]
    public async Task Revoked_leaf_is_reported_revoked()
    {
        var ca = TestCaMaterial.CreateCa();
        var revokedAt = new DateTime(2026, 3, 2, 9, 30, 0, DateTimeKind.Utc);
        var (db, service) = Build(ca, (d, caId) =>
            d.Certificates.Add(Row(ca, caId, LeafSerial, "CN=leaf.example.test",
                isCa: false, revoked: true, revokedAt: revokedAt)));

        using (db)
        {
            var revoked = Assert.IsType<RevokedStatus>(await StatusForAsync(service, ca, LeafSerial));
            Assert.Equal(revokedAt, revoked.RevocationTime.ToUniversalTime());
        }
    }

    /// <summary>
    /// A serial this CA never issued gets RFC 6960 4.4.8 extended revoke, not "good" — the
    /// responder is authoritative for its own issuer namespace, so silence would be a wrong
    /// "unknown" that a client might treat as acceptable.
    /// </summary>
    [Fact]
    public async Task Never_issued_serial_gets_extended_revoke_not_good()
    {
        var ca = TestCaMaterial.CreateCa();
        var (db, service) = Build(ca, (_, _) => { });

        using (db)
        {
            var status = await StatusForAsync(service, ca, NeverIssuedSerial);
            var revoked = Assert.IsType<RevokedStatus>(status);
            Assert.Equal(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                revoked.RevocationTime.ToUniversalTime());
        }
    }

    /// <summary>
    /// The data-integrity guard: a row marked revoked with no RevocationDate must fail the whole
    /// response rather than have a date synthesized, which would let backdated signatures look
    /// valid after revocation.
    /// </summary>
    [Fact]
    public async Task Revoked_row_with_no_revocation_date_yields_internal_error()
    {
        var ca = TestCaMaterial.CreateCa();
        var (db, service) = Build(ca, (d, caId) =>
            d.Certificates.Add(Row(ca, caId, LeafSerial, "CN=leaf.example.test",
                isCa: false, revoked: true, revokedAt: null)));

        using (db)
        {
            var result = new OcspProcessingResult();
            var responseDer = await service.ProcessOcspRequestAsync(
                ca.BuildOcspRequest(LeafSerial), "test-ca", result);

            Assert.Equal(OcspRespStatus.InternalError, new OcspResp(responseDer).Status);
        }
    }

    /// <summary>A disabled CA refuses to answer at all rather than guessing.</summary>
    [Fact]
    public async Task Disabled_CA_does_not_answer()
    {
        var ca = TestCaMaterial.CreateCa();
        var db = InMemoryDbContextFactory.Create();

        var caCertId = Guid.NewGuid();
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = caCertId,
            SerialNumber = CertificateUtil.FormatSerialNumber(ca.Certificate.SerialNumber),
            SubjectDN = ca.SubjectDn,
            Issuer = ca.SubjectDn,
            IsCA = true,
            Pem = CertificateUtil.ConvertDerToPem(ca.Certificate.GetEncoded(), "CERTIFICATE"),
            RawCertificate = ca.Certificate.GetEncoded(),
            NotBefore = ca.Certificate.NotBefore,
            NotAfter = ca.Certificate.NotAfter,
        });
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(),
            Name = "test-ca",
            Label = "test-ca",
            IsEnabled = false,          // the point of the test
            CertificateId = caCertId,
        });
        db.SaveChanges();

        var service = new OcspResponderService(
            db, new TestKeystore(ca.AsSigner()),
            NullLogger<OcspResponderService>.Instance,
            new StubSecurityPolicyService(DefaultPolicy()));

        using (db)
        {
            var result = new OcspProcessingResult();
            var responseDer = await service.ProcessOcspRequestAsync(
                ca.BuildOcspRequest(LeafSerial), "test-ca", result);

            Assert.NotEqual(OcspRespStatus.Successful, new OcspResp(responseDer).Status);
        }
    }

    // ── Nonce echo ───────────────────────────────────────────────────────────

    /// <summary>
    /// The response nonce must equal the request nonce BYTE FOR BYTE.
    /// <para>
    /// RFC 6960 §4.4.1 binds a response to its request with the nonce, and clients compare the
    /// extension values directly — OpenSSL's <c>OCSP_check_nonce</c> does exactly that. The
    /// responder used to rebuild the extension from the UNWRAPPED nonce, emitting one DER layer
    /// too few: a request nonce of <c>0410CF03…</c> came back as <c>CF03…</c>. Every client that
    /// sends a nonce and verifies the response — the default for <c>openssl ocsp</c> — got
    /// "Nonce Verify error" and treated a perfectly good response as untrustworthy.
    /// </para>
    /// <para>
    /// It survived earlier testing because <c>-noverify</c> skips the nonce check, and the harness
    /// sent no nonce at all. Asserting on the raw extension value is the point: comparing the
    /// unwrapped bytes would have passed against the broken code.
    /// </para>
    /// </summary>
    [Fact]
    public async Task Response_echoes_the_request_nonce_byte_for_byte()
    {
        var ca = TestCaMaterial.CreateCa();
        var (db, service) = Build(ca, (d, caId) =>
            d.Certificates.Add(Row(ca, caId, LeafSerial, "CN=leaf.example.test", isCa: false)));
        using (db)
        {
            var nonce = Enumerable.Range(0, 16).Select(i => (byte)(0xC0 + i)).ToArray();
            var der = ca.BuildOcspRequestWithNonce(LeafSerial, nonce, out var requestExtValue);

            var responseDer = await service.ProcessOcspRequestAsync(der, "test-ca", new OcspProcessingResult());
            var basic = (BasicOcspResp)new OcspResp(responseDer).GetResponseObject();

            var responseExtValue = basic.ResponseExtensions?.GetExtension(
                Org.BouncyCastle.Asn1.Ocsp.OcspObjectIdentifiers.PkixOcspNonce)?.Value;

            Assert.NotNull(responseExtValue);
            Assert.Equal(requestExtValue.GetOctets(), responseExtValue!.GetOctets());
        }
    }

    /// <summary>A request without a nonce must not gain one in the response.</summary>
    [Fact]
    public async Task Response_carries_no_nonce_when_the_request_had_none()
    {
        var ca = TestCaMaterial.CreateCa();
        var (db, service) = Build(ca, (d, caId) =>
            d.Certificates.Add(Row(ca, caId, LeafSerial, "CN=leaf.example.test", isCa: false)));
        using (db)
        {
            var responseDer = await service.ProcessOcspRequestAsync(
                ca.BuildOcspRequest(LeafSerial), "test-ca", new OcspProcessingResult());
            var basic = (BasicOcspResp)new OcspResp(responseDer).GetResponseObject();

            Assert.Null(basic.ResponseExtensions?.GetExtension(
                Org.BouncyCastle.Asn1.Ocsp.OcspObjectIdentifiers.PkixOcspNonce));
        }
    }

}
