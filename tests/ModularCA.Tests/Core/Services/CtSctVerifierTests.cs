using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// <see cref="CtSctVerifier"/>: SCTs from a CT log are verified against the log's configured key
/// over RFC 6962 section 3.2's <c>digitally-signed</c> structure, and <see cref="CtSubmissionService"/>
/// keeps only the ones that verify. Before 0.4.4 the key was stored and never read, so any answer
/// from a log URL was recorded as an SCT.
/// </summary>
public sealed class CtSctVerifierTests
{
    private const ulong Timestamp = 1_762_646_400_000UL;

    /// <summary>A stand-in for the DER certificate submitted; the SCT signs its bytes whatever they are.</summary>
    private static readonly byte[] Certificate = RandomNumberGenerator.GetBytes(600);

    /// <summary>A log's <c>add-chain</c> answer for <paramref name="certificate"/>, signed by <paramref name="sign"/>.</summary>
    private static byte[] Answer(byte[] spki, byte signatureAlgorithm, Func<byte[], byte[]> sign, byte[] certificate,
        byte[]? extensions = null, byte version = 0, byte hash = CtSctVerifier.HashSha256, byte[]? logId = null)
    {
        var sct = new CtSctVerifier.Sct(version, logId ?? SHA256.HashData(spki), Timestamp, extensions ?? [], []);
        var signature = sign(CtSctVerifier.X509EntrySignedData(sct, certificate));
        return Json(sct, DigitallySigned(hash, signatureAlgorithm, signature));
    }

    private static byte[] DigitallySigned(byte hash, byte algorithm, byte[] signature)
    {
        var ds = new byte[4 + signature.Length];
        ds[0] = hash;
        ds[1] = algorithm;
        BinaryPrimitives.WriteUInt16BigEndian(ds.AsSpan(2, 2), (ushort)signature.Length);
        signature.CopyTo(ds, 4);
        return ds;
    }

    private static byte[] Json(CtSctVerifier.Sct sct, byte[] digitallySigned) => JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
    {
        ["sct_version"] = sct.Version,
        ["id"] = Convert.ToBase64String(sct.LogId),
        ["timestamp"] = sct.Timestamp,
        ["extensions"] = Convert.ToBase64String(sct.Extensions),
        ["signature"] = Convert.ToBase64String(digitallySigned),
    });

    private static Func<byte[], byte[]> Signer(ECDsa key) =>
        data => key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

    private static Func<byte[], byte[]> Signer(RSA key) =>
        data => key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    private static string Base64Key(AsymmetricAlgorithm key) => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    [Fact]
    public void An_ecdsa_p256_sct_over_the_certificate_verifies()
    {
        using var log = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var answer = Answer(log.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureEcdsa, Signer(log), Certificate);
        Assert.Null(CtSctVerifier.VerifyX509Entry(answer, Certificate, Base64Key(log)));
    }

    [Fact]
    public void An_rsa_sct_over_the_certificate_verifies()
    {
        using var log = RSA.Create(2048);
        var answer = Answer(log.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureRsa, Signer(log), Certificate);
        Assert.Null(CtSctVerifier.VerifyX509Entry(answer, Certificate, Base64Key(log)));
    }

    [Fact]
    public void Extensions_are_part_of_what_is_signed()
    {
        using var log = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var answer = Answer(log.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureEcdsa, Signer(log), Certificate, extensions: [1, 2, 3]);
        Assert.Null(CtSctVerifier.VerifyX509Entry(answer, Certificate, Base64Key(log)));

        // The same signature with the extensions dropped from the answer.
        var tampered = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(answer)!
            .ToDictionary(kv => kv.Key, kv => (object)kv.Value);
        tampered["extensions"] = "";
        Assert.Contains("does not verify", CtSctVerifier.VerifyX509Entry(JsonSerializer.SerializeToUtf8Bytes(tampered), Certificate, Base64Key(log)));
    }

    [Fact]
    public void An_sct_over_another_certificate_does_not_verify()
    {
        using var log = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var answer = Answer(log.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureEcdsa, Signer(log), RandomNumberGenerator.GetBytes(600));
        Assert.Contains("does not verify", CtSctVerifier.VerifyX509Entry(answer, Certificate, Base64Key(log)));
    }

    [Fact]
    public void An_sct_signed_by_another_key_is_refused()
    {
        using var log = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var impostor = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Signed by the impostor under its own log id: the id does not match the configured key.
        var ownId = Answer(impostor.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureEcdsa, Signer(impostor), Certificate);
        Assert.Contains("names another log", CtSctVerifier.VerifyX509Entry(ownId, Certificate, Base64Key(log)));

        // Signed by the impostor under the real log's id: the signature does not verify.
        var stolenId = Answer(log.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureEcdsa, Signer(impostor), Certificate);
        Assert.Contains("does not verify", CtSctVerifier.VerifyX509Entry(stolenId, Certificate, Base64Key(log)));
    }

    [Fact]
    public void Only_v1_sha256_and_the_keys_own_algorithm_are_accepted()
    {
        using var log = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = log.ExportSubjectPublicKeyInfo();

        Assert.Contains("version", CtSctVerifier.VerifyX509Entry(
            Answer(spki, CtSctVerifier.SignatureEcdsa, Signer(log), Certificate, version: 1), Certificate, Base64Key(log)));
        Assert.Contains("SHA-256", CtSctVerifier.VerifyX509Entry(
            Answer(spki, CtSctVerifier.SignatureEcdsa, Signer(log), Certificate, hash: 2), Certificate, Base64Key(log)));
        Assert.Contains("ECDSA", CtSctVerifier.VerifyX509Entry(
            Answer(spki, CtSctVerifier.SignatureRsa, Signer(log), Certificate), Certificate, Base64Key(log)));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("{\"sct_version\":0,\"id\":\"AAAA\",\"timestamp\":1,\"signature\":\"BAMAAA==\"}")]
    [InlineData("{\"sct_version\":0,\"id\":\"%%%\",\"timestamp\":1,\"signature\":\"BAMAAA==\"}")]
    public void A_malformed_answer_is_refused_with_a_reason(string body)
    {
        using var log = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.StartsWith("The CT log's answer", CtSctVerifier.VerifyX509Entry(Encoding.UTF8.GetBytes(body), Certificate, Base64Key(log)));
    }

    /// <summary>The x509_entry structure, byte by byte as RFC 6962 section 3.2 lays it out.</summary>
    [Fact]
    public void The_x509_entry_signed_data_follows_rfc_6962()
    {
        var sct = new CtSctVerifier.Sct(0, new byte[32], 0x0102030405060708UL, [0xAA], []);
        var data = CtSctVerifier.X509EntrySignedData(sct, [0x30, 0x00]);
        Assert.Equal(new byte[]
        {
            0x00,                                           // sct_version v1
            0x00,                                           // signature_type certificate_timestamp
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // timestamp
            0x00, 0x00,                                     // entry_type x509_entry
            0x00, 0x00, 0x02, 0x30, 0x00,                   // ASN.1Cert<1..2^24-1>
            0x00, 0x01, 0xAA,                               // CtExtensions<0..2^16-1>
        }, data);
    }

    /// <summary>The precert_entry structure: the issuer key hash, then the length-prefixed TBSCertificate.</summary>
    [Fact]
    public void The_precert_entry_signed_data_follows_rfc_6962()
    {
        var sct = new CtSctVerifier.Sct(0, new byte[32], 1UL, [], []);
        var issuerKeyHash = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var data = CtSctVerifier.PrecertEntrySignedData(sct, issuerKeyHash, [0x30, 0x01, 0x05]);
        var expected = new List<byte> { 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x01 };
        expected.AddRange(issuerKeyHash);
        expected.AddRange(new byte[] { 0x00, 0x00, 0x03, 0x30, 0x01, 0x05, 0x00, 0x00 });
        Assert.Equal(expected.ToArray(), data);
        Assert.Throws<ArgumentException>(() => CtSctVerifier.PrecertEntrySignedData(sct, new byte[20], [0x30]));
    }

    [Fact]
    public void A_precert_sct_verifies_over_its_own_structure()
    {
        using var log = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = log.ExportSubjectPublicKeyInfo();
        var issuerKeyHash = SHA256.HashData(RandomNumberGenerator.GetBytes(91));
        var tbs = RandomNumberGenerator.GetBytes(400);
        var unsigned = new CtSctVerifier.Sct(0, SHA256.HashData(spki), Timestamp, [], []);
        var signature = Signer(log)(CtSctVerifier.PrecertEntrySignedData(unsigned, issuerKeyHash, tbs));
        var sct = unsigned with { Signature = DigitallySigned(CtSctVerifier.HashSha256, CtSctVerifier.SignatureEcdsa, signature) };

        Assert.Null(CtSctVerifier.Verify(sct, CtSctVerifier.PrecertEntrySignedData(sct, issuerKeyHash, tbs), Base64Key(log)));
        // The same SCT read as over a certificate does not verify.
        Assert.NotNull(CtSctVerifier.Verify(sct, CtSctVerifier.X509EntrySignedData(sct, tbs), Base64Key(log)));
    }

    [Fact]
    public void A_p256_or_rsa_2048_key_is_accepted_in_base64_or_pem()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = RSA.Create(2048);
        Assert.Null(CtSctVerifier.PublicKeyError(Base64Key(ec)));
        Assert.Null(CtSctVerifier.PublicKeyError(Base64Key(rsa)));
        Assert.Null(CtSctVerifier.PublicKeyError(ec.ExportSubjectPublicKeyInfoPem()));
        Assert.Null(CtSctVerifier.PublicKeyError("  " + Base64Key(ec) + "\n"));
    }

    [Fact]
    public void Other_keys_are_refused()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var rsa1024 = RSA.Create(1024);
        Assert.Contains("P-256", CtSctVerifier.PublicKeyError(Base64Key(p384)));
        Assert.Contains("2048", CtSctVerifier.PublicKeyError(Base64Key(rsa1024)));
        Assert.Contains("not base64", CtSctVerifier.PublicKeyError("not a key!"));
        Assert.NotNull(CtSctVerifier.PublicKeyError(Convert.ToBase64String(RandomNumberGenerator.GetBytes(91))));
        Assert.NotNull(CtSctVerifier.PublicKeyError(""));
    }

    /// <summary>
    /// The submission keeps the SCT of a log whose key it verifies against, and discards the SCT of
    /// a log with no key and of a log whose answer another key signed.
    /// </summary>
    [Fact]
    public async Task Submission_keeps_only_scts_that_verify()
    {
        using var good = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var answers = new Dictionary<string, byte[]>
        {
            ["https://good.example/ct/v1/add-chain"] = Answer(good.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureEcdsa, Signer(good), Certificate),
            ["https://nokey.example/ct/v1/add-chain"] = Answer(good.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureEcdsa, Signer(good), Certificate),
            ["https://forged.example/ct/v1/add-chain"] = Answer(other.ExportSubjectPublicKeyInfo(), CtSctVerifier.SignatureEcdsa, Signer(other), Certificate),
        };

        await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase($"ct-{Guid.NewGuid():N}").Options);
        db.CtLogs.AddRange(
            new CtLogEntity { Name = "good", Url = "https://good.example", PublicKeyBase64 = Base64Key(good) },
            new CtLogEntity { Name = "nokey", Url = "https://nokey.example", PublicKeyBase64 = "" },
            new CtLogEntity { Name = "forged", Url = "https://forged.example/", PublicKeyBase64 = Base64Key(good) });
        await db.SaveChangesAsync();

        var service = new CtSubmissionService(db, new FixedAnswers(answers), NullLogger<CtSubmissionService>.Instance);
        var scts = await service.SubmitToCTLogsAsync(Certificate, RandomNumberGenerator.GetBytes(300), null);

        var kept = Assert.Single(scts);
        Assert.Equal(answers["https://good.example/ct/v1/add-chain"], kept);
    }

    /// <summary>An HTTP client factory whose clients answer each URL with a fixed body.</summary>
    private sealed class FixedAnswers(Dictionary<string, byte[]> answers) : IHttpClientFactory
    {
        /// <summary>A client over <see cref="Handler"/>.</summary>
        public HttpClient CreateClient(string name) => new(new Handler(answers));

        private sealed class Handler(Dictionary<string, byte[]> answers) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                Task.FromResult(answers.TryGetValue(request.RequestUri!.ToString(), out var body)
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                    : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
