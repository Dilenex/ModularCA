using ModularCA.Core.Services.Cmp;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using System.Text;
using Xunit;

namespace ModularCA.Tests.Core.Services.Cmp;

/// <summary>
/// Pins RFC 4210 §5.1.3.1 password-based MAC key derivation.
/// <para>
/// The responder verified a request's PBMAC correctly and then protected its response with a key
/// no client could reproduce. Verification derived <c>OWF^n(secret || requestSalt)</c>, as it
/// should. The response builder generated a fresh salt, did not have the secret — it had only
/// been handed the request's derived key — and so computed
/// <c>OWF^1024(requestDerivedKey || responseSalt)</c>, while the client, holding the secret and
/// reading the new salt out of the header, computed <c>OWF^1024(secret || responseSalt)</c>. The
/// two never agree. Every PBMAC-protected CMP response therefore failed verification at every
/// conforming client, which is exactly the bootstrap case PBMAC exists to serve — a client that
/// does not yet have the CA certificate and cannot check a signature.
/// </para>
/// <para>
/// The in-code comment asserted the opposite ("clients that implement PBM verify correctly will
/// accept this"), which is why the defect survived: it reads like a considered decision. These
/// tests assert the derivation against an independent implementation of the RFC's definition, so
/// the claim is checked rather than restated.
/// </para>
/// </summary>
public class CmpPbmacKeyDerivationTests
{
    private static readonly AlgorithmIdentifier Sha1 = new(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
    private static readonly AlgorithmIdentifier Sha256 =
        new(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"), DerNull.Instance);

    /// <summary>
    /// RFC 4210 §5.1.3.1, written out independently of the implementation under test:
    /// the first pass hashes <c>secret || salt</c>, and each further iteration hashes the previous
    /// digest.
    /// </summary>
    private static byte[] RfcDerive(byte[] secret, byte[] salt, AlgorithmIdentifier owf, int iterations)
    {
        var digest = DigestUtilities.GetDigest(owf.Algorithm);
        var input = secret.Concat(salt).ToArray();
        var dk = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(input, 0, input.Length);
        digest.DoFinal(dk, 0);
        for (var i = 1; i < iterations; i++)
        {
            digest.Reset();
            digest.BlockUpdate(dk, 0, dk.Length);
            digest.DoFinal(dk, 0);
        }
        return dk;
    }

    private static byte[] Secret => Encoding.UTF8.GetBytes("s3cret-shared-value");
    private static byte[] SaltA => Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
    private static byte[] SaltB => Enumerable.Range(100, 16).Select(i => (byte)i).ToArray();

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(1024)]
    public void The_derivation_matches_the_rfc_definition(int iterations)
    {
        Assert.Equal(
            RfcDerive(Secret, SaltA, Sha1, iterations),
            CmpService.DerivePbmKey(Secret, SaltA, Sha1, iterations));
    }

    [Fact]
    public void It_honours_the_clients_one_way_function()
    {
        // The response used to hardcode SHA-1 whatever the client selected, so a client that
        // negotiated SHA-256 was handed a MAC keyed on a digest it was not using.
        var sha256Key = CmpService.DerivePbmKey(Secret, SaltA, Sha256, 1024);
        Assert.Equal(32, sha256Key.Length);
        Assert.Equal(RfcDerive(Secret, SaltA, Sha256, 1024), sha256Key);
        Assert.NotEqual(CmpService.DerivePbmKey(Secret, SaltA, Sha1, 1024), sha256Key);
    }

    [Fact]
    public void A_response_salt_yields_the_key_the_client_will_compute()
    {
        // What the fix is for. The client holds only the secret; given the response's salt it
        // computes this. The responder must arrive at the same bytes.
        var clientSide = RfcDerive(Secret, SaltB, Sha1, 1024);
        var responderSide = CmpService.DerivePbmKey(Secret, SaltB, Sha1, 1024);
        Assert.Equal(clientSide, responderSide);
    }

    [Fact]
    public void Chaining_the_requests_derived_key_produces_a_key_the_client_cannot_reproduce()
    {
        // The old response path, reconstructed: derive from the REQUEST's key instead of the
        // secret. It is a well-formed key — which is why nothing crashed — and it is not the key
        // the client computes, which is why nothing verified.
        var requestKey = CmpService.DerivePbmKey(Secret, SaltA, Sha1, 1024);
        var oldResponseKey = CmpService.DerivePbmKey(requestKey, SaltB, Sha1, 1024);
        var whatTheClientComputes = RfcDerive(Secret, SaltB, Sha1, 1024);

        Assert.NotEqual(whatTheClientComputes, oldResponseKey);
        Assert.Equal(whatTheClientComputes, CmpService.DerivePbmKey(Secret, SaltB, Sha1, 1024));
    }

    [Fact]
    public void A_different_salt_gives_a_different_key()
    {
        Assert.NotEqual(
            CmpService.DerivePbmKey(Secret, SaltA, Sha1, 1024),
            CmpService.DerivePbmKey(Secret, SaltB, Sha1, 1024));
    }

    [Fact]
    public void A_different_secret_gives_a_different_key()
    {
        Assert.NotEqual(
            CmpService.DerivePbmKey(Secret, SaltA, Sha1, 1024),
            CmpService.DerivePbmKey(Encoding.UTF8.GetBytes("another-secret"), SaltA, Sha1, 1024));
    }

    [Fact]
    public void The_caller_supplied_secret_is_not_mutated()
    {
        // The derivation zeroes its own scratch buffer; it must not zero the caller's secret,
        // which the request context still needs for the response.
        var secret = Secret;
        var before = (byte[])secret.Clone();
        CmpService.DerivePbmKey(secret, SaltA, Sha1, 1024);
        Assert.Equal(before, secret);
    }
}

/// <summary>
/// Verifies a PBMAC-protected response the way a client does: derive the key from the shared
/// secret and the salt advertised in the response header, then check the MAC over
/// <c>SEQUENCE { header, body }</c>.
/// <para>
/// This is the test the defect could not have survived. The derivation unit tests above pin the
/// key schedule; this one pins that the response builder actually feeds it the secret, which is
/// the thing that was missing — the builder had only the request's derived key to work with and
/// improvised.
/// </para>
/// </summary>
public class CmpPbmacResponseProtectionTests
{
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("device-shared-secret");

    private static PkiMessage BuildResponse(AlgorithmIdentifier owf, AlgorithmIdentifier mac, int iterations)
    {
        var ctx = new CmpService.CmpRequestContext
        {
            ProtectionMode = CmpService.CmpProtectionMode.PbMac,
            PbmSecret = (byte[])Secret.Clone(),
            PbmOwf = owf,
            PbmMac = mac,
            PbmIterationCount = iterations,
            PbmReferenceValue = Encoding.UTF8.GetBytes("device-001"),
        };

        var der = CmpService.BuildPbmProtectedMessage(
            new GeneralName(new Org.BouncyCastle.Asn1.X509.X509Name("CN=Issuing CA")),
            new GeneralName(new Org.BouncyCastle.Asn1.X509.X509Name("CN=printer1")),
            new PkiBody(23, new ErrorMsgContent(new PkiStatusInfo(2))),
            new DerOctetString(new byte[] { 1, 2, 3, 4 }),
            new DerOctetString(Enumerable.Repeat((byte)9, 16).ToArray()),
            Enumerable.Repeat((byte)7, 16).ToArray(),
            ctx);

        return PkiMessage.GetInstance(Asn1Object.FromByteArray(der));
    }

    /// <summary>Recomputes the MAC exactly as a conforming client would.</summary>
    private static byte[] ClientComputedMac(PkiMessage response)
    {
        var pbm = PbmParameter.GetInstance(response.Header.ProtectionAlg.Parameters);
        var digest = DigestUtilities.GetDigest(pbm.Owf.Algorithm);
        var input = Secret.Concat(pbm.Salt.GetOctets()).ToArray();
        var dk = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(input, 0, input.Length);
        digest.DoFinal(dk, 0);
        for (var i = 1; i < pbm.IterationCount.IntValueExact; i++)
        {
            digest.Reset();
            digest.BlockUpdate(dk, 0, dk.Length);
            digest.DoFinal(dk, 0);
        }

        var protectedPart = new DerSequence(response.Header, response.Body).GetDerEncoded();
        var mac = MacUtilities.GetMac(pbm.Mac.Algorithm);
        mac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(dk));
        mac.BlockUpdate(protectedPart, 0, protectedPart.Length);
        var result = new byte[mac.GetMacSize()];
        mac.DoFinal(result, 0);
        return result;
    }

    private static readonly AlgorithmIdentifier HmacSha1 =
        new(new DerObjectIdentifier("1.3.6.1.5.5.8.1.2"), DerNull.Instance);
    private static readonly AlgorithmIdentifier HmacSha256 =
        new(new DerObjectIdentifier("1.2.840.113549.2.9"), DerNull.Instance);
    private static readonly AlgorithmIdentifier Sha1Owf =
        new(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
    private static readonly AlgorithmIdentifier Sha256Owf =
        new(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"), DerNull.Instance);

    [Fact]
    public void A_client_holding_the_shared_secret_can_verify_the_response()
    {
        var response = BuildResponse(Sha1Owf, HmacSha1, 1024);
        Assert.Equal(ClientComputedMac(response), response.Protection.GetBytes());
    }

    [Fact]
    public void The_clients_negotiated_algorithms_are_echoed_rather_than_forced_to_sha1()
    {
        var response = BuildResponse(Sha256Owf, HmacSha256, 512);
        var pbm = PbmParameter.GetInstance(response.Header.ProtectionAlg.Parameters);

        Assert.Equal(Sha256Owf.Algorithm, pbm.Owf.Algorithm);
        Assert.Equal(HmacSha256.Algorithm, pbm.Mac.Algorithm);
        Assert.Equal(512, pbm.IterationCount.IntValueExact);
        Assert.Equal(ClientComputedMac(response), response.Protection.GetBytes());
    }

    [Fact]
    public void The_response_carries_its_own_salt()
    {
        // Response protection stays independent of the request's, which is the reason the key has
        // to be re-derived rather than reused in the first place.
        var first = PbmParameter.GetInstance(BuildResponse(Sha1Owf, HmacSha1, 1024).Header.ProtectionAlg.Parameters);
        var second = PbmParameter.GetInstance(BuildResponse(Sha1Owf, HmacSha1, 1024).Header.ProtectionAlg.Parameters);
        Assert.NotEqual(first.Salt.GetOctets(), second.Salt.GetOctets());
    }

    [Fact]
    public void The_senderKID_identifies_the_credential_that_validates_the_response()
    {
        var response = BuildResponse(Sha1Owf, HmacSha1, 1024);
        Assert.Equal("device-001", Encoding.UTF8.GetString(response.Header.SenderKID.GetOctets()));
    }

    [Fact]
    public void A_response_cannot_be_built_without_the_verified_secret()
    {
        // Fail loudly rather than emit an unprotected or improvised MAC.
        var ctx = new CmpService.CmpRequestContext
        {
            ProtectionMode = CmpService.CmpProtectionMode.PbMac,
            PbmOwf = Sha1Owf,
            PbmMac = HmacSha1,
        };
        Assert.Throws<InvalidOperationException>(() => CmpService.BuildPbmProtectedMessage(
            new GeneralName(new Org.BouncyCastle.Asn1.X509.X509Name("CN=Issuing CA")),
            new GeneralName(new Org.BouncyCastle.Asn1.X509.X509Name("CN=printer1")),
            new PkiBody(23, new ErrorMsgContent(new PkiStatusInfo(2))),
            null, null, new byte[16], ctx));
    }
}
