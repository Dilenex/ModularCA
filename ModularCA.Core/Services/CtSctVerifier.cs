using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ModularCA.Core.Services;

/// <summary>
/// Verifies the Signed Certificate Timestamps a Certificate Transparency log returns, against the
/// log's configured public key (RFC 6962 section 3.2), and validates that key when an operator
/// configures it.
/// </summary>
/// <remarks>
/// <para>
/// An SCT is the log's signature over a <c>digitally-signed</c> structure: the SCT version, the
/// signature type (<c>certificate_timestamp</c>), the timestamp, the entry type, the signed entry
/// and the SCT extensions. The signed entry is the certificate itself for an <c>x509_entry</c>, or
/// the issuer key hash and the TBSCertificate for a <c>precert_entry</c>. The node submits the
/// issued certificate through <c>add-chain</c>, so what it verifies is an <c>x509_entry</c>; the
/// precertificate encoding is here for an <c>add-pre-chain</c> flow.
/// </para>
/// <para>
/// RFC 6962 section 2.1.4 allows a log key of ECDSA on NIST P-256 or RSA of at least 2048 bits, with
/// SHA-256. The key is configured as the log lists publish it: the base64 of its DER
/// SubjectPublicKeyInfo. A PEM block is accepted too.
/// </para>
/// </remarks>
public static class CtSctVerifier
{
    /// <summary>RFC 6962 <c>Version</c> v1, the only SCT version defined.</summary>
    public const byte SctVersionV1 = 0;

    /// <summary>RFC 6962 <c>SignatureType.certificate_timestamp</c>.</summary>
    public const byte CertificateTimestampSignatureType = 0;

    /// <summary>TLS 1.2 <c>HashAlgorithm.sha256</c> (RFC 5246 section 7.4.1.4.1).</summary>
    public const byte HashSha256 = 4;

    /// <summary>TLS 1.2 <c>SignatureAlgorithm.rsa</c>.</summary>
    public const byte SignatureRsa = 1;

    /// <summary>TLS 1.2 <c>SignatureAlgorithm.ecdsa</c>.</summary>
    public const byte SignatureEcdsa = 3;

    /// <summary>RFC 6962 <c>LogEntryType</c>.</summary>
    public enum LogEntryType : ushort
    {
        /// <summary>The entry is a certificate (<c>add-chain</c>).</summary>
        X509Entry = 0,

        /// <summary>The entry is a precertificate (<c>add-pre-chain</c>).</summary>
        PrecertEntry = 1,
    }

    /// <summary>One SCT as a log's <c>add-chain</c> or <c>add-pre-chain</c> answer carries it (RFC 6962 section 4.1).</summary>
    /// <param name="Version">The SCT version; v1 is 0.</param>
    /// <param name="LogId">The log id: SHA-256 of the log's DER SubjectPublicKeyInfo.</param>
    /// <param name="Timestamp">Milliseconds since the Unix epoch.</param>
    /// <param name="Extensions">The SCT extensions, usually empty.</param>
    /// <param name="Signature">The TLS <c>DigitallySigned</c> structure: hash algorithm, signature algorithm, length-prefixed signature.</param>
    public sealed record Sct(byte Version, byte[] LogId, ulong Timestamp, byte[] Extensions, byte[] Signature);

    /// <summary>
    /// Why <paramref name="publicKey"/> is not a usable CT log key, or null when it is: it must be
    /// the base64 (or PEM) of a DER SubjectPublicKeyInfo for ECDSA P-256 or RSA of 2048 bits or more.
    /// </summary>
    /// <param name="publicKey">The key as an operator configured it.</param>
    public static string? PublicKeyError(string? publicKey)
    {
        if (string.IsNullOrWhiteSpace(publicKey))
            return "The CT log public key is empty.";
        var spki = DecodePublicKey(publicKey);
        if (spki == null)
            return "The CT log public key is not base64: give the log's DER SubjectPublicKeyInfo in base64, as the log lists publish it.";
        var error = LoadKey(spki, out var ec, out var rsa);
        ec?.Dispose();
        rsa?.Dispose();
        return error;
    }

    /// <summary>
    /// Parses a log's JSON answer to <c>add-chain</c> or <c>add-pre-chain</c>
    /// (<c>sct_version</c>, <c>id</c>, <c>timestamp</c>, <c>extensions</c>, <c>signature</c>).
    /// </summary>
    /// <param name="json">The answer's body.</param>
    /// <exception cref="FormatException">The body is not such an answer.</exception>
    public static Sct ParseAddChainResponse(byte[] json)
    {
        AddChainResponse? body;
        try
        {
            body = JsonSerializer.Deserialize<AddChainResponse>(json);
        }
        catch (JsonException ex)
        {
            throw new FormatException("The CT log's answer is not JSON.", ex);
        }
        if (body?.SctVersion is not { } version || body.Id is null || body.Timestamp is not { } timestamp || body.Signature is null)
            throw new FormatException("The CT log's answer lacks sct_version, id, timestamp or signature.");
        var logId = FromBase64(body.Id, "id");
        if (logId.Length != 32)
            throw new FormatException("The CT log's answer has a log id that is not 32 bytes.");
        return new Sct(version, logId, timestamp,
            string.IsNullOrEmpty(body.Extensions) ? [] : FromBase64(body.Extensions, "extensions"),
            FromBase64(body.Signature, "signature"));

        static byte[] FromBase64(string value, string field)
        {
            try
            {
                return Convert.FromBase64String(value);
            }
            catch (FormatException ex)
            {
                throw new FormatException($"The CT log's answer has a {field} that is not base64.", ex);
            }
        }
    }

    /// <summary>
    /// The bytes an SCT over a certificate (<c>x509_entry</c>) signs: RFC 6962 section 3.2's
    /// <c>digitally-signed</c> structure with the DER certificate as the signed entry.
    /// </summary>
    /// <param name="sct">The SCT, for its version, timestamp and extensions.</param>
    /// <param name="certificateDer">The DER certificate submitted to the log.</param>
    public static byte[] X509EntrySignedData(Sct sct, byte[] certificateDer)
    {
        var entry = new byte[3 + certificateDer.Length];
        WriteUInt24(entry, 0, certificateDer.Length);
        certificateDer.CopyTo(entry, 3);
        return SignedData(sct, LogEntryType.X509Entry, entry);
    }

    /// <summary>
    /// The bytes an SCT over a precertificate (<c>precert_entry</c>) signs: the signed entry is the
    /// SHA-256 of the issuer's DER SubjectPublicKeyInfo followed by the length-prefixed DER
    /// TBSCertificate, with the poison extension removed, as RFC 6962 section 3.2 defines it.
    /// </summary>
    /// <param name="sct">The SCT, for its version, timestamp and extensions.</param>
    /// <param name="issuerKeyHash">SHA-256 of the issuing CA's DER SubjectPublicKeyInfo, 32 bytes.</param>
    /// <param name="tbsCertificateDer">The precertificate's DER TBSCertificate without the poison extension.</param>
    public static byte[] PrecertEntrySignedData(Sct sct, byte[] issuerKeyHash, byte[] tbsCertificateDer)
    {
        if (issuerKeyHash.Length != 32)
            throw new ArgumentException("The issuer key hash is a SHA-256 hash, 32 bytes.", nameof(issuerKeyHash));
        var entry = new byte[32 + 3 + tbsCertificateDer.Length];
        issuerKeyHash.CopyTo(entry, 0);
        WriteUInt24(entry, 32, tbsCertificateDer.Length);
        tbsCertificateDer.CopyTo(entry, 35);
        return SignedData(sct, LogEntryType.PrecertEntry, entry);
    }

    /// <summary>
    /// Verifies a log's answer to <c>add-chain</c> for <paramref name="certificateDer"/> against the
    /// log's key. Returns null when the SCT is v1, names this key's log id, is signed with SHA-256
    /// and the key's algorithm, and its signature verifies; otherwise why it was refused.
    /// </summary>
    /// <param name="responseJson">The body of the log's answer.</param>
    /// <param name="certificateDer">The DER certificate that was submitted.</param>
    /// <param name="publicKey">The log's key, base64 (or PEM) DER SubjectPublicKeyInfo.</param>
    public static string? VerifyX509Entry(byte[] responseJson, byte[] certificateDer, string publicKey)
    {
        Sct sct;
        try
        {
            sct = ParseAddChainResponse(responseJson);
        }
        catch (FormatException ex)
        {
            return ex.Message;
        }
        return Verify(sct, X509EntrySignedData(sct, certificateDer), publicKey);
    }

    /// <summary>
    /// Verifies <paramref name="sct"/>'s signature over <paramref name="signedData"/> (from
    /// <see cref="X509EntrySignedData"/> or <see cref="PrecertEntrySignedData"/>) against the log's
    /// key. Returns null when it verifies, otherwise why it was refused.
    /// </summary>
    /// <param name="sct">The SCT.</param>
    /// <param name="signedData">The <c>digitally-signed</c> structure the SCT signs.</param>
    /// <param name="publicKey">The log's key, base64 (or PEM) DER SubjectPublicKeyInfo.</param>
    public static string? Verify(Sct sct, byte[] signedData, string publicKey)
    {
        if (sct.Version != SctVersionV1)
            return $"The SCT has version {sct.Version}; only v1 is defined.";
        var spki = DecodePublicKey(publicKey);
        if (spki == null)
            return "The CT log public key is not base64.";
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(spki), sct.LogId))
            return "The SCT names another log: its log id is not the SHA-256 of the configured public key.";
        if (sct.Signature.Length < 4)
            return "The SCT signature is truncated.";
        var hash = sct.Signature[0];
        var algorithm = sct.Signature[1];
        var length = BinaryPrimitives.ReadUInt16BigEndian(sct.Signature.AsSpan(2, 2));
        if (sct.Signature.Length != 4 + length)
            return "The SCT signature's length does not match its content.";
        if (hash != HashSha256)
            return $"The SCT is signed with hash algorithm {hash}; RFC 6962 requires SHA-256.";
        var signature = sct.Signature.AsSpan(4);

        if (LoadKey(spki, out var ec, out var rsa) is { } keyError)
            return keyError;
        using (ec)
        using (rsa)
        {
            if (ec != null)
            {
                if (algorithm != SignatureEcdsa)
                    return $"The SCT is signed with signature algorithm {algorithm}, but the log's key is ECDSA.";
                return ec.VerifyData(signedData, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
                    ? null : "The SCT signature does not verify against the log's public key.";
            }
            if (algorithm != SignatureRsa)
                return $"The SCT is signed with signature algorithm {algorithm}, but the log's key is RSA.";
            return rsa!.VerifyData(signedData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                ? null : "The SCT signature does not verify against the log's public key.";
        }
    }

    /// <summary>The DER SubjectPublicKeyInfo in <paramref name="publicKey"/> (base64, or a PEM block), or null when it is not base64.</summary>
    internal static byte[]? DecodePublicKey(string publicKey)
    {
        var text = publicKey.Trim();
        if (text.StartsWith("-----BEGIN", StringComparison.Ordinal))
        {
            var lines = text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal));
            text = string.Concat(lines);
        }
        var compact = new StringBuilder(text.Length);
        foreach (var c in text)
            if (!char.IsWhiteSpace(c))
                compact.Append(c);
        try
        {
            var der = Convert.FromBase64String(compact.ToString());
            return der.Length == 0 ? null : der;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Loads <paramref name="spki"/> as an ECDSA P-256 or an RSA (2048 bits or more) key. Returns
    /// null and sets exactly one of <paramref name="ec"/> and <paramref name="rsa"/> on success,
    /// which the caller disposes; otherwise why the key is not usable, with neither set.
    /// </summary>
    private static string? LoadKey(byte[] spki, out ECDsa? ec, out RSA? rsa)
    {
        ec = null;
        rsa = null;
        var candidate = ECDsa.Create();
        try
        {
            candidate.ImportSubjectPublicKeyInfo(spki, out var read);
            if (read != spki.Length)
            {
                candidate.Dispose();
                return "The CT log public key has bytes after its SubjectPublicKeyInfo.";
            }
            if (candidate.KeySize != 256 || !IsP256(candidate.ExportParameters(false).Curve))
            {
                candidate.Dispose();
                return "The CT log public key is ECDSA on a curve other than P-256; RFC 6962 logs use P-256.";
            }
            ec = candidate;
            return null;
        }
        catch (CryptographicException)
        {
            candidate.Dispose();
        }

        var rsaCandidate = RSA.Create();
        try
        {
            rsaCandidate.ImportSubjectPublicKeyInfo(spki, out var read);
            if (read != spki.Length)
            {
                rsaCandidate.Dispose();
                return "The CT log public key has bytes after its SubjectPublicKeyInfo.";
            }
            if (rsaCandidate.KeySize < 2048)
            {
                rsaCandidate.Dispose();
                return $"The CT log public key is RSA of {rsaCandidate.KeySize} bits; RFC 6962 requires at least 2048.";
            }
            rsa = rsaCandidate;
            return null;
        }
        catch (CryptographicException)
        {
            rsaCandidate.Dispose();
            return "The CT log public key is not an ECDSA P-256 or RSA SubjectPublicKeyInfo.";
        }
    }

    /// <summary>
    /// Whether <paramref name="curve"/> is NIST P-256. Windows names it by friendly name
    /// (<c>nistP256</c>, <c>ECDSA_P256</c>), OpenSSL by OID or <c>prime256v1</c>, so both are compared.
    /// </summary>
    private static bool IsP256(ECCurve curve) =>
        curve.IsNamed && curve.Oid is { } oid
        && (oid.Value == "1.2.840.10045.3.1.7"
            || oid.FriendlyName is "nistP256" or "ECDSA_P256" or "secp256r1" or "prime256v1");

    /// <summary>RFC 6962 section 3.2's <c>digitally-signed</c> structure for an SCT over <paramref name="signedEntry"/>.</summary>
    private static byte[] SignedData(Sct sct, LogEntryType entryType, byte[] signedEntry)
    {
        if (sct.Extensions.Length > ushort.MaxValue)
            throw new ArgumentException("The SCT extensions are longer than 65535 bytes.", nameof(sct));
        var data = new byte[1 + 1 + 8 + 2 + signedEntry.Length + 2 + sct.Extensions.Length];
        var at = 0;
        data[at++] = sct.Version;
        data[at++] = CertificateTimestampSignatureType;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(at, 8), sct.Timestamp);
        at += 8;
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(at, 2), (ushort)entryType);
        at += 2;
        signedEntry.CopyTo(data, at);
        at += signedEntry.Length;
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(at, 2), (ushort)sct.Extensions.Length);
        at += 2;
        sct.Extensions.CopyTo(data, at);
        return data;
    }

    /// <summary>Writes <paramref name="value"/> as a TLS <c>uint24</c> length.</summary>
    private static void WriteUInt24(byte[] buffer, int offset, int value)
    {
        if (value is < 1 or > 0xFFFFFF)
            throw new ArgumentException("A signed entry must be between 1 and 16777215 bytes.");
        buffer[offset] = (byte)(value >> 16);
        buffer[offset + 1] = (byte)(value >> 8);
        buffer[offset + 2] = (byte)value;
    }

    /// <summary>The JSON body of an <c>add-chain</c> answer (RFC 6962 section 4.1).</summary>
    private sealed class AddChainResponse
    {
        /// <summary>The SCT version.</summary>
        [JsonPropertyName("sct_version")]
        public byte? SctVersion { get; set; }

        /// <summary>The log id, base64.</summary>
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        /// <summary>Milliseconds since the Unix epoch.</summary>
        [JsonPropertyName("timestamp")]
        public ulong? Timestamp { get; set; }

        /// <summary>The SCT extensions, base64.</summary>
        [JsonPropertyName("extensions")]
        public string? Extensions { get; set; }

        /// <summary>The <c>DigitallySigned</c> structure, base64.</summary>
        [JsonPropertyName("signature")]
        public string? Signature { get; set; }
    }
}
