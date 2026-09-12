using System.Text;
using System.Text.Json;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace ModularCA.Shared.Licensing;

/// <summary>
/// Parses and verifies a signed licence document offline.
/// </summary>
/// <remarks>
/// <para>
/// The wire form is two base64url segments separated by a dot:
/// <c>base64url(claims-json).base64url(signature)</c>. The signature covers the ASCII bytes of
/// the first segment exactly as they appear, which sidesteps JSON canonicalisation entirely —
/// the classic way signed-JSON schemes get broken is disagreeing about whitespace or key order,
/// and there is nothing to disagree about when the signed input is the literal encoded text.
/// </para>
/// <para>
/// The payload is readable by anyone holding the licence, deliberately. Enforcement here is
/// honour-system: the customer should be able to decode their own licence and see exactly what
/// they bought, and an opaque blob would be hostile for no security benefit, since the binary
/// that checks it is open source anyway.
/// </para>
/// <para>
/// Verification is entirely offline, against a public key compiled into this assembly. A
/// certificate authority frequently runs air-gapped or in a DMZ, and any licensing scheme that
/// needed to reach a vendor endpoint would disqualify the product from exactly the deployments
/// worth selling to.
/// </para>
/// </remarks>
public static class LicenseVerifier
{
    /// <summary>
    /// Ed25519 public key of the ModularCA licence signer, base64.
    /// </summary>
    /// <remarks>
    /// Safe to publish — it is a public key, and the private half never leaves the licence
    /// issuer. Ed25519 rather than RSA or ECDSA because verification is deterministic, the key
    /// is 32 bytes, and there are no curve or padding parameters to get wrong.
    /// <para>
    /// This placeholder is all zeroes and will verify nothing. Replace it with the real signer's
    /// public key before the first commercial release; <c>LicenseKeyIsConfigured</c> reports
    /// whether that has happened so a build cannot quietly ship still trusting nothing.
    /// </para>
    /// </remarks>
    public const string SignerPublicKeyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// <summary>
    /// False while <see cref="SignerPublicKeyBase64"/> is still the all-zero placeholder.
    /// </summary>
    public static bool LicenseKeyIsConfigured =>
        DecodeSignerKey() is { } key && key.Any(b => b != 0);

    private static byte[]? DecodeSignerKey()
    {
        try
        {
            var raw = Convert.FromBase64String(SignerPublicKeyBase64);
            return raw.Length == 32 ? raw : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Verifies a licence document and returns its claims.
    /// </summary>
    /// <remarks>
    /// Never throws. Every failure resolves to a <see cref="LicenseLoadResult"/> the caller can
    /// log and carry on from, because the only correct response to an unreadable licence is to
    /// run as the free edition.
    /// </remarks>
    /// <param name="document">The licence file's contents.</param>
    /// <param name="signerPublicKey">
    /// Override for the pinned key, for tests only. Production callers omit it; there is no
    /// configuration path that reaches this, because a configurable trust anchor would be a
    /// documented bypass rather than a feature.
    /// </param>
    public static LicenseLoadResult Verify(string? document, byte[]? signerPublicKey = null)
    {
        if (string.IsNullOrWhiteSpace(document))
            return LicenseLoadResult.None;

        var parts = document.Trim().Split('.');
        if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0)
        {
            return new LicenseLoadResult(
                LicenseStatus.Malformed, null,
                "Licence is not in the expected <claims>.<signature> form.");
        }

        byte[] claimsBytes, signature;
        try
        {
            claimsBytes = Base64UrlDecode(parts[0]);
            signature = Base64UrlDecode(parts[1]);
        }
        catch (FormatException)
        {
            return new LicenseLoadResult(
                LicenseStatus.Malformed, null, "Licence segments are not valid base64url.");
        }

        var key = signerPublicKey ?? DecodeSignerKey();
        if (key is null || key.Length != 32)
        {
            return new LicenseLoadResult(
                LicenseStatus.SignatureInvalid, null,
                "This build has no usable licence signing key, so no licence can be verified.");
        }

        // Signed input is the encoded first segment verbatim — not the decoded JSON — so
        // re-serialisation can never change what was signed.
        var signedInput = Encoding.ASCII.GetBytes(parts[0]);

        bool verified;
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(key, 0));
            verifier.BlockUpdate(signedInput, 0, signedInput.Length);
            verified = verifier.VerifySignature(signature);
        }
        catch (Exception)
        {
            // A malformed signature makes BouncyCastle throw rather than return false. Either
            // way the answer is the same and neither may escape into the startup path.
            verified = false;
        }

        if (!verified)
        {
            return new LicenseLoadResult(
                LicenseStatus.SignatureInvalid, null,
                "Licence signature did not verify against this build's licence signing key.");
        }

        LicenseClaims? claims;
        try
        {
            claims = JsonSerializer.Deserialize<LicenseClaims>(claimsBytes, SafeJsonOptions.Default);
        }
        catch (JsonException)
        {
            claims = null;
        }

        if (claims is null || string.IsNullOrWhiteSpace(claims.LicenseId))
        {
            return new LicenseLoadResult(
                LicenseStatus.Malformed, null,
                "Licence signature verified but its claims could not be read.");
        }

        return new LicenseLoadResult(
            LicenseStatus.Valid, claims,
            $"Licence {claims.LicenseId} for {claims.Licensee}, maintenance through {claims.MaintenanceThrough:yyyy-MM-dd}.");
    }

    /// <summary>Decodes base64url, tolerating the omitted padding the encoding allows.</summary>
    private static byte[] Base64UrlDecode(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }

    /// <summary>
    /// Encodes claims and a detached signature into the wire form. Used by the licence issuer
    /// and by tests; the running product only ever verifies.
    /// </summary>
    public static string Encode(byte[] claimsJson, byte[] signature)
        => Base64UrlEncode(claimsJson) + "." + Base64UrlEncode(signature);

    /// <summary>Returns the exact bytes a signer must sign for the given claims JSON.</summary>
    public static byte[] SigningInput(byte[] claimsJson)
        => Encoding.ASCII.GetBytes(Base64UrlEncode(claimsJson));

    private static string Base64UrlEncode(byte[] value)
        => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
