using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Parses, verifies, and validates ACME JWS (JSON Web Signature) request
/// payloads. Enforces an explicit JWS algorithm allow-list
/// (<c>RS256</c>, <c>ES256</c>, <c>ES384</c>, <c>PS256</c>) per RFC 8555 §6.2,
/// cross-checks <c>alg</c> vs the registered account key type, and implements
/// <c>PS256</c> with RSA-PSS padding.
/// <para>
/// Account public keys arrive on an endpoint that authenticates nobody — the JWK in the
/// protected header is attacker-chosen — so every key is size-validated through
/// <see cref="KeyAlgorithmPolicy"/> <em>before</em> it is handed to the platform crypto
/// provider. That closes both directions of abuse: a 512-bit modulus whose signatures would
/// otherwise be treated as valid, and a 32768-bit modulus whose verification would cost the
/// server orders of magnitude more than the request that carried it (asymmetric CPU
/// amplification). The check lives inside the private
/// <c>VerifySignature(string, JsonElement, byte[], byte[])</c> overload deliberately: that is
/// the single chokepoint every path funnels through — new-account (<c>jwk</c>), authenticated
/// requests (<c>kid</c>, JWK re-hydrated from the database) and key rollover (inner JWS) —
/// so a key stored before this validation existed is re-validated on next use.
/// </para>
/// </summary>
public class AcmeJwsService(IAcmeAccountService accountService, IAcmeNonceService nonceService) : IAcmeJwsService
{
    private readonly IAcmeAccountService _accountService = accountService;
    private readonly IAcmeNonceService _nonceService = nonceService;

    /// <summary>
    /// RFC 8555 §6.2 allow-list. Anything outside this set is
    /// rejected with <c>urn:ietf:params:acme:error:badSignatureAlgorithm</c>.
    /// </summary>
    public static readonly HashSet<string> AllowedAlgorithms = new(StringComparer.Ordinal)
    {
        "RS256", "PS256", "ES256", "ES384"
    };

    public async Task<AcmeJwsPayload> ParseAndVerifyAsync(string rawBody, string requestUrl)
    {
        var jws = JsonSerializer.Deserialize<JsonElement>(rawBody);

        var protectedB64 = jws.GetProperty("protected").GetString()
            ?? throw new InvalidOperationException("Missing protected header.");
        var payloadB64 = jws.GetProperty("payload").GetString()
            ?? throw new InvalidOperationException("Missing payload.");
        var signatureB64 = jws.GetProperty("signature").GetString()
            ?? throw new InvalidOperationException("Missing signature.");

        var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(protectedB64));
        var header = JsonSerializer.Deserialize<JsonElement>(headerJson);

        var alg = header.GetProperty("alg").GetString()
            ?? throw new InvalidOperationException("Missing alg in protected header.");

        // Enforce the RFC 8555 algorithm allow-list before any
        // cryptographic work. Prefix with "badSignatureAlgorithm:" so the filter
        // can map the exception to the correct ACME problem type.
        if (!AllowedAlgorithms.Contains(alg))
            throw new InvalidOperationException($"badSignatureAlgorithm: Algorithm '{alg}' is not permitted. Allowed: {string.Join(", ", AllowedAlgorithms)}.");

        var url = header.TryGetProperty("url", out var urlProp) ? urlProp.GetString() : null;

        if (url != requestUrl)
            throw new InvalidOperationException("JWS url does not match request URL.");

        // Check if this is a new-account request (uses JWK, not kid) — nonce still recommended but some clients omit on first request
        bool hasKid = header.TryGetProperty("kid", out _);
        if (!header.TryGetProperty("nonce", out var nonceProp) || string.IsNullOrEmpty(nonceProp.GetString()))
        {
            if (hasKid) // Not a new-account request — nonce is required
                throw new InvalidOperationException("Nonce is required in ACME JWS protected header.");
        }
        else
        {
            var nonce = nonceProp.GetString()!;
            if (!await _nonceService.ConsumeAsync(nonce))
                throw new InvalidOperationException("Invalid or expired nonce.");
        }

        string? kid = header.TryGetProperty("kid", out var kidProp) ? kidProp.GetString() : null;
        JsonElement? jwk = header.TryGetProperty("jwk", out var jwkProp) ? jwkProp : null;

        if (kid != null && jwk != null)
            throw new InvalidOperationException("JWS must contain either kid or jwk, not both.");
        if (kid == null && jwk == null)
            throw new InvalidOperationException("JWS must contain kid or jwk.");

        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = Base64UrlDecode(signatureB64);

        Guid? accountId = null;
        string? thumbprint = null;

        if (jwk != null)
        {
            VerifySignature(alg, jwk.Value, signingInput, signature);
            thumbprint = ComputeThumbprint(jwk.Value.GetRawText());
        }
        else if (kid != null)
        {
            var kidUri = new Uri(kid);
            var accountIdStr = kidUri.Segments.Last().TrimEnd('/');
            if (!Guid.TryParse(accountIdStr, out var parsedId))
                throw new InvalidOperationException("Invalid kid format.");

            var account = await _accountService.GetByIdAsync(parsedId)
                ?? throw new InvalidOperationException("Account not found.");

            accountId = account.Id;

            var acctJwkJson = await _accountService.GetJwkByIdAsync(parsedId)
                ?? throw new InvalidOperationException("Account JWK not found.");
            var acctJwk = JsonSerializer.Deserialize<JsonElement>(acctJwkJson);
            VerifySignature(alg, acctJwk, signingInput, signature);
            thumbprint = ComputeThumbprint(acctJwkJson);
        }

        return new AcmeJwsPayload
        {
            ProtectedHeader = headerJson,
            Payload = payloadB64.Length == 0 ? "" : Encoding.UTF8.GetString(Base64UrlDecode(payloadB64)),
            Signature = signatureB64,
            Kid = kid,
            Jwk = jwk,
            Nonce = nonceProp.ValueKind != JsonValueKind.Undefined ? nonceProp.GetString() : null,
            Url = url,
            AccountId = accountId,
            JwkThumbprint = thumbprint
        };
    }

    /// <summary>
    /// Computes the RFC 7638 JWK thumbprint: SHA-256 over the required members in lexicographic
    /// order, with no whitespace. The member values are hashed exactly as they arrived on the
    /// wire — deliberately <em>not</em> normalised the way
    /// <see cref="ImportValidatedRsaKey"/> trims the modulus it imports, because RFC 7638 defines
    /// the thumbprint over the JWK's octet representation and re-encoding it would produce a
    /// thumbprint no client could reproduce.
    /// <para>
    /// This routine only reads and hashes strings — it never imports a key — so it is not a
    /// second, unvalidated entry point for a hostile JWK. It is nonetheless reached with
    /// attacker-supplied JSON (the <c>oldKey</c> member of a key-rollover payload is thumbprinted
    /// before anything about it has been verified), so missing members raise
    /// <see cref="InvalidOperationException"/> — which the ACME layer turns into a problem
    /// document — rather than a <see cref="KeyNotFoundException"/> that would escape as a 500.
    /// </para>
    /// </summary>
    /// <param name="jwkJson">The raw JWK JSON object text.</param>
    /// <returns>The base64url-encoded SHA-256 thumbprint.</returns>
    public string ComputeThumbprint(string jwkJson)
    {
        var jwk = JsonSerializer.Deserialize<JsonElement>(jwkJson);
        if (jwk.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("badPublicKey: JWK must be a JSON object.");

        var kty = RequiredMember(jwk, "kty");

        string canonical;
        if (kty == "RSA")
        {
            var e = RequiredMember(jwk, "e");
            var n = RequiredMember(jwk, "n");
            canonical = $"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}";
        }
        else if (kty == "EC")
        {
            var crv = RequiredMember(jwk, "crv");
            var x = RequiredMember(jwk, "x");
            var y = RequiredMember(jwk, "y");
            canonical = $"{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        }
        else
        {
            throw new InvalidOperationException($"badPublicKey: Unsupported key type: {kty}");
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncode(hash);
    }

    /// <summary>
    /// Verifies a JWS signature using the specified JWK.
    /// </summary>
    public void VerifySignature(string protectedB64, string payloadB64, string signatureB64, string jwkJson)
    {
        var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(protectedB64));
        var header = JsonSerializer.Deserialize<JsonElement>(headerJson);
        var alg = header.GetProperty("alg").GetString()
            ?? throw new InvalidOperationException("Missing alg in protected header.");

        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
        var signature = Base64UrlDecode(signatureB64);
        var jwk = JsonSerializer.Deserialize<JsonElement>(jwkJson);

        VerifySignature(alg, jwk, signingInput, signature);
    }

    /// <summary>
    /// Verifies a JWS signature after enforcing the RFC 8555
    /// algorithm allow-list and cross-checking that <paramref name="alg"/> is
    /// consistent with the JWK <c>kty</c> and (for EC keys) the named curve.
    /// <list type="bullet">
    /// <item><description><c>RS256</c>/<c>PS256</c> require <c>kty == "RSA"</c>.</description></item>
    /// <item><description><c>ES256</c> requires <c>kty == "EC"</c> and <c>crv == "P-256"</c>.</description></item>
    /// <item><description><c>ES384</c> requires <c>kty == "EC"</c> and <c>crv == "P-384"</c>.</description></item>
    /// <item><description><c>PS256</c> is verified with <see cref="RSASignaturePadding.Pss"/>.</description></item>
    /// </list>
    /// The supplied public key is also bounded before any cryptographic work: RSA moduli and
    /// exponents go through <see cref="ImportValidatedRsaKey"/>, and EC coordinates are checked
    /// against the field size of the curve the <c>alg</c> pins. This is the one chokepoint every
    /// caller reaches — the <c>jwk</c> branch, the <c>kid</c> branch that re-hydrates a stored
    /// account JWK, and the key-rollover inner JWS — so no key path escapes the policy, in
    /// either direction, including keys persisted before the policy existed.
    /// </summary>
    /// <param name="alg">The JWS <c>alg</c> from the protected header; already allow-listed.</param>
    /// <param name="jwk">The public key to verify against.</param>
    /// <param name="signingInput">ASCII <c>protected.payload</c> bytes covered by the signature.</param>
    /// <param name="signature">The decoded JWS signature octets.</param>
    /// <exception cref="InvalidOperationException">
    /// On verification failure, or — prefixed <c>badSignatureAlgorithm:</c> or
    /// <c>badPublicKey:</c> — when the algorithm or the key itself is rejected. The ACME JWS
    /// filter maps those prefixes onto the matching RFC 8555 problem types.
    /// </exception>
    private static void VerifySignature(string alg, JsonElement jwk, byte[] signingInput, byte[] signature)
    {
        if (!AllowedAlgorithms.Contains(alg))
            throw new InvalidOperationException($"badSignatureAlgorithm: Algorithm '{alg}' is not permitted.");

        if (jwk.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("badPublicKey: JWK must be a JSON object.");

        var kty = jwk.TryGetProperty("kty", out var ktyProp) ? ktyProp.GetString() : null;

        // Cross-check: alg must match the account key type. An RSA key cannot
        // be verified with ES256, and an EC key cannot be verified with RS256.
        if (alg is "RS256" or "PS256")
        {
            if (kty != "RSA")
                throw new InvalidOperationException($"badSignatureAlgorithm: alg '{alg}' requires an RSA key, got '{kty}'.");

            // Size/exponent validation happens inside ImportValidatedRsaKey, before the
            // key reaches the platform provider. `using` so the OpenSSL EVP_PKEY handle
            // behind RSA.Create() is released here instead of at finalization — every ACME
            // request went through this path, so a leak here is a per-request leak.
            using var rsa = ImportValidatedRsaKey(jwk);

            var padding = alg == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            if (!rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, padding))
                throw new InvalidOperationException("RSA signature verification failed.");
            return;
        }

        if (alg is "ES256" or "ES384")
        {
            if (kty != "EC")
                throw new InvalidOperationException($"badSignatureAlgorithm: alg '{alg}' requires an EC key, got '{kty}'.");

            var crv = jwk.TryGetProperty("crv", out var crvProp) ? crvProp.GetString() : null;
            // Enforce ES256⇔P-256, ES384⇔P-384 pairing to
            // block curve/hash confusion.
            var (requiredCurve, hashAlg) = alg switch
            {
                "ES256" => ("P-256", HashAlgorithmName.SHA256),
                "ES384" => ("P-384", HashAlgorithmName.SHA384),
                _ => throw new InvalidOperationException($"badSignatureAlgorithm: Unsupported EC alg: {alg}")
            };
            if (crv != requiredCurve)
                throw new InvalidOperationException($"badSignatureAlgorithm: alg '{alg}' requires curve '{requiredCurve}', got '{crv}'.");

            // The curve is pinned by alg above, so the key size is already bounded — an EC
            // key has no attacker-chosen size dimension the way an RSA modulus does, and no
            // separate size check is warranted here. What is *not* pinned by the pairing is
            // the encoding of the point itself, which is validated below.
            var (curve, fieldOctets) = requiredCurve switch
            {
                "P-256" => (ECCurve.NamedCurves.nistP256, 32),
                "P-384" => (ECCurve.NamedCurves.nistP384, 48),
                _ => throw new InvalidOperationException($"Unsupported curve: {requiredCurve}")
            };

            byte[] x, y;
            try
            {
                x = Base64UrlDecode(RequiredMember(jwk, "x"));
                y = Base64UrlDecode(RequiredMember(jwk, "y"));
            }
            catch (FormatException)
            {
                throw new InvalidOperationException("badPublicKey: EC JWK 'x' or 'y' is not valid base64url.");
            }

            // RFC 7518 §6.2.1.2/6.2.1.3: unlike the RSA modulus, EC coordinates are
            // fixed-width — zero-padded to the full field size, never trimmed. Enforcing the
            // exact length rejects truncated or over-long coordinates deterministically
            // instead of leaving the outcome to whatever the platform provider does with a
            // ragged ECPoint.
            if (x.Length != fieldOctets || y.Length != fieldOctets)
                throw new InvalidOperationException(
                    $"badPublicKey: curve '{requiredCurve}' requires {fieldOctets}-octet x and y coordinates, got {x.Length} and {y.Length}.");

            // ECDsa.Create validates that Q actually lies on the curve; a point off the curve
            // surfaces as CryptographicException. Translate it so it becomes an ACME
            // badPublicKey problem document rather than an unhandled 500.
            ECDsa ecdsaKey;
            try
            {
                ecdsaKey = ECDsa.Create(new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = x, Y = y }
                });
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException($"badPublicKey: EC public key is not a valid point on '{requiredCurve}': {ex.Message}");
            }

            // `using` for the same reason as the RSA branch — this method returns straight
            // out of both branches, so without it the provider handle only dies at finalization.
            using var ecdsa = ecdsaKey;

            // JWS EC signatures are RFC 7515 IEEE P1363 concat form. Try that
            // first; fall back to DER for clients that send X.509/DSS form.
            if (!ecdsa.VerifyData(signingInput, signature, hashAlg))
            {
                if (!ecdsa.VerifyData(signingInput, signature, hashAlg, DSASignatureFormat.Rfc3279DerSequence))
                    throw new InvalidOperationException("ECDSA signature verification failed.");
            }
            return;
        }

        throw new InvalidOperationException($"badSignatureAlgorithm: Unsupported algorithm: {alg}");
    }

    /// <summary>
    /// Reads a required JWK string member, rejecting anything that is absent, non-string, empty,
    /// or that contains a character outside the base64url alphabet.
    /// <para>
    /// The charset restriction is what keeps <see cref="ComputeThumbprint"/> honest. That method
    /// builds the RFC 7638 canonical form by string interpolation rather than by a JSON writer,
    /// so a member value containing a quote could inject structure into the canonical text and
    /// let two different JWKs hash to the same thumbprint — and a thumbprint is what identifies
    /// an ACME account. Every member that reaches the canonical form (<c>kty</c>, <c>crv</c>,
    /// <c>n</c>, <c>e</c>, <c>x</c>, <c>y</c>) is legitimately drawn from this alphabet, so
    /// enforcing it costs nothing and removes the ambiguity.
    /// </para>
    /// </summary>
    private static string RequiredMember(JsonElement jwk, string name)
    {
        if (!jwk.TryGetProperty(name, out var prop) || prop.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException($"badPublicKey: JWK is missing required string member '{name}'.");

        var value = prop.GetString()!;
        if (value.Length == 0)
            throw new InvalidOperationException($"badPublicKey: JWK member '{name}' is empty.");

        foreach (var c in value)
        {
            var ok = c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_';
            if (!ok)
                throw new InvalidOperationException($"badPublicKey: JWK member '{name}' contains an illegal character.");
        }

        return value;
    }

    /// <summary>
    /// Upper bound on the width of an accepted RSA public exponent, in bits. The cost of a
    /// public-key operation grows with the bit length of <c>e</c>, so an attacker-supplied
    /// 4096-bit exponent is a CPU-amplification lever every bit as effective as an oversized
    /// modulus — and no real key needs one. 32 bits comfortably covers every exponent in
    /// practical use (F4 / 65537 is 17 bits) while capping the work a single unauthenticated
    /// ACME request can buy.
    /// </summary>
    private const int MaxRsaExponentBits = 32;

    /// <summary>
    /// Decodes, validates, and imports the RSA public key carried in an ACME JWK.
    /// <para>
    /// The modulus size is decided by <see cref="KeyAlgorithmPolicy.IsAllowed(string, int)"/>
    /// so the CA has exactly one answer to "what RSA sizes do we accept" — an ACME account key
    /// is held to the same bar as any other key the CA trusts, rather than to a second,
    /// silently-drifting constant defined here.
    /// </para>
    /// <para>
    /// Leading zero octets are stripped from <c>n</c> and <c>e</c> before anything is measured
    /// or imported. RFC 7518 §2 defines both as the unsigned big-endian integer with no leading
    /// zero padding, so a conforming client never sends them — but a hostile one can, and the
    /// naive <c>n.Length * 8</c> reading of the size then over-reports by 8 bits per padding
    /// octet. Left unhandled, that lets a 1024-bit key wearing 128 zero octets present itself as
    /// a 2048-bit key and clear a minimum-size check. Trimming first means the size test and the
    /// imported key describe the same integer. Note the trim is not applied to the JWK text used
    /// for the RFC 7638 thumbprint, which must hash the member values exactly as they arrived.
    /// </para>
    /// </summary>
    /// <param name="jwk">The JWK object from the JWS protected header, or the account's stored JWK.</param>
    /// <returns>An imported <see cref="RSA"/> instance the caller owns and must dispose.</returns>
    /// <exception cref="InvalidOperationException">
    /// Prefixed <c>badPublicKey:</c> when the key is malformed or outside policy, so the ACME
    /// filter can emit <c>urn:ietf:params:acme:error:badPublicKey</c>.
    /// </exception>
    private static RSA ImportValidatedRsaKey(JsonElement jwk)
    {
        var nRaw = RequiredMember(jwk, "n");
        var eRaw = RequiredMember(jwk, "e");

        byte[] n, e;
        try
        {
            n = TrimLeadingZeros(Base64UrlDecode(nRaw));
            e = TrimLeadingZeros(Base64UrlDecode(eRaw));
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("badPublicKey: RSA JWK 'n' or 'e' is not valid base64url.");
        }

        if (n.Length == 0)
            throw new InvalidOperationException("badPublicKey: RSA modulus is zero.");

        // An RSA modulus is the product of two odd primes and is therefore always odd. An even
        // modulus is not a weak key, it is not a key at all — reject it before the provider
        // has to reason about it.
        if ((n[^1] & 1) == 0)
            throw new InvalidOperationException("badPublicKey: RSA modulus is even and cannot be a valid RSA key.");

        var modulusBits = GetBitLength(n);
        if (!KeyAlgorithmPolicy.IsAllowed("RSA", modulusBits))
            throw new InvalidOperationException(
                $"badPublicKey: RSA account key of {modulusBits} bits is not permitted by CA key policy.");

        if (e.Length == 0)
            throw new InvalidOperationException("badPublicKey: RSA public exponent is zero.");

        // e must be odd: it has to be coprime with φ(n), which is even for any real RSA modulus,
        // so an even e can never be a usable exponent.
        if ((e[^1] & 1) == 0)
            throw new InvalidOperationException("badPublicKey: RSA public exponent must be odd.");

        var exponentBits = GetBitLength(e);

        // e == 1 is the degenerate exponent: encryption/verification becomes the identity map,
        // which would make signature "verification" meaningless.
        if (exponentBits < 2)
            throw new InvalidOperationException("badPublicKey: RSA public exponent must be at least 3.");
        if (exponentBits > MaxRsaExponentBits)
            throw new InvalidOperationException(
                $"badPublicKey: RSA public exponent of {exponentBits} bits exceeds the {MaxRsaExponentBits}-bit limit.");

        var rsa = RSA.Create();
        try
        {
            rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
        }
        catch (CryptographicException ex)
        {
            // Dispose before rethrowing — the half-built key would otherwise leak an unmanaged
            // provider handle on exactly the path an attacker controls.
            rsa.Dispose();
            throw new InvalidOperationException($"badPublicKey: RSA public key could not be imported: {ex.Message}");
        }

        return rsa;
    }

    /// <summary>
    /// Returns <paramref name="value"/> with any leading zero octets removed, so the result is
    /// the minimal big-endian encoding of the same unsigned integer. Returns the original array
    /// when there is nothing to trim; returns an empty array when the value is zero.
    /// </summary>
    private static byte[] TrimLeadingZeros(byte[] value)
    {
        var i = 0;
        while (i < value.Length && value[i] == 0) i++;
        return i == 0 ? value : value[i..];
    }

    /// <summary>
    /// Computes the true bit length of a big-endian unsigned integer that has already been
    /// stripped of leading zero octets by <see cref="TrimLeadingZeros"/>. Counts the significant
    /// bits of the top octet rather than assuming eight, so a 2048-bit modulus reports 2048 and a
    /// key that is a few bits short of a nominal size cannot round up into an allowed bucket.
    /// </summary>
    private static int GetBitLength(byte[] magnitude)
    {
        if (magnitude.Length == 0) return 0;
        var bits = (magnitude.Length - 1) * 8;
        for (int top = magnitude[0]; top != 0; top >>= 1) bits++;
        return bits;
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
