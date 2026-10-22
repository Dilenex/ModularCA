namespace ModularCA.Ssh;

/// <summary>OpenSSH public key type names, and the certificate type each one has.</summary>
public static class SshKeyTypes
{
    /// <summary>Ed25519.</summary>
    public const string Ed25519 = "ssh-ed25519";

    /// <summary>ECDSA on NIST P-256.</summary>
    public const string EcdsaP256 = "ecdsa-sha2-nistp256";

    /// <summary>ECDSA on NIST P-384.</summary>
    public const string EcdsaP384 = "ecdsa-sha2-nistp384";

    /// <summary>ECDSA on NIST P-521.</summary>
    public const string EcdsaP521 = "ecdsa-sha2-nistp521";

    /// <summary>RSA. The key type stays <c>ssh-rsa</c> whatever hash signs with it.</summary>
    public const string Rsa = "ssh-rsa";

    /// <summary>DSA. Parsed so a caller can name it in a refusal; never certified.</summary>
    public const string Dss = "ssh-dss";

    /// <summary>The suffix every OpenSSH v01 certificate type carries.</summary>
    public const string CertificateSuffix = "-cert-v01@openssh.com";

    /// <summary>The key types a certificate can be issued for, or signed with.</summary>
    public static readonly IReadOnlyList<string> Certifiable = [Ed25519, EcdsaP256, EcdsaP384, EcdsaP521, Rsa];

    /// <summary>
    /// The certificate type for a public key type, for example
    /// <c>ssh-ed25519-cert-v01@openssh.com</c>.
    /// </summary>
    /// <exception cref="ArgumentException">The key type cannot be certified.</exception>
    public static string CertificateType(string keyType)
    {
        if (!Certifiable.Contains(keyType))
            throw new ArgumentException($"SSH key type '{keyType}' cannot be certified.", nameof(keyType));
        return keyType + CertificateSuffix;
    }

    /// <summary>The public key type a certificate type certifies, or null when it is not one this code reads.</summary>
    public static string? KeyTypeOfCertificate(string certificateType)
    {
        if (!certificateType.EndsWith(CertificateSuffix, StringComparison.Ordinal))
            return null;
        var keyType = certificateType[..^CertificateSuffix.Length];
        return Certifiable.Contains(keyType) ? keyType : null;
    }

    /// <summary>The OpenSSH curve identifier for an ECDSA key type, or null for any other type.</summary>
    public static string? CurveName(string keyType) => keyType switch
    {
        EcdsaP256 => "nistp256",
        EcdsaP384 => "nistp384",
        EcdsaP521 => "nistp521",
        _ => null,
    };
}

/// <summary>
/// SSH signature algorithm names, and the signer algorithm name each one is computed with.
/// </summary>
public static class SshSignatureAlgorithms
{
    /// <summary>Ed25519 over the data.</summary>
    public const string Ed25519 = SshKeyTypes.Ed25519;

    /// <summary>ECDSA P-256 with SHA-256.</summary>
    public const string EcdsaP256 = SshKeyTypes.EcdsaP256;

    /// <summary>ECDSA P-384 with SHA-384.</summary>
    public const string EcdsaP384 = SshKeyTypes.EcdsaP384;

    /// <summary>ECDSA P-521 with SHA-512.</summary>
    public const string EcdsaP521 = SshKeyTypes.EcdsaP521;

    /// <summary>RSA PKCS#1 v1.5 with SHA-256.</summary>
    public const string RsaSha256 = "rsa-sha2-256";

    /// <summary>RSA PKCS#1 v1.5 with SHA-512.</summary>
    public const string RsaSha512 = "rsa-sha2-512";

    /// <summary>
    /// The signature algorithm a CA key signs with. An RSA key uses <paramref name="rsaAlgorithm"/>,
    /// which must be one of the two SHA-2 names; SHA-1 <c>ssh-rsa</c> signatures are never made.
    /// </summary>
    public static string ForKeyType(string keyType, string rsaAlgorithm = RsaSha512) => keyType switch
    {
        SshKeyTypes.Ed25519 or SshKeyTypes.EcdsaP256 or SshKeyTypes.EcdsaP384 or SshKeyTypes.EcdsaP521 => keyType,
        SshKeyTypes.Rsa when rsaAlgorithm is RsaSha256 or RsaSha512 => rsaAlgorithm,
        SshKeyTypes.Rsa => throw new ArgumentException($"'{rsaAlgorithm}' is not an RSA SHA-2 signature algorithm.", nameof(rsaAlgorithm)),
        _ => throw new ArgumentException($"SSH key type '{keyType}' cannot sign certificates.", nameof(keyType)),
    };

    /// <summary>True when a key of <paramref name="keyType"/> makes signatures named <paramref name="algorithm"/>.</summary>
    public static bool IsCompatible(string algorithm, string keyType) => algorithm switch
    {
        RsaSha256 or RsaSha512 => keyType == SshKeyTypes.Rsa,
        Ed25519 or EcdsaP256 or EcdsaP384 or EcdsaP521 => keyType == algorithm,
        _ => false,
    };

    /// <summary>
    /// The algorithm name the signer and BouncyCastle use for an SSH signature algorithm, for
    /// example <c>SHA384withECDSA</c> for <c>ecdsa-sha2-nistp384</c>.
    /// </summary>
    public static string SignerAlgorithmName(string algorithm) => algorithm switch
    {
        Ed25519 => "Ed25519",
        EcdsaP256 => "SHA256withECDSA",
        EcdsaP384 => "SHA384withECDSA",
        EcdsaP521 => "SHA512withECDSA",
        RsaSha256 => "SHA256withRSA",
        RsaSha512 => "SHA512withRSA",
        _ => throw new ArgumentException($"Unsupported SSH signature algorithm '{algorithm}'.", nameof(algorithm)),
    };
}
