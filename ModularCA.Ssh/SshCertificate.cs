namespace ModularCA.Ssh;

/// <summary>
/// A parsed OpenSSH v01 certificate. Parsing checks structure only: that every field is present
/// and well formed, that option names are sorted and unique, and that nothing trails the
/// signature. It does not check the signature or any policy; see <see cref="VerifySignature"/>
/// and <see cref="SshCertificateRules"/>.
/// </summary>
public sealed class SshCertificate
{
    private SshCertificate() { }

    /// <summary>The certificate type name, for example <c>ssh-ed25519-cert-v01@openssh.com</c>.</summary>
    public required string CertificateType { get; init; }

    /// <summary>The nonce.</summary>
    public required byte[] Nonce { get; init; }

    /// <summary>The certified key, with the fields shown in <see cref="SshCertificateFields"/>.</summary>
    public required SshCertificateFields Fields { get; init; }

    /// <summary>The reserved field, empty in every certificate OpenSSH issues.</summary>
    public required byte[] Reserved { get; init; }

    /// <summary>The CA public key that signed the certificate.</summary>
    public required SshPublicKey SignatureKey { get; init; }

    /// <summary>The signature blob, <c>string algorithm, string signature</c>.</summary>
    public required byte[] SignatureBlob { get; init; }

    /// <summary>The signature algorithm named in <see cref="SignatureBlob"/>.</summary>
    public required string SignatureAlgorithm { get; init; }

    /// <summary>The bytes the signature covers: everything before the signature field.</summary>
    public required byte[] ToBeSigned { get; init; }

    /// <summary>The whole certificate blob.</summary>
    public required byte[] Blob { get; init; }

    /// <summary>The comment from the OpenSSH text form, when parsed from one.</summary>
    public string? Comment { get; init; }

    /// <summary>
    /// Parses a certificate in OpenSSH text form, <c>type base64 [comment]</c>, as
    /// <c>ssh-keygen</c> writes it to <c>*-cert.pub</c>.
    /// </summary>
    /// <exception cref="FormatException">The text is not a single well-formed certificate.</exception>
    public static SshCertificate ParseOpenSsh(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var trimmed = text.Trim();
        if (trimmed.Contains('\n') || trimmed.Contains('\r'))
            throw new FormatException("Give exactly one certificate, on one line.");
        var parts = trimmed.Split([' ', '\t'], 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            throw new FormatException("The certificate has no data.");

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException)
        {
            throw new FormatException("The certificate data is not valid base64.");
        }

        var parsed = Parse(blob, parts.Length > 2 ? parts[2].Trim() : null);
        if (parsed.CertificateType != parts[0])
            throw new FormatException($"The data is a {parsed.CertificateType}, but the line names {parts[0]}.");
        return parsed;
    }

    /// <summary>Parses a certificate blob.</summary>
    /// <exception cref="FormatException">The blob is malformed or of an unsupported type.</exception>
    public static SshCertificate Parse(byte[] blob) => Parse(blob, null);

    private static SshCertificate Parse(byte[] blob, string? comment)
    {
        ArgumentNullException.ThrowIfNull(blob);
        var reader = new SshReader(blob);
        var certificateType = reader.Utf8String();
        var keyType = SshKeyTypes.KeyTypeOfCertificate(certificateType)
            ?? throw new FormatException($"Unsupported certificate type '{certificateType}'.");
        var nonce = reader.String();

        var keyStart = reader.Position;
        SshPublicKey.ReadKeyFields(reader, keyType);
        var subjectKey = SshPublicKey.FromBlob(new SshWriter().String(keyType).Raw(reader.Slice(keyStart)).ToArray());

        var serial = reader.UInt64();
        var type = reader.UInt32();
        if (type is not ((uint)SshCertificateType.User or (uint)SshCertificateType.Host))
            throw new FormatException($"Unknown certificate type {type}.");
        var keyId = reader.Utf8String();
        var principals = ReadPrincipals(reader.String());
        var validAfter = reader.UInt64();
        var validBefore = reader.UInt64();
        var critical = ReadOptions(reader.String(), "critical options");
        var extensions = ReadOptions(reader.String(), "extensions");
        var reserved = reader.String();

        SshPublicKey signatureKey;
        try
        {
            signatureKey = SshPublicKey.FromBlob(reader.String());
        }
        catch (FormatException e)
        {
            throw new FormatException("The signature key is not a valid public key.", e);
        }

        var toBeSigned = reader.Slice(0);
        var signatureBlob = reader.String();
        reader.EnsureEnd("certificate");
        var signature = SshSignature.Decode(signatureBlob);

        return new SshCertificate
        {
            CertificateType = certificateType,
            Nonce = nonce,
            Fields = new SshCertificateFields
            {
                SubjectKey = subjectKey,
                Type = (SshCertificateType)type,
                Serial = serial,
                KeyId = keyId,
                Principals = principals,
                ValidAfter = validAfter,
                ValidBefore = validBefore,
                CriticalOptions = critical,
                Extensions = extensions,
            },
            Reserved = reserved,
            SignatureKey = signatureKey,
            SignatureBlob = signatureBlob,
            SignatureAlgorithm = signature.Algorithm,
            ToBeSigned = toBeSigned,
            Blob = (byte[])blob.Clone(),
            Comment = string.IsNullOrEmpty(comment) ? null : comment,
        };
    }

    /// <summary>True when the signature verifies over <see cref="ToBeSigned"/> with <see cref="SignatureKey"/>.</summary>
    public bool VerifySignature() => SshSignature.Verify(SignatureKey, ToBeSigned, SignatureBlob);

    /// <summary>Renders the certificate in OpenSSH text form, <c>type base64 [comment]</c>.</summary>
    public string ToOpenSsh(string? comment = null) => ToOpenSsh(Blob, comment);

    /// <summary>Renders a certificate blob in OpenSSH text form, <c>type base64 [comment]</c>.</summary>
    public static string ToOpenSsh(byte[] certificate, string? comment = null)
    {
        var type = new SshReader(certificate).Utf8String();
        var line = type + " " + Convert.ToBase64String(certificate);
        return string.IsNullOrEmpty(comment) ? line : line + " " + comment;
    }

    private static List<string> ReadPrincipals(byte[] packed)
    {
        var reader = new SshReader(packed);
        var principals = new List<string>();
        while (!reader.AtEnd)
            principals.Add(reader.Utf8String());
        return principals;
    }

    private static List<SshOption> ReadOptions(byte[] packed, string what)
    {
        var reader = new SshReader(packed);
        var options = new List<SshOption>();
        string? previous = null;
        while (!reader.AtEnd)
        {
            var name = reader.Utf8String();
            if (previous != null && string.CompareOrdinal(previous, name) >= 0)
                throw new FormatException($"The {what} are not sorted by name, or repeat one.");
            previous = name;

            var data = reader.String();
            var value = "";
            if (data.Length > 0)
            {
                var inner = new SshReader(data);
                value = inner.Utf8String();
                inner.EnsureEnd($"value of {name}");
            }
            options.Add(new SshOption(name, value));
        }
        return options;
    }
}
