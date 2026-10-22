namespace ModularCA.Ssh;

/// <summary>The OpenSSH certificate type field.</summary>
public enum SshCertificateType : uint
{
    /// <summary><c>SSH2_CERT_TYPE_USER</c>: authenticates a user to a server.</summary>
    User = 1,

    /// <summary><c>SSH2_CERT_TYPE_HOST</c>: authenticates a server to a client.</summary>
    Host = 2,
}

/// <summary>
/// A critical option or extension. An empty <see cref="Value"/> is a flag and is encoded with
/// empty data; any other value is encoded as a string inside the data string.
/// </summary>
/// <param name="Name">The option name, for example <c>force-command</c> or <c>permit-pty</c>.</param>
/// <param name="Value">The value, or empty for a flag.</param>
public sealed record SshOption(string Name, string Value = "");

/// <summary>
/// Everything in an OpenSSH certificate that the caller chooses. The nonce, the signature key and
/// the signature are supplied when the certificate is encoded and signed.
/// </summary>
public sealed record SshCertificateFields
{
    /// <summary>The <c>valid_before</c> value that means the certificate never expires.</summary>
    public const ulong Forever = ulong.MaxValue;

    /// <summary>The key being certified.</summary>
    public required SshPublicKey SubjectKey { get; init; }

    /// <summary>User or host.</summary>
    public required SshCertificateType Type { get; init; }

    /// <summary>The serial number. Zero is legal on the wire but never issued.</summary>
    public required ulong Serial { get; init; }

    /// <summary>The key id, free text that sshd logs.</summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// The principals, in order. An empty list is legal on the wire, and means any user or any
    /// host; <see cref="SshCertificateRules"/> refuses it.
    /// </summary>
    public required IReadOnlyList<string> Principals { get; init; }

    /// <summary>Start of validity, in Unix seconds.</summary>
    public required ulong ValidAfter { get; init; }

    /// <summary>End of validity, in Unix seconds, or <see cref="Forever"/>.</summary>
    public required ulong ValidBefore { get; init; }

    /// <summary>Critical options, in any order; the encoder sorts them by name.</summary>
    public IReadOnlyList<SshOption> CriticalOptions { get; init; } = [];

    /// <summary>
    /// Extensions, in any order; the encoder sorts them by name. The certificate carries exactly
    /// these, with no defaults added.
    /// </summary>
    public IReadOnlyList<SshOption> Extensions { get; init; } = [];
}
