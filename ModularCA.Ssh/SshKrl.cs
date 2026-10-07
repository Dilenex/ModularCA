namespace ModularCA.Ssh;

/// <summary>
/// Builds OpenSSH key revocation lists (<c>PROTOCOL.krl</c>) that revoke certificates by serial.
/// A KRL is unsigned, as <c>ssh-keygen -k</c> makes it, so it needs only the CA's public key.
/// </summary>
public static class SshKrl
{
    /// <summary><c>KRL_MAGIC</c>, "SSHKRL\n\0".</summary>
    public const ulong Magic = 0x5353484b524c0a00UL;

    /// <summary><c>KRL_FORMAT_VERSION</c>.</summary>
    public const uint FormatVersion = 1;

    private const byte SectionCertificates = 1;
    private const byte CertSectionSerialList = 0x20;

    /// <summary>
    /// Encodes a KRL revoking <paramref name="revokedSerials"/> under <paramref name="caKey"/>.
    /// Serials are sorted and deduplicated and written as one serial list. With no serials the KRL
    /// is the header alone, which revokes nothing, as <c>ssh-keygen -k</c> writes it.
    /// </summary>
    /// <param name="caKey">The CA public key the serials are scoped to.</param>
    /// <param name="revokedSerials">Revoked certificate serials; zero is refused.</param>
    /// <param name="krlVersion">A number that should increase each time the list changes.</param>
    /// <param name="generatedAt">The generation time, written in Unix seconds.</param>
    /// <param name="comment">The KRL comment.</param>
    /// <exception cref="ArgumentException">A serial is zero, or the time is before 1970.</exception>
    public static byte[] Encode(SshPublicKey caKey, IEnumerable<ulong> revokedSerials, ulong krlVersion,
        DateTimeOffset generatedAt, string comment = "")
    {
        ArgumentNullException.ThrowIfNull(caKey);
        ArgumentNullException.ThrowIfNull(revokedSerials);
        ArgumentNullException.ThrowIfNull(comment);
        var seconds = generatedAt.ToUnixTimeSeconds();
        if (seconds < 0)
            throw new ArgumentException("The generation time is before 1970.", nameof(generatedAt));

        var serials = new SortedSet<ulong>(revokedSerials);
        if (serials.Contains(0))
            throw new ArgumentException("Serial zero cannot be revoked by serial.", nameof(revokedSerials));

        var writer = new SshWriter()
            .UInt64(Magic)
            .UInt32(FormatVersion)
            .UInt64(krlVersion)
            .UInt64((ulong)seconds)
            .UInt64(0)
            .String([])
            .String(comment);

        if (serials.Count > 0)
        {
            var list = new SshWriter();
            foreach (var serial in serials)
                list.UInt64(serial);

            var section = new SshWriter()
                .String(caKey.Blob)
                .String([])
                .Byte(CertSectionSerialList)
                .String(list.ToArray());

            writer.Byte(SectionCertificates).String(section.ToArray());
        }
        return writer.ToArray();
    }
}
