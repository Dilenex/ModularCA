namespace ModularCA.Shared.Models.Config;

/// <summary>
/// Where the node finds its signer, and how the signer role listens. The defaults keep a single
/// process in-process, which is the shape of every install before stage 2. Paths resolve
/// against the application base directory when relative, as <c>Https.CertificatePath</c> does.
/// </summary>
/// <remarks>
/// The node side (<see cref="Mode"/>, <see cref="Endpoint"/>, <see cref="ClientCertificate"/>,
/// <see cref="PinnedServerSpki"/>) and the signer side (<see cref="Listen"/>,
/// <see cref="ServerCertificate"/>, <see cref="PinnedClientSpki"/>) share the section because on
/// a single host the two units read the same file; each process reads the keys for its role.
/// Identity comes from the signer's own identity CA (<c>--init-identity</c> on the signer role),
/// which issues one server certificate to the signer and one client certificate to the node;
/// each side pins the other's public key and consults no trust store.
/// </remarks>
public class SignerConfig
{
    /// <summary>The signer runs inside the node's process; the default.</summary>
    public const string InProcessMode = "InProcess";

    /// <summary>The node reaches a signer role in another process over mutual TLS.</summary>
    public const string RemoteMode = "Remote";

    /// <summary><see cref="InProcessMode"/> or <see cref="RemoteMode"/>. Read by the node role.</summary>
    public string Mode { get; set; } = InProcessMode;

    /// <summary>Whether the node reaches its signer over the wire.</summary>
    public bool IsRemote => string.Equals(Mode?.Trim(), RemoteMode, StringComparison.OrdinalIgnoreCase);

    // ---- Node side ----

    /// <summary>The signer role's address, <c>https://host:port</c>; loopback on a single host.</summary>
    public string Endpoint { get; set; } = "https://127.0.0.1:8446";

    /// <summary>PKCS#12 holding the node's client certificate and key, issued by the signer's identity CA.</summary>
    public string ClientCertificate { get; set; } = "config/signer-client.pfx";

    /// <summary>The password of <see cref="ClientCertificate"/>; empty when the file has none.</summary>
    public string ClientCertificatePassword { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 over the signer's server certificate SubjectPublicKeyInfo, hex, as
    /// <c>--issue-node-identity</c> writes it to <c>signer-pin.txt</c>. The node accepts no
    /// other server certificate, whatever chain it presents.
    /// </summary>
    public string PinnedServerSpki { get; set; } = string.Empty;

    // ---- Signer side ----

    /// <summary>The address the signer role listens on, <c>host:port</c>; loopback on a single host.</summary>
    public string Listen { get; set; } = "127.0.0.1:8446";

    /// <summary>PKCS#12 holding the signer's server certificate and key, written by <c>--init-identity</c>.</summary>
    public string ServerCertificate { get; set; } = "config/signer-server.pfx";

    /// <summary>The password of <see cref="ServerCertificate"/>; empty when the file has none.</summary>
    public string ServerCertificatePassword { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 over the node's client certificate SubjectPublicKeyInfo, hex, as
    /// <c>--issue-node-identity</c> prints it. The signer refuses every other client at the
    /// TLS handshake.
    /// </summary>
    public string PinnedClientSpki { get; set; } = string.Empty;

    /// <summary>
    /// PKCS#12 holding the signer's identity CA, which issues the two certificates above.
    /// Written by <c>--init-identity</c>, read by <c>--issue-node-identity</c>, and by nothing
    /// at runtime.
    /// </summary>
    public string IdentityCa { get; set; } = "config/signer-identity-ca.pfx";

    /// <summary>The password of <see cref="IdentityCa"/>; empty when the file has none.</summary>
    public string IdentityCaPassword { get; set; } = string.Empty;

    /// <summary>
    /// Resolves a configured path against <paramref name="baseDirectory"/> when it is relative,
    /// the convention every certificate path in the configuration follows.
    /// </summary>
    public static string ResolvePath(string path, string baseDirectory)
        => Path.IsPathRooted(path) ? path : Path.Combine(baseDirectory, path);
}
