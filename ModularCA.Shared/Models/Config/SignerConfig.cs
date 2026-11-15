using ModularCA.Shared.Settings;

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
    [Setting(SettingClass.HostLocal, SettingReload.Restart)]
    public string Mode { get; set; } = InProcessMode;

    /// <summary>Whether the node reaches its signer over the wire.</summary>
    public bool IsRemote => string.Equals(Mode?.Trim(), RemoteMode, StringComparison.OrdinalIgnoreCase);

    // ---- Node side ----

    /// <summary>The signer role's address, <c>https://host:port</c>; loopback on a single host.</summary>
    [Setting(SettingClass.HostLocal, SettingReload.Restart)]
    public string Endpoint { get; set; } = "https://127.0.0.1:8446";

    /// <summary>PKCS#12 holding the node's client certificate and key, issued by the signer's identity CA.</summary>
    [Setting(SettingClass.HostLocal, SettingReload.Restart)]
    public string ClientCertificate { get; set; } = "config/signer-client.pfx";

    /// <summary>The password of <see cref="ClientCertificate"/>; empty when the file has none.</summary>
    [Setting(SettingClass.HostLocal, SettingReload.Restart)]
    public string ClientCertificatePassword { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 over the signer's server certificate SubjectPublicKeyInfo, hex, as
    /// <c>--issue-node-identity</c> writes it to <c>signer-pin.txt</c>. The node accepts no
    /// other server certificate, whatever chain it presents.
    /// </summary>
    [Setting(SettingClass.HostLocal, SettingReload.Restart)]
    public string PinnedServerSpki { get; set; } = string.Empty;

    // ---- Signer side ----

    /// <summary>The address the signer role listens on, <c>host:port</c>; loopback on a single host.</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string Listen { get; set; } = "127.0.0.1:8446";

    /// <summary>PKCS#12 holding the signer's server certificate and key, written by <c>--init-identity</c>.</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string ServerCertificate { get; set; } = "config/signer-server.pfx";

    /// <summary>The password of <see cref="ServerCertificate"/>; empty when the file has none.</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string ServerCertificatePassword { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 over the node's client certificate SubjectPublicKeyInfo, hex, as
    /// <c>--issue-node-identity</c> prints it. The signer refuses every other client at the
    /// TLS handshake.
    /// </summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string PinnedClientSpki { get; set; } = string.Empty;

    /// <summary>
    /// PKCS#12 holding the signer's identity CA, which issues the two certificates above.
    /// Written by <c>--init-identity</c>, read by <c>--issue-node-identity</c>, and by nothing
    /// at runtime.
    /// </summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string IdentityCa { get; set; } = "config/signer-identity-ca.pfx";

    /// <summary>The password of <see cref="IdentityCa"/>; empty when the file has none.</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string IdentityCaPassword { get; set; } = string.Empty;

    /// <summary>The signer's issuance journal: where it is kept and how its two checks behave.</summary>
    public SignerJournalConfig Journal { get; set; } = new();

    /// <summary>
    /// Resolves a configured path against <paramref name="baseDirectory"/> when it is relative,
    /// the convention every certificate path in the configuration follows.
    /// </summary>
    public static string ResolvePath(string path, string baseDirectory)
        => Path.IsPathRooted(path) ? path : Path.Combine(baseDirectory, path);
}

/// <summary>
/// The settings of the signer's issuance journal (<c>docs/architecture/signer-journal.md</c>).
/// They are the signer's own: a node cannot change them, and the settings store does not hold
/// them.
/// </summary>
public class SignerJournalConfig
{
    /// <summary>The value of <see cref="Checks"/> that refuses what a check finds.</summary>
    public const string EnforceChecks = "enforce";

    /// <summary>The value of <see cref="Checks"/> that signs what a check finds and logs it.</summary>
    public const string WarnChecks = "warn";

    /// <summary>
    /// The journal's home: the directory that holds <c>current/</c>, where the live segments
    /// are, and the journals that were set aside. The default is <c>signer/journal</c>:
    /// <c>&lt;base&gt;/signer/journal</c>, or <c>journal</c> in the signer's own directory when it
    /// has one (<see cref="SignerPaths.JournalDirectory"/>). It is not in the keystores
    /// directory, and should be on a volume that is not rolled back or restored with the
    /// keystores or the database; a volume may be mounted directly on it.
    /// <c>MODULARCA__SIGNER__JOURNAL__DIRECTORY</c> overrides it.
    /// </summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string Directory { get; set; } = SignerPaths.DefaultJournalDirectory;

    /// <summary>
    /// What the signer does when a CRL does not continue the newest one it journaled, or an OCSP
    /// response would say "good" for a serial on it: <c>enforce</c> refuses to sign,
    /// <c>warn</c> signs and logs. <c>warn</c> is for the time after a database was taken back
    /// and before the lost revocations are entered again.
    /// </summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string Checks { get; set; } = EnforceChecks;

    /// <summary>Whether the two checks refuse; anything but <see cref="WarnChecks"/> does.</summary>
    public bool Enforces => !string.Equals(Checks?.Trim(), WarnChecks, StringComparison.OrdinalIgnoreCase);

    /// <summary>The default of <see cref="LowSpaceMiB"/>: 1 GiB.</summary>
    public const int DefaultLowSpaceMiB = 1024;

    /// <summary>The default of <see cref="CriticalSpaceMiB"/>: 128 MiB.</summary>
    public const int DefaultCriticalSpaceMiB = 128;

    /// <summary>
    /// Free space on the journal's volume, in MiB, below which the health check reports
    /// <c>low_space</c>. A warning only: the signer goes on issuing. 1024 by default; 0 turns
    /// the warning off.
    /// </summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public int LowSpaceMiB { get; set; } = DefaultLowSpaceMiB;

    /// <summary>
    /// Free space on the journal's volume, in MiB, below which the health check reports
    /// <c>critical_space</c>. A warning only: the signer goes on issuing until a write to the
    /// journal actually fails. 128 by default; 0 turns the warning off.
    /// </summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public int CriticalSpaceMiB { get; set; } = DefaultCriticalSpaceMiB;
}
