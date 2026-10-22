using ModularCA.Keystore;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// In-memory <see cref="ISignerKeyRegistry"/> holding whatever CAs a test hands it.
/// <para>
/// The real keystore reads signed, encrypted files off disk and unlocks them with a passphrase,
/// which is not something a unit test should stand up. What the signer actually needs from it
/// is narrow: the list of signers and a private-key handle per signer.
/// </para>
/// </summary>
internal sealed class TestKeystore : ISignerKeyRegistry
{
    private readonly List<(X509Certificate Certificate, IPrivateKeyHandle Handle)> _signers;
    private readonly List<X509Certificate> _trusted;

    public TestKeystore(params (X509Certificate Certificate, IPrivateKeyHandle Handle)[] signers)
    {
        _signers = signers.ToList();
        _trusted = _signers.Select(s => s.Certificate).ToList();
    }

    public List<X509Certificate> GetTrustedAuthorities() => _trusted.ToList();

    public List<CertificateAuthorityIdentity> GetSigners() => _signers.Select(s => new CertificateAuthorityIdentity(s.Certificate)).ToList();

    public IPrivateKeyHandle? GetPrivateKeyFor(X509Certificate cert)
        => _signers.FirstOrDefault(s => s.Certificate.SerialNumber.Equals(cert.SerialNumber)
                                     && s.Certificate.SubjectDN.Equivalent(cert.SubjectDN))
                   .Handle;

    /// <summary>Adds a signer the way the runtime registry does, de-duplicating on serial and subject.</summary>
    public void RegisterSigner(X509Certificate certificate, IPrivateKeyHandle handle)
    {
        if (GetPrivateKeyFor(certificate) == null)
            _signers.Add((certificate, handle));
        RegisterTrustedCert(certificate);
    }

    public void RegisterTrustedCert(X509Certificate cert)
    {
        if (!_trusted.Any(t => t.SerialNumber.Equals(cert.SerialNumber)))
            _trusted.Add(cert);
    }

    private readonly List<SshKeyBinding> _sshKeys = new();

    public SshKeyBinding? GetSshKey(Guid sshCaKeyId)
    {
        lock (_sshKeys) return _sshKeys.FirstOrDefault(k => k.KeyId == sshCaKeyId);
    }

    public IReadOnlyList<SshKeyBinding> GetSshKeys()
    {
        lock (_sshKeys) return _sshKeys.ToList();
    }

    /// <summary>Binds an SSH CA key to its row the way the runtime registry does: a row never changes key.</summary>
    public void RegisterSshKey(SshKeyBinding binding)
    {
        lock (_sshKeys)
        {
            var bound = _sshKeys.FirstOrDefault(k => k.KeyId == binding.KeyId);
            if (bound == null)
                _sshKeys.Add(binding);
            else if (!bound.PublicKey.Equals(binding.PublicKey))
                throw new InvalidOperationException($"SSH CA key row {binding.KeyId} is already bound to another key.");
        }
    }
}

/// <summary>
/// The signer's persistence for tests: every committed pair is kept in memory so a test can
/// assert what would have been appended to the keystore files, and the keystore files
/// themselves are a dictionary of bytes by name, so a test can seed what a backup exports and
/// read back what a restore imported.
/// </summary>
internal sealed class InMemorySignerKeyPersistence : ModularCA.Keystore.Signing.ISignerKeyPersistence
{
    private readonly List<(byte[] PrivateKeyDer, byte[] CertificateDer)> _appended = new();

    /// <summary>The pairs appended so far, oldest first. The private key bytes are copies taken before the signer zeroes its own.</summary>
    public IReadOnlyList<(byte[] PrivateKeyDer, byte[] CertificateDer)> Appended => _appended;

    /// <summary>When set, every append throws it, to test a commit that cannot persist.</summary>
    public Exception? FailWith { get; set; }

    /// <summary>The keystore files by name, as the persistence keeps them.</summary>
    public Dictionary<string, byte[]> KeystoreFiles { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Stands in for signature verification on import: a file for which this returns false is
    /// refused as not verifying, and nothing is written. Every file verifies by default.
    /// </summary>
    public Func<string, byte[], bool> Verifies { get; set; } = (_, _) => true;

    public void Append(byte[] privateKeyPkcs8Der, byte[] certificateDer)
    {
        if (FailWith != null) throw FailWith;
        _appended.Add(((byte[])privateKeyPkcs8Der.Clone(), (byte[])certificateDer.Clone()));
    }

    private readonly List<byte[]> _sshAppended = new();

    /// <summary>The SSH CA keys appended so far, as PKCS#8, oldest first: what the SSH keystore would hold.</summary>
    public IReadOnlyList<byte[]> SshAppended => _sshAppended;

    public void AppendSshKey(byte[] privateKeyPkcs8Der)
    {
        if (FailWith != null) throw FailWith;
        _sshAppended.Add((byte[])privateKeyPkcs8Der.Clone());
    }

    public IReadOnlyList<string> ListKeystoreFiles()
        => KeystoreFiles.Keys.Where(k => k.EndsWith(".keystore", StringComparison.Ordinal)).OrderBy(k => k, StringComparer.Ordinal).ToList();

    public byte[] ReadKeystoreFile(string name)
        => KeystoreFiles.TryGetValue(name, out var bytes) ? (byte[])bytes.Clone() : throw new FileNotFoundException(name);

    public void ImportKeystoreFile(string name, byte[] bytes)
    {
        if (!Verifies(name, bytes))
            throw new System.Security.SecurityException($"Keystore file '{name}' does not verify.");
        KeystoreFiles[name] = (byte[])bytes.Clone();
    }

    /// <summary>The keystore files moved aside so far: the name each had, and the name it was kept under.</summary>
    public List<(string Name, string MovedTo)> MovedAside { get; } = new();

    public string? MoveKeystoreFileAside(string name)
    {
        if (!KeystoreFiles.Remove(name, out var bytes))
            return null;
        var aside = $"{name}.bak.{MovedAside.Count + 1}";
        KeystoreFiles[aside] = bytes;
        MovedAside.Add((name, aside));
        return aside;
    }
}

/// <summary>
/// Returns a fixed <see cref="SecurityPolicyEntity"/>. Tests that care about a specific switch —
/// RequireSignedRequests, RequireMtlsOcspCheck, the OCSP TTLs — construct one with that value set
/// rather than seeding a row and hoping the caching layer agrees.
/// </summary>
internal sealed class StubSecurityPolicyService : ISecurityPolicyService
{
    private readonly SecurityPolicyEntity _policy;

    public StubSecurityPolicyService(SecurityPolicyEntity? policy = null)
        => _policy = policy ?? new SecurityPolicyEntity();

    public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);

    public void InvalidateCache() { }
}
