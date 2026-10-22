using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using ModularCA.Tests.TestUtils;

namespace ModularCA.Tests.Core.Services;

/// <summary>The SSH services as a node composes them, for a test that has only a database, a signer and an audit.</summary>
internal static class SshServices
{
    /// <summary>The login name rule over <paramref name="db"/>, asking the real capability resolver who may request.</summary>
    public static SshLoginNameService LoginNames(ModularCADbContext db, ModularCA.Shared.Interfaces.IAuditService audit)
        => new(db, audit, new ModularCA.Auth.Authorization.SshRequestRights(db));

    /// <summary>The SSH CA service over <paramref name="db"/>, with <see cref="LoginNames"/> over the same database and audit.</summary>
    public static SshCaService Ca(ModularCADbContext db, ISigningService signer, ModularCA.Shared.Interfaces.IAuditService audit)
        => new(db, signer, audit, NullLogger<SshCaService>.Instance, LoginNames(db, audit));
}

/// <summary>
/// A signer no test expects to be asked anything: every call fails the test that made it, and
/// <see cref="Calls"/> counts them. For the paths that must not reach the signer: a refusal
/// decided on the node, a KRL, a disable.
/// </summary>
internal sealed class UnaskedSigner : ISigningService
{
    public int Calls { get; private set; }

    private Exception Asked(string what)
    {
        Calls++;
        return new InvalidOperationException($"The signer was asked to {what}; this path must not reach it.");
    }

    public Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("sign");
    public Task<byte[]> SignSshCertificateAsync(SshCertificateRequest request, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("sign an SSH certificate");
    public Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("decrypt");
    public Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("generate a key");
    public Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("import a key");
    public Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("commit a key");
    public Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("export a key");
    public Task<byte[]> WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("wrap a secret");
    public Task<byte[]> UnwrapSecretAsync(byte[] wrapped, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("unwrap a secret");
    public Task<byte[]> WrapBoundSecretAsync(SecretKind kind, string binding, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("wrap a secret");
    public Task<byte[]> UnwrapBoundSecretAsync(byte[] wrapped, string binding, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("unwrap a secret");
    public Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default) => throw Asked("list keys");
    public Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default) => throw Asked("retire a key");
    public Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default) => throw Asked("report its health");
}

/// <summary>
/// Passes every call to the signer behind it, and lets a test stand in for what a real signer
/// cannot be made to do: one that predates the SSH keystore, one that refuses for a reason of
/// the test's choosing, one that returns something other than what it was asked for. Each hook
/// is null until a test sets it. The contexts and requests the node sent are kept for a test
/// to read.
/// </summary>
internal sealed class RelayingSigner(ISigningService inner) : ISigningService
{
    /// <summary>What the node's key specification becomes before the signer behind sees it.</summary>
    public Func<KeySpec, KeySpec>? RewriteSpec { get; set; }

    /// <summary>Runs in place of the commit; it may throw.</summary>
    public Func<KeyRef, Guid, SigningContext, Task>? OnCommit { get; set; }

    /// <summary>Runs in place of the SSH signature; it may throw, or sign something else.</summary>
    public Func<SshCertificateRequest, SigningContext, Task<byte[]>>? OnSignSsh { get; set; }

    /// <summary>What the list of keys becomes before the node sees it.</summary>
    public Func<IReadOnlyList<KeyInfo>, IReadOnlyList<KeyInfo>>? RewriteListed { get; set; }

    public List<(KeySpec Spec, SigningContext Context)> Generated { get; } = [];
    public List<(KeyRef Key, Guid RowId, SigningContext Context)> Committed { get; } = [];
    public List<(KeyRef Key, SigningContext Context)> Retired { get; } = [];
    public List<(SshCertificateRequest Request, SigningContext Context)> SshSigned { get; } = [];

    /// <summary>The signer behind this one.</summary>
    public ISigningService Inner => inner;

    public Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default)
    {
        Generated.Add((spec, context));
        return inner.GenerateKeyAsync(RewriteSpec?.Invoke(spec) ?? spec, context, cancellationToken);
    }

    public Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default)
    {
        Committed.Add((key, certificateId, context));
        return OnCommit != null ? OnCommit(key, certificateId, context) : inner.CommitKeyAsync(key, certificateId, context, cancellationToken);
    }

    public Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default)
    {
        Retired.Add((key, context));
        return inner.RetireKeyAsync(key, context, cancellationToken);
    }

    public Task<byte[]> SignSshCertificateAsync(SshCertificateRequest request, SigningContext context, CancellationToken cancellationToken = default)
    {
        SshSigned.Add((request, context));
        return OnSignSsh != null ? OnSignSsh(request, context) : inner.SignSshCertificateAsync(request, context, cancellationToken);
    }

    public Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default) => inner.SignAsync(key, algorithm, data, context, cancellationToken);
    public Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default) => inner.DecryptAsync(key, enveloped, context, cancellationToken);
    /// <summary>Runs in place of the import; it may throw, or answer with another reference.</summary>
    public Func<KeyMaterial, SigningContext, Task<KeyRef>>? OnImport { get; set; }

    /// <summary>Runs after the signer behind has taken an import and before the node hears of it; it may throw.</summary>
    public Action<KeyRef>? AfterImport { get; set; }

    /// <summary>The imports the node asked for: the row, the keystore, the format, the size of the material and the context.</summary>
    public List<(Guid RowId, string Keystore, string Format, int Length, SigningContext Context)> Imported { get; } = [];

    public async Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default)
    {
        Imported.Add((material.CertificateId, material.Keystore, material.Format, material.Wrapped.Length, context));
        if (OnImport != null)
            return await OnImport(material, context);
        var held = await inner.ImportKeyAsync(material, context, cancellationToken);
        AfterImport?.Invoke(held);
        return held;
    }

    public Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default) => inner.ExportKeyAsync(key, wrap, context, cancellationToken);
    public Task<byte[]> WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => inner.WrapSecretAsync(kind, secret, context, cancellationToken);
    public Task<byte[]> UnwrapSecretAsync(byte[] wrapped, SigningContext context, CancellationToken cancellationToken = default) => inner.UnwrapSecretAsync(wrapped, context, cancellationToken);
    public Task<byte[]> WrapBoundSecretAsync(SecretKind kind, string binding, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => inner.WrapBoundSecretAsync(kind, binding, secret, context, cancellationToken);
    public Task<byte[]> UnwrapBoundSecretAsync(byte[] wrapped, string binding, SigningContext context, CancellationToken cancellationToken = default) => inner.UnwrapBoundSecretAsync(wrapped, binding, context, cancellationToken);
    public async Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default)
    {
        var listed = await inner.ListKeysAsync(context, cancellationToken);
        return RewriteListed?.Invoke(listed) ?? listed;
    }

    public Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default) => inner.HealthAsync(cancellationToken);
}

/// <summary>An audit that keeps every entry whole, so a test can read who, what, the outcome and the details.</summary>
internal sealed class SshAuditLog : ModularCA.Shared.Interfaces.IAuditService
{
    public sealed record Entry(string Action, Guid? ActorId, string? Actor, string? TargetType, string? TargetId, object? Details,
        string? SourceIp, bool Success, string? Error, Guid? CaId);

    public List<Entry> Entries { get; } = [];

    /// <summary>The entries of one action, oldest first.</summary>
    public List<Entry> Of(string action) => Entries.Where(e => e.Action == action).ToList();

    public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
        string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
        string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
    {
        Entries.Add(new Entry(actionType, actorUserId, actorUsername, targetEntityType, targetEntityId, details, sourceIp, success, errorMessage, certificateAuthorityId));
        return Task.CompletedTask;
    }
}

/// <summary>
/// A node with SSH CAs, as the tests of <see cref="SshCaService"/> need one: an application
/// database with the built-in roles and an instance that waives key ceremonies, the real
/// in-process signer over an empty keystore and an in-memory persistence, an audit that keeps
/// its entries, and the service over them. <see cref="Relay"/> stands between the service and
/// the signer, so a test can read what the node sent and bend the signer where a real one cannot
/// be bent.
/// </summary>
internal sealed class SshNode : IDisposable
{
    public string DatabaseName { get; } = $"ssh-node-{Guid.NewGuid():N}";
    public ModularCADbContext Db { get; }
    public TestKeystore Keystore { get; } = new();
    public InMemorySignerKeyPersistence Persistence { get; } = new();
    public InProcessSigningService RealSigner { get; }
    public RelayingSigner Relay { get; }
    public SshAuditLog Audit { get; } = new();
    public SshCaService Service { get; }

    /// <summary>The user the tests sign and create as.</summary>
    public ModularCA.Shared.Interfaces.SshCaActor Actor { get; } = new(Guid.NewGuid(), "ssh-operator", "192.0.2.7");

    /// <summary>
    /// A service identity to sign user certificates for where the test is not about login
    /// names: its principals are as typed, and its key id is <see cref="CiKeyId"/>.
    /// </summary>
    public static ModularCA.Shared.Interfaces.SshCertificateSubject Ci { get; } = ModularCA.Shared.Interfaces.SshCertificateSubject.ForService("ci");

    /// <summary>The key id the CA writes for <see cref="Ci"/>.</summary>
    public const string CiKeyId = "svc:ci";

    /// <summary>The login name rule over this node's database and audit.</summary>
    public SshLoginNameService LoginNames => SshServices.LoginNames(Db, Audit);

    /// <summary>Adds an active user, and makes them a member of <paramref name="groups"/>.</summary>
    public UserEntity AddUser(string username, params Guid[] groups)
    {
        var user = new UserEntity { Id = Guid.NewGuid(), Username = username, Email = $"{username}@example.test", PasswordHash = "x" };
        Db.Users.Add(user);
        foreach (var group in groups)
            Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = group, UserId = user.Id });
        Db.SaveChanges();
        return user;
    }

    /// <summary>The group the SSH CA of <paramref name="key"/> was created with for <paramref name="template"/>: admin, operator, auditor or user.</summary>
    public CaGroupEntity GroupOf(SshCaKeyEntity key, string template)
    {
        var label = Db.CertificateAuthorities.Single(c => c.Id == key.CertificateAuthorityId).Label;
        return Db.CaGroups.Single(g => g.Name == $"{label}-{template}");
    }

    /// <summary>Adds an instance group that belongs to no CA.</summary>
    public CaGroupEntity AddGroup(string name)
    {
        var group = new CaGroupEntity { Id = Guid.NewGuid(), Name = name, DisplayName = name, SpaceId = null };
        Db.CaGroups.Add(group);
        Db.SaveChanges();
        return group;
    }

    /// <param name="requireKeyCeremony">Whether the instance requires a key ceremony.</param>
    /// <param name="unlocked">Whether the signer has unlocked its keystore.</param>
    public SshNode(bool requireKeyCeremony = false, bool unlocked = true)
    {
        Db = InMemoryDbContextFactory.Create(DatabaseName);
        ModularCA.Bootstrap.BootstrapProfileSeeder.SeedBuiltInRoles(Db);
        Db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = requireKeyCeremony, CeremonyRequiredApprovals = 1 });
        Db.SaveChanges();

        var scopes = TestSigner.ScopesFor(DatabaseName);
        RealSigner = new InProcessSigningService(Keystore, scopes, new DatabaseSignerAuditSink(scopes), Persistence,
            NullLogger<InProcessSigningService>.Instance, unlocked: unlocked);
        Relay = new RelayingSigner(RealSigner);
        Service = ServiceOver(Relay);
    }

    /// <summary>The service over this node's database and audit, asking <paramref name="signer"/>.</summary>
    public SshCaService ServiceOver(ISigningService signer) => SshServices.Ca(Db, signer, Audit);

    /// <summary>A second context over the same database, to read what was really saved.</summary>
    public ModularCADbContext Reopen() => InMemoryDbContextFactory.Create(DatabaseName);

    /// <summary>Creates an SSH CA that signs both certificate types, valid up to <paramref name="maxValidityHours"/>.</summary>
    public Task<SshCaKeyEntity> CreateCaAsync(string name = "Fleet SSH", string keyType = "ed25519", int? keySize = null, int maxValidityHours = 48)
        => Service.GenerateKeyPairAsync(name, keyType, isUserCa: true, isHostCa: true, maxValidityHours, keySize, actor: Actor);

    /// <summary>
    /// Seeds an SSH CA as an install from before the SSH keystore has one: an enabled row whose
    /// key is a file on the node, which the signer does not hold.
    /// </summary>
    public SshCaKeyEntity SeedLegacyCa(string name = "Old SSH")
    {
        var pair = ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "");
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = name, Label = name.ToLowerInvariant().Replace(' ', '-'), Type = "SSH", IsSshCa = true, SpaceId = null };
        var key = new SshCaKeyEntity
        {
            Id = Guid.NewGuid(), Name = name, KeyType = "ed25519", CertificateAuthorityId = ca.Id,
            PublicKey = SshPublicKey.FromKeyParameter(pair.Public).ToAuthorizedKey(name),
            KeyStorage = SshCaKeyStorage.LegacyFile, PrivateKeyPath = $"config/ssh-ca-keys/{Guid.NewGuid()}",
            IsUserCa = true, IsHostCa = true, MaxValidityHours = 24,
        };
        Db.CertificateAuthorities.Add(ca);
        Db.SshCaKeys.Add(key);
        Db.SaveChanges();
        return key;
    }

    /// <summary>A fresh subject key of the given algorithm, as the authorized_keys line a client submits.</summary>
    public static string SubjectKey(string algorithm = "Ed25519", string sizeOrCurve = "", string? comment = "alice@laptop")
        => SshPublicKey.FromKeyParameter(ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair(algorithm, sizeOrCurve).Public).ToAuthorizedKey(comment);

    /// <summary>
    /// A DSA public key as an authorized_keys line. The numbers are not a real key: the parser
    /// checks only that a DSA key is well formed, since no DSA key is ever certified.
    /// </summary>
    public static string DsaKey()
        => SshPublicKey.FromKeyParameter(new Org.BouncyCastle.Crypto.Parameters.DsaPublicKeyParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(8),
            new Org.BouncyCastle.Crypto.Parameters.DsaParameters(
                Org.BouncyCastle.Math.BigInteger.ValueOf(23), Org.BouncyCastle.Math.BigInteger.ValueOf(11), Org.BouncyCastle.Math.BigInteger.ValueOf(4)))).ToAuthorizedKey("legacy");

    public void Dispose() => Db.Dispose();
}
