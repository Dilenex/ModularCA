using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Ssh;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text.Json;

namespace ModularCA.Core.Services;

/// <summary>
/// SSH certificate authorities over the signer. The signer generates and holds every SSH CA
/// key and builds and signs every SSH certificate; this service holds no key, reads no key file
/// and runs no program. It keeps what the signer does not decide: the CA, group, key and
/// certificate rows, the serial's uniqueness, the default signing profiles and the audit entry
/// of each operation, written here once whichever controller or ceremony called. It also writes
/// every certificate's key id (<see cref="SshKeyIds"/>), and holds a certificate for a user to the
/// login names that user holds on the key (<see cref="ISshLoginNameService"/>).
/// </summary>
/// <remarks>
/// A row whose <see cref="SshCaKeyEntity.KeyStorage"/> is <see cref="SshCaKeyStorage.LegacyFile"/>
/// is a key made before the signer held SSH keys, still a file on the node. It signs nothing
/// here until it has been imported into the signer; its row, its file and its
/// <see cref="SshCaKeyEntity.PrivateKeyPath"/> are left exactly as they are.
/// </remarks>
public class SshCaService : ISshCaService
{
    /// <summary>The caller identity SSH operations ask the signer under; the signer audits it with every decision.</summary>
    private const string SignerCaller = nameof(SshCaService);

    /// <summary>
    /// How far before the node's clock a certificate's <c>valid_after</c> is set, so that a
    /// server whose clock runs a little behind accepts a certificate the moment it is issued.
    /// <b>This is an open owner decision</b>, question 1 of
    /// <c>docs/architecture/ssh-keystore.md</c>: five minutes, or none. The signer's allowance
    /// for a start in the past (<c>SshValidAfterAllowance</c> in
    /// <c>InProcessSigningService.SshCertificates.cs</c>, ten minutes) depends on this value: it
    /// is this plus five minutes of clock difference between node and signer, and has to move
    /// with it. The validity window is counted from the backdated start, so a certificate asked
    /// for N hours is valid for N hours less this from the moment it is issued, and the window
    /// never exceeds what a profile or the key allows.
    /// </summary>
    public static readonly TimeSpan ValidAfterBackdate = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether a KRL is served for an SSH CA key with no revoked certificate. <b>This is an open
    /// owner decision</b>, question 2 of <c>docs/architecture/ssh-keystore.md</c>. True, as
    /// built: <see cref="GenerateKrlAsync"/> always returns a valid KRL, one with no entries
    /// when nothing is revoked, and both KRL routes answer 200 with it. False restores what was
    /// there before: <see cref="GenerateKrlAsync"/> returns no bytes when nothing is revoked,
    /// which the admin route answers with 200 and a JSON message and the public route with 204.
    /// </summary>
    public static readonly bool ServeKrlWithNoEntries = true;

    /// <summary>The longest comment written after a public key or a certificate.</summary>
    private const int MaxCommentLength = 256;

    private static readonly int[] RsaSizes = [2048, 3072, 4096, 7680, 8192];
    private static readonly int[] EcdsaSizes = [256, 384, 521];

    private readonly ModularCADbContext _db;
    private readonly ISigningService _signer;
    private readonly IAuditService _audit;
    private readonly ILogger<SshCaService> _logger;
    private readonly ISshLoginNameService _loginNames;

    /// <summary>
    /// Creates the service over the application database, the signer and the audit.
    /// <paramref name="loginNames"/> decides whether a user may request from an SSH CA and
    /// which login names they hold.
    /// </summary>
    public SshCaService(ModularCADbContext db, ISigningService signer, IAuditService audit, ILogger<SshCaService> logger,
        ISshLoginNameService loginNames)
    {
        ArgumentNullException.ThrowIfNull(loginNames);
        _db = db;
        _signer = signer;
        _audit = audit;
        _logger = logger;
        _loginNames = loginNames;
    }

    /// <summary>
    /// Creates an SSH CA whose key the signer generates and holds. The SSH CA and its groups are
    /// instance rows, with no space. Its label, derived from <paramref name="name"/>, must be
    /// valid and not reserved, and its label and name unused by any CA of the instance,
    /// soft-deleted ones included; otherwise nothing is generated. The key's advisory review
    /// date is set two years ahead for a key that signs user certificates and five for a
    /// host-only key (<see cref="SshCaKeyDefaults"/>), and is in the audit entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The order is the one X.509 CA creation uses. The signer generates the key under a
    /// ceremony context that states the instance and names <paramref name="ceremonyId"/> when
    /// there is one, and holds it pending. One database transaction then writes the CA row, its
    /// four groups with their roles, the <c>SshCaKeys</c> row (the public key rendered from what
    /// the signer returned, storage <see cref="SshCaKeyStorage.Signer"/>, no key path) and the
    /// default signing profiles. Once that has committed, the key is committed to the row, which
    /// is when the signer writes it to the SSH keystore: the signer reads the row to bind the
    /// key, so the row has to be there first.
    /// </para>
    /// <para>
    /// A failure before the transaction commits rolls it back and retires the pending key, so no
    /// row and no key is left. A commit the signer refuses, or that fails, retires the key and
    /// deletes the rows again. A label or name another request takes during the save is a
    /// <see cref="ResourceConflictException"/>.
    /// </para>
    /// <para>
    /// A signer that predates the SSH keystore ignores the key's usage and generates an X.509
    /// key in <see cref="KeyRef.DefaultKeystore"/>. The reference it returns says so; that key is
    /// retired and the creation fails with <see cref="SshCaKeyUnavailableException"/>.
    /// </para>
    /// </remarks>
    public async Task<SshCaKeyEntity> GenerateKeyPairAsync(string name, string keyType, bool isUserCa, bool isHostCa, int maxValidityHours,
        int? keySize = null, Guid? ceremonyId = null, SshCaActor? actor = null)
    {
        var caLabel = name.ToLowerInvariant().Replace(" ", "-");
        CaLabelRules.Validate(caLabel, paramName: nameof(name));
        await CaLabelRules.EnsureUniqueAsync(_db, caLabel, name);
        var algorithm = AlgorithmOf(keyType, keySize);

        try
        {
            var entity = await CreateAsync(name, caLabel, algorithm, isUserCa, isHostCa, maxValidityHours, ceremonyId);

            await _audit.LogAsync(AuditActionType.SshCaKeyCreated, actor?.UserId, actor?.Username ?? "system",
                "SshCaKey", entity.Id.ToString(),
                new
                {
                    entity.Name, entity.KeyType, entity.KeySize, Fingerprint = FingerprintOf(entity.PublicKey),
                    entity.IsUserCa, entity.IsHostCa, entity.MaxValidityHours, entity.ReviewBy, entity.KeyStorage, CeremonyId = ceremonyId,
                },
                actor?.SourceIp, certificateAuthorityId: entity.CertificateAuthorityId);
            _logger.LogInformation("SSH CA key created in the signer: {Name} ({KeyType}), ID={Id}", entity.Name, entity.KeyType, entity.Id);
            return entity;
        }
        catch (Exception ex) when (ex is not AuditWriteFailedException)
        {
            await AuditFailureAsync(AuditActionType.SshCaKeyCreated, actor, "SshCaKey", null,
                new { Name = name, KeyType = algorithm.KeyType, algorithm.KeySize, CeremonyId = ceremonyId }, ex);
            throw;
        }
    }

    /// <summary>
    /// The steps of <see cref="GenerateKeyPairAsync"/> between the checks on the name and the
    /// audit entry: generate, write the rows, commit the key. The key row takes its advisory
    /// review date from <see cref="SshCaKeyDefaults.ReviewBy"/>.
    /// </summary>
    private async Task<SshCaKeyEntity> CreateAsync(string name, string caLabel, SshCaAlgorithm algorithm,
        bool isUserCa, bool isHostCa, int maxValidityHours, Guid? ceremonyId)
    {
        var generation = SigningContext.ForScope(SignerCaller, SigningPurpose.Ceremony, spaceId: null, ceremonyId: ceremonyId);
        GeneratedKey generated;
        try
        {
            generated = await _signer.GenerateKeyAsync(new KeySpec(algorithm.Algorithm, algorithm.SizeOrCurve, Usage: KeySpec.SshUsage), generation);
        }
        catch (SigningRefusedException ex) when (SshSignerRefusals.ForKeyCreation(ex) is SshCaKeyUnavailableException unavailable)
        {
            throw unavailable;
        }

        if (!string.Equals(generated.Key.Keystore, KeyRef.SshKeystore, StringComparison.OrdinalIgnoreCase))
        {
            await RetireQuietlyAsync(generated.Key, generation);
            throw new SshCaKeyUnavailableException(
                $"{SshCaKeyUnavailableException.SignerPredatesSshKeystore}: it was asked for an SSH CA key and generated one in "
                + $"{generated.Key.Keystore}, which holds X.509 keys. That key was discarded and no SSH CA was created.");
        }

        SshPublicKey publicKey;
        try
        {
            publicKey = SshPublicKey.FromKeyParameter(PublicKeyFactory.CreateKey(generated.PublicKeyDer));
            if (publicKey.KeyType != algorithm.SshKeyType)
                throw new InvalidOperationException(
                    $"The signer was asked for an {algorithm.SshKeyType} SSH CA key and returned a {publicKey.KeyType} key.");
        }
        catch
        {
            await RetireQuietlyAsync(generated.Key, generation);
            throw;
        }

        var caEntity = new CertificateAuthorityEntity
        {
            Name = name,
            Label = caLabel,
            IsSshCa = true,
            IsEnabled = true,
            Type = "SSH",
            SpaceId = null,
        };
        var entity = new SshCaKeyEntity
        {
            Id = Guid.NewGuid(),
            Name = name,
            KeyType = algorithm.KeyType,
            KeySize = algorithm.KeySize,
            PublicKey = publicKey.ToAuthorizedKey(CommentOf(name)),
            PrivateKeyPath = null,
            KeyStorage = SshCaKeyStorage.Signer,
            IsUserCa = isUserCa,
            IsHostCa = isHostCa,
            MaxValidityHours = maxValidityHours,
            CertificateAuthorityId = caEntity.Id,
        };
        entity.ReviewBy = SshCaKeyDefaults.ReviewBy(entity.CreatedAt, isUserCa, isHostCa);

        await using var tx = await _db.Database.BeginTransactionAsync();
        try
        {
            await WriteRowsAsync(caEntity, entity);
            await tx.CommitAsync();
        }
        catch (Exception ex)
        {
            try { await tx.RollbackAsync(); } catch { /* the failure being unwound is the one to report */ }
            ForgetRows(caEntity.Id, entity.Id);
            await RetireQuietlyAsync(generated.Key, generation);
            if (ex is DbUpdateException dbEx && CaLabelRules.IsNameRace(dbEx))
                throw CaLabelRules.NameRaceConflict(caLabel, name);
            throw;
        }

        var binding = SigningContext.ForScope(SignerCaller, SigningPurpose.Ceremony, spaceId: null, caEntity.Id, ceremonyId);
        try
        {
            await _signer.CommitKeyAsync(generated.Key, entity.Id, binding);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "The signer did not commit the key of SSH CA '{Name}'; removing the rows written for it.", name);
            await RetireQuietlyAsync(generated.Key, binding);
            try
            {
                await RemoveRowsAsync(caEntity.Id, entity.Id);
            }
            catch (Exception removal)
            {
                _logger.LogError(removal,
                    "The rows of SSH CA '{Name}' (CA {CaId}, key row {KeyId}) could not be removed after its key was not committed. "
                    + "The signer holds no key for the row, so it signs nothing; disable the SSH CA.", name, caEntity.Id, entity.Id);
            }
            if (ex is SigningRefusedException refusal && SshSignerRefusals.ForKeyCreation(refusal) is SshCaKeyUnavailableException unavailable)
                throw unavailable;
            throw;
        }

        return entity;
    }

    /// <summary>
    /// Writes the rows of a new SSH CA inside the caller's transaction: the instance CA row, its
    /// four authorization groups with their built-in roles, the key row and the default signing
    /// profiles for the certificate types the key signs. Each signing profile takes the key's
    /// own maximum validity: the key holds the ceiling and a request profile the everyday
    /// number. The user profile's default extensions are
    /// <see cref="SshCaKeyDefaults.UserSigningDefaultExtensions"/>, which permit no forwarding.
    /// </summary>
    private async Task WriteRowsAsync(CertificateAuthorityEntity caEntity, SshCaKeyEntity entity)
    {
        _db.CertificateAuthorities.Add(caEntity);
        await _db.SaveChangesAsync();

        var templates = new[]
        {
            ("admin", "Administrator"),
            ("operator", "Operator"),
            ("auditor", "Auditor"),
            ("user", "Requester")
        };

        var groupsCreated = 0;
        foreach (var (suffix, templateName) in templates)
        {
            var groupName = $"{caEntity.Label}-{suffix}";
            if (await _db.CaGroups.AnyAsync(g => g.Name == groupName))
                continue;

            _db.CaGroups.Add(new CaGroupEntity
            {
                Name = groupName,
                DisplayName = $"{caEntity.Name} {templateName}",
                CertificateAuthorityId = caEntity.Id,
                TemplateName = templateName,
                IsSystemGroup = false,
                IsAutoGenerated = true,
                RequiredQuorum = 1,
                SpaceId = null,
                CreatedAt = DateTime.UtcNow
            });
            groupsCreated++;
        }
        if (groupsCreated > 0)
            await _db.SaveChangesAsync();

        var autoGroups = await _db.CaGroups
            .Where(g => g.CertificateAuthorityId == caEntity.Id && g.IsAutoGenerated)
            .ToListAsync();
        foreach (var group in autoGroups)
        {
            RoleAssignmentHelper.AssignBuiltInRoleToGroup(_db, group, group.TemplateName!);
        }

        _db.SshCaKeys.Add(entity);

        if (entity.IsUserCa)
        {
            _db.SshSigningProfiles.Add(new SshSigningProfileEntity
            {
                Name = $"{entity.Name} - User Signing",
                Description = $"Auto-generated user signing profile for {entity.Name}",
                SshCaKeyId = entity.Id,
                AllowUserCerts = true,
                AllowHostCerts = false,
                MaxValidityHours = entity.MaxValidityHours,
                DefaultExtensions = JsonSerializer.Serialize(SshCaKeyDefaults.UserSigningDefaultExtensions),
                SourceAddressRestrictions = "[]",
            });
        }
        if (entity.IsHostCa)
        {
            _db.SshSigningProfiles.Add(new SshSigningProfileEntity
            {
                Name = $"{entity.Name} - Host Signing",
                Description = $"Auto-generated host signing profile for {entity.Name}",
                SshCaKeyId = entity.Id,
                AllowUserCerts = false,
                AllowHostCerts = true,
                MaxValidityHours = entity.MaxValidityHours,
                DefaultExtensions = "[]",
                SourceAddressRestrictions = "[]",
            });
        }
        await _db.SaveChangesAsync();
    }

    /// <summary>
    /// Stops tracking the rows of an SSH CA whose transaction was rolled back, so that a later
    /// save on this context does not write them after all.
    /// </summary>
    private void ForgetRows(Guid caId, Guid keyId)
    {
        var groupIds = _db.ChangeTracker.Entries<CaGroupEntity>()
            .Where(e => e.Entity.CertificateAuthorityId == caId).Select(e => e.Entity.Id).ToHashSet();
        foreach (var entry in _db.ChangeTracker.Entries().ToList())
        {
            var ours = entry.Entity switch
            {
                CertificateAuthorityEntity ca => ca.Id == caId,
                CaGroupEntity group => groupIds.Contains(group.Id),
                RoleAssignmentEntity assignment => assignment.GroupId is Guid g && groupIds.Contains(g),
                CapabilityGrantEntity grant => groupIds.Contains(grant.GroupId),
                SshCaKeyEntity key => key.Id == keyId,
                SshSigningProfileEntity profile => profile.SshCaKeyId == keyId,
                _ => false,
            };
            if (ours)
                entry.State = EntityState.Detached;
        }
    }

    /// <summary>
    /// Deletes the rows <see cref="WriteRowsAsync"/> wrote, after the signer did not commit the
    /// key they were written for: the signing profiles, the key row, the groups with their roles
    /// and grants, and the CA row.
    /// </summary>
    private async Task RemoveRowsAsync(Guid caId, Guid keyId)
    {
        _db.SshSigningProfiles.RemoveRange(await _db.SshSigningProfiles.Where(p => p.SshCaKeyId == keyId).ToListAsync());
        _db.SshCaKeys.RemoveRange(await _db.SshCaKeys.Where(k => k.Id == keyId).ToListAsync());

        var groups = await _db.CaGroups.Where(g => g.CertificateAuthorityId == caId).ToListAsync();
        var groupIds = groups.Select(g => g.Id).ToList();
        _db.RoleAssignments.RemoveRange(await _db.RoleAssignments.Where(a => a.GroupId != null && groupIds.Contains(a.GroupId.Value)).ToListAsync());
        _db.CapabilityGrants.RemoveRange(await _db.CapabilityGrants.Where(g => groupIds.Contains(g.GroupId)).ToListAsync());
        _db.CaGroups.RemoveRange(groups);

        _db.CertificateAuthorities.RemoveRange(await _db.CertificateAuthorities.IgnoreQueryFilters().Where(c => c.Id == caId).ToListAsync());
        await _db.SaveChangesAsync();
    }

    /// <summary>
    /// Retires a pending key after a failure, best effort: the failure being unwound is the one
    /// to report, and a key that cannot be retired is logged, not thrown.
    /// </summary>
    private async Task RetireQuietlyAsync(KeyRef key, SigningContext context)
    {
        try
        {
            await _signer.RetireKeyAsync(key, context);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Pending key {Key} could not be retired after a failed SSH CA creation.", key);
        }
    }

    /// <summary>
    /// Disables an SSH CA key and its CA, and revokes all active certificates issued by it, all
    /// at one recorded time. No key is touched: the signer refuses to sign for a disabled row,
    /// and the key stays where it is.
    /// </summary>
    public async Task DisableAsync(Guid caKeyId, SshCaActor? actor = null, Guid? ceremonyId = null)
    {
        var key = await _db.SshCaKeys.FindAsync(caKeyId)
            ?? throw new InvalidOperationException("SSH CA key not found.");

        key.IsEnabled = false;

        var caEntity = await _db.CertificateAuthorities.FindAsync(key.CertificateAuthorityId);
        if (caEntity != null)
            caEntity.IsEnabled = false;

        var activeCerts = await _db.SshCertificates
            .Where(c => c.SshCaKeyId == caKeyId && !c.IsRevoked)
            .ToListAsync();

        var now = DateTime.UtcNow;
        foreach (var cert in activeCerts)
            cert.Revoke(now);

        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshCaKeyDisabled, actor?.UserId, actor?.Username ?? "system",
            "SshCaKey", caKeyId.ToString(),
            new { key.Name, RevokedCertificates = activeCerts.Count, CeremonyId = ceremonyId }, actor?.SourceIp);
        _logger.LogWarning("SSH CA key '{Name}' disabled. {Count} certificate(s) revoked.", key.Name, activeCerts.Count);
    }

    /// <summary>
    /// Moves the advisory review date of an SSH CA key (<see cref="SshCaKeyEntity.ReviewBy"/>)
    /// and writes the audit entry. The date must be in the future and at most
    /// <see cref="SshCaKeyDefaults.MaxReviewYearsAhead"/> years ahead. Only that column changes:
    /// the key, its limits, its certificates and its KRL are as they were.
    /// </summary>
    /// <returns>The key with its new date, or null when there is no such key.</returns>
    /// <exception cref="InvalidRequestException">The date is not in the future, or is too far ahead.</exception>
    public async Task<SshCaKeyEntity?> SetReviewByAsync(Guid caKeyId, DateTime reviewBy, SshCaActor? actor = null)
    {
        if (SshCaKeyDefaults.ReviewByError(reviewBy, DateTime.UtcNow) is { } problem)
            throw new InvalidRequestException(problem);

        var key = await _db.SshCaKeys.FindAsync(caKeyId);
        if (key == null)
            return null;

        var was = key.ReviewBy;
        key.ReviewBy = reviewBy.Kind == DateTimeKind.Local ? reviewBy.ToUniversalTime() : DateTime.SpecifyKind(reviewBy, DateTimeKind.Utc);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshCaKeyReviewDateChanged, actor?.UserId, actor?.Username ?? "system",
            "SshCaKey", caKeyId.ToString(),
            new { SshCaKeyName = key.Name, key.ReviewBy, Was = was },
            actor?.SourceIp, certificateAuthorityId: key.CertificateAuthorityId);
        return key;
    }

    /// <summary>
    /// Refuses with <see cref="ConfigurationValidationException"/> when the SSH CA key, or the
    /// certificate authority it belongs to, is disabled or deleted.
    /// </summary>
    private async Task EnsureSshCaUsableAsync(SshCaKeyEntity caKey)
    {
        if (!caKey.IsEnabled)
            throw new ConfigurationValidationException(
                $"SSH CA key '{caKey.Name}' is disabled and cannot sign.", ErrorCodes.IssuingCaDisabled);

        var ca = await _db.CertificateAuthorities
            .FirstOrDefaultAsync(c => c.Id == caKey.CertificateAuthorityId);
        if (ca == null || ca.IsDeleted || !ca.IsEnabled)
            throw new ConfigurationValidationException(
                $"The certificate authority for SSH CA key '{caKey.Name}' is disabled or deleted; the key cannot sign.",
                ErrorCodes.IssuingCaDisabled);
    }

    /// <summary>
    /// Signs a user public key under the given SSH CA key, through the signer. Refuses a
    /// disabled or deleted CA, a key that does not sign user certificates, and a key that still
    /// awaits its import into the signer. The key id is written from <paramref name="subject"/>
    /// (<see cref="SshKeyIds"/>). For a user, the user must exist, be active and be one the SSH CA
    /// may refer to, every principal must be a login name that user holds on the key, and the
    /// certificate ends no later than those names allow (<see cref="SshLoginNameHolding"/>). For a
    /// service identity the principals are as the caller checked them. The certificate carries
    /// exactly <paramref name="extensions"/> (see <see cref="SshCertificateOptions"/>).
    /// </summary>
    public Task<SshCertificateEntity> SignUserKeyAsync(Guid caKeyId, string publicKey, SshCertificateSubject subject, List<string> principals,
        int? validityHours, List<string>? extensions, SshCaActor? actor = null, int? profileMaxValidityHours = null)
    {
        ArgumentNullException.ThrowIfNull(subject);
        return SignAsync(caKeyId, publicKey, subject, principals, validityHours, profileMaxValidityHours, extensions, SshCertificateType.User, actor);
    }

    /// <summary>
    /// Signs a host public key under the given SSH CA key, through the signer. Refuses a
    /// disabled or deleted CA, a key that does not sign host certificates, and a key that still
    /// awaits its import into the signer. The key id is the first hostname. A host certificate
    /// carries no options.
    /// </summary>
    public Task<SshCertificateEntity> SignHostKeyAsync(Guid caKeyId, string publicKey, List<string> hostnames,
        int? validityHours, SshCaActor? actor = null, int? profileMaxValidityHours = null)
        => SignAsync(caKeyId, publicKey, null, hostnames, validityHours, profileMaxValidityHours, null, SshCertificateType.Host, actor);

    /// <summary>
    /// The key id the CA would write for <paramref name="subject"/>: the username of an existing,
    /// active user, or <c>svc:</c> and the label of a service identity.
    /// </summary>
    public async Task<string> KeyIdOfAsync(SshCertificateSubject subject)
    {
        ArgumentNullException.ThrowIfNull(subject);
        return subject.UserId is Guid userId
            ? SshKeyIds.ForUser((await SubjectUserAsync(userId)).Username)
            : SshKeyIds.ForService(subject.ServiceLabel);
    }

    /// <summary>The user a certificate is asked for, who must exist and be active.</summary>
    /// <exception cref="InvalidRequestException">There is no such user, or the user is not active.</exception>
    private async Task<(Guid Id, string Username)> SubjectUserAsync(Guid userId)
    {
        var user = await _db.Users.AsNoTracking().Where(u => u.Id == userId).Select(u => new { u.Id, u.Username, u.IsActive }).FirstOrDefaultAsync();
        if (user == null || !user.IsActive)
            throw new InvalidRequestException(SubjectRefused);
        return (user.Id, user.Username);
    }

    /// <summary>One sentence for a subject that is unknown, inactive or out of the SSH CA's scope, so the answer does not say which.</summary>
    private const string SubjectRefused =
        "The user this certificate is for does not exist, is not active, or has no membership, role or grant in this SSH CA's scope.";

    /// <summary>The refusal for a subject the SSH CA may refer to but who holds no cert.request on it.</summary>
    private const string SubjectMayNotRequest =
        "The user this certificate is for may not request certificates from this SSH CA, so none is issued for them. "
        + "Give the user a role on the SSH CA that lets them request.";

    /// <summary>
    /// What both certificate types share. Which profiles apply was decided by the caller; this
    /// checks the subject key and the CA key's row, writes the key id, issues for a user only
    /// while that user may request from the SSH CA, holds a user certificate to the login names
    /// its subject holds, picks a serial no certificate of the CA key has, and
    /// asks the signer for the certificate under an <see cref="SigningPurpose.SshCertificate"/>
    /// context naming the SSH CA at instance scope.
    /// </summary>
    /// <remarks>
    /// The principals and the options reach the signer exactly as given: nothing is rewritten on
    /// the way, so what was approved is what is certified, and what the signer's rules refuse is
    /// refused with its reason. The row stored is read back from the certificate the signer
    /// returned (serial, key id, principals, validity, options, subject key), never from the
    /// request, together with who the certificate is for and why that subject held each login
    /// name. The certificate is signed before it is stored; should the save then fail, the
    /// signer's own audit still holds the certificate's hash, serial and key id.
    /// </remarks>
    private async Task<SshCertificateEntity> SignAsync(Guid caKeyId, string publicKey, SshCertificateSubject? certificateFor, List<string> principals,
        int? validityHours, int? profileMaxValidityHours, List<string>? extensions, SshCertificateType type, SshCaActor? actor)
    {
        var subject = ParseSubjectKey(publicKey);
        principals ??= [];
        var typeName = type == SshCertificateType.Host ? SshCertificateRequest.HostType : SshCertificateRequest.UserType;

        var caKey = await _db.SshCaKeys.FindAsync(caKeyId)
            ?? throw new InvalidOperationException("SSH CA key not found");
        await EnsureSshCaUsableAsync(caKey);
        if (type == SshCertificateType.User && !caKey.IsUserCa)
            throw new ConfigurationValidationException($"SSH CA key '{caKey.Name}' is not configured for user certificates.");
        if (type == SshCertificateType.Host && !caKey.IsHostCa)
            throw new ConfigurationValidationException($"SSH CA key '{caKey.Name}' is not configured for host certificates.");

        var caPublicKey = TryParseCaKey(caKey.PublicKey);
        if (caPublicKey != null && SshCertificateRules.CheckSubjectKey(subject, caPublicKey) is { } keyProblem)
            throw new InvalidRequestException(keyProblem);

        (Guid Id, string Username)? subjectUser = null;
        string? serviceLabel = null;
        string certKeyId;
        if (type == SshCertificateType.Host)
        {
            certKeyId = SshKeyIds.ForHost(principals);
        }
        else if (certificateFor!.UserId is Guid subjectUserId)
        {
            subjectUser = await SubjectUserAsync(subjectUserId);
            certKeyId = SshKeyIds.ForUser(subjectUser.Value.Username);
        }
        else
        {
            serviceLabel = certificateFor.ServiceLabel;
            certKeyId = SshKeyIds.ForService(serviceLabel);
        }

        int serial;
        do
        {
            serial = RandomNumberGenerator.GetInt32(1, int.MaxValue);
        } while (await _db.SshCertificates.AnyAsync(c => c.SshCaKeyId == caKey.Id && c.SerialNumber == serial));

        // What a failure entry says: never a principal, so not a host certificate's key id, which is one.
        var asked = new
        {
            CertificateType = typeName, KeyId = type == SshCertificateType.Host ? null : certKeyId, SerialNumber = (long)serial,
            PrincipalCount = principals.Count,
            SubjectUserId = subjectUser?.Id, SubjectUsername = subjectUser?.Username, ServiceLabel = serviceLabel,
        };

        var validAfter = DateTimeOffset.UtcNow.Subtract(ValidAfterBackdate).ToUnixTimeSeconds();
        var startsAt = DateTimeOffset.FromUnixTimeSeconds(validAfter).UtcDateTime;
        var limitHours = Math.Min(caKey.MaxValidityHours, profileMaxValidityHours ?? caKey.MaxValidityHours);
        SshLoginNameIssuance? names = null;
        IReadOnlyList<SshLoginNameGround>? grounds = null;
        if (subjectUser is { } forUser)
        {
            try
            {
                if (!await _loginNames.MayReferenceUserAsync(caKey.Id, forUser.Id))
                    throw new InvalidRequestException(SubjectRefused);
                if (!await _loginNames.MayRequestAsync(forUser.Id, caKey.Id))
                    throw new InvalidRequestException(SubjectMayNotRequest);
                names = await _loginNames.ForIssuanceAsync(forUser.Id, caKey.Id, principals, startsAt);
                grounds = names.Grounds;
            }
            catch (InvalidRequestException)
            {
                await AuditFailureAsync(AuditActionType.SshCertIssued, actor, "SshCaKey", caKey.Id.ToString(), asked,
                    new InvalidRequestException(
                        "The subject does not hold a login name asked for, may not request from the SSH CA, or the SSH CA may not refer to the subject."));
                throw;
            }
        }
        else if (type == SshCertificateType.User)
        {
            grounds = SshLoginNameHolding.Typed(principals);
        }
        var endsAt = new DateTimeOffset(SshLoginNameHolding.ValidBefore(startsAt, validityHours, limitHours, names)).ToUnixTimeSeconds();

        if (caKey.KeyStorage == SshCaKeyStorage.LegacyFile)
        {
            var awaiting = new SshCaKeyUnavailableException(
                $"{SshCaKeyUnavailableException.AwaitingImport}: '{caKey.Name}' is still a key file on the node, and signs nothing until it has been imported.");
            await AuditFailureAsync(AuditActionType.SshCertIssued, actor, "SshCaKey", caKey.Id.ToString(), asked, awaiting);
            throw awaiting;
        }

        var (criticalOptions, certExtensions) = SshCertificateOptions.From(type == SshCertificateType.Host ? null : extensions);
        var request = new SshCertificateRequest(
            new KeyRef(caKey.Id, KeyRef.SshKeystore), subject.Blob, typeName, (ulong)serial, certKeyId, principals.ToList(),
            validAfter, endsAt, criticalOptions, certExtensions);
        var context = SigningContext.ForCa(SignerCaller, SigningPurpose.SshCertificate, caKey.CertificateAuthorityId, spaceId: null);

        byte[] blob;
        try
        {
            blob = await _signer.SignSshCertificateAsync(request, context);
        }
        catch (SigningRefusedException ex)
        {
            await AuditFailureAsync(AuditActionType.SshCertIssued, actor, "SshCaKey", caKey.Id.ToString(), asked, ex);
            var translated = SshSignerRefusals.ForSigning(ex, caKey.Name);
            if (ReferenceEquals(translated, ex))
                throw;
            throw translated;
        }

        var certificate = SshCertificate.Parse(blob);
        var issued = certificate.Fields;
        if (!issued.SubjectKey.Equals(subject) || issued.Serial != (ulong)serial
            || (caPublicKey != null && !certificate.SignatureKey.Equals(caPublicKey)))
        {
            _logger.LogError(
                "The signer returned an SSH certificate that is not the one asked of SSH CA key {CaKeyId}: serial {Serial} (asked {Asked}), SHA-256 {Hash}. It was not stored.",
                caKey.Id, issued.Serial, serial, Convert.ToHexString(SHA256.HashData(blob)));
            throw new InvalidOperationException("The signer returned an SSH certificate that is not the one asked for; it was not stored.");
        }

        var comment = CommentOf(subject.Comment ?? issued.KeyId);
        var options = SshCertificateOptions.Describe(issued.CriticalOptions, issued.Extensions);
        var entity = new SshCertificateEntity
        {
            SshCaKeyId = caKey.Id,
            CertificateType = issued.Type == SshCertificateType.Host ? SshCertificateRequest.HostType : SshCertificateRequest.UserType,
            KeyId = issued.KeyId,
            SerialNumber = (long)issued.Serial,
            Principals = JsonSerializer.Serialize(issued.Principals),
            ValidAfter = TimeOf(issued.ValidAfter),
            ValidBefore = TimeOf(issued.ValidBefore),
            PublicKey = issued.SubjectKey.ToAuthorizedKey(comment),
            SignedCertificate = SshCertificate.ToOpenSsh(blob, comment),
            Extensions = options.Count > 0 ? JsonSerializer.Serialize(options) : null,
            IssuedByUserId = actor?.UserId,
            SubjectUserId = subjectUser?.Id,
            LoginNameGrounds = grounds == null ? null : SshLoginNameHolding.Serialize(grounds),
            SourceIp = actor?.SourceIp,
        };

        _db.SshCertificates.Add(entity);
        try
        {
            await _db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "An SSH {Type} certificate was signed by SSH CA key {CaKeyId} and could not be stored: serial {Serial}, SHA-256 {Hash}. The signer's audit holds it.",
                entity.CertificateType, caKey.Id, entity.SerialNumber, Convert.ToHexString(SHA256.HashData(blob)));
            throw;
        }

        await _audit.LogAsync(AuditActionType.SshCertIssued, actor?.UserId, actor?.Username,
            "SshCertificate", entity.Id.ToString(),
            new
            {
                entity.CertificateType, entity.KeyId, entity.SerialNumber, entity.Principals,
                SubjectUserId = subjectUser?.Id, SubjectUsername = subjectUser?.Username, ServiceLabel = serviceLabel,
            },
            actor?.SourceIp);
        _logger.LogInformation("SSH {Type} cert issued: KeyId={KeyId}, Serial={Serial}, Principals={Principals}",
            entity.CertificateType, entity.KeyId, entity.SerialNumber, string.Join(",", issued.Principals));

        return entity;
    }

    /// <summary>Returns the public key of an SSH CA key, as an authorized_keys line.</summary>
    public async Task<string> GetPublicKeyAsync(Guid caKeyId)
    {
        var caKey = await _db.SshCaKeys.FindAsync(caKeyId)
            ?? throw new InvalidOperationException("SSH CA key not found");
        return caKey.PublicKey;
    }

    /// <summary>Lists the SSH CA keys, by name.</summary>
    public async Task<List<SshCaKeyEntity>> GetCaKeysAsync()
    {
        return await _db.SshCaKeys.AsNoTracking().OrderBy(k => k.Name).ToListAsync();
    }

    /// <summary>
    /// Lists issued SSH certificates with pagination, optionally filtered by CA key.
    /// </summary>
    public async Task<List<SshCertificateEntity>> GetCertificatesAsync(int page = 1, int pageSize = 50, Guid? caKeyId = null, string? sort = null)
    {
        var query = _db.SshCertificates.AsNoTracking().AsQueryable();
        if (caKeyId.HasValue)
            query = query.Where(c => c.SshCaKeyId == caKeyId.Value);
        return await Ordered(query, sort)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync();
    }

    /// <summary>
    /// Orders certificate rows as the certificate lists do: by <c>createdAt</c> (the default,
    /// newest first), <c>keyId</c> or <c>validBefore</c>, descending with a leading <c>-</c>.
    /// An unknown field is the default.
    /// </summary>
    internal static IOrderedQueryable<SshCertificateEntity> Ordered(IQueryable<SshCertificateEntity> query, string? sort)
        => ListSort.Parse(sort, "createdAt", "keyId", "validBefore") switch
        {
            ("keyId", false) => query.OrderBy(c => c.KeyId),
            ("keyId", true) => query.OrderByDescending(c => c.KeyId),
            ("validBefore", false) => query.OrderBy(c => c.ValidBefore),
            ("validBefore", true) => query.OrderByDescending(c => c.ValidBefore),
            ("createdAt", false) => query.OrderBy(c => c.CreatedAt),
            _ => query.OrderByDescending(c => c.CreatedAt),
        };

    /// <summary>
    /// Revokes an SSH certificate, optionally constrained to the CA key that issued it, records
    /// when (<see cref="SshCertificateEntity.Revoke"/>), and writes the audit entry when it did.
    /// A certificate that is already revoked keeps the time it has.
    /// </summary>
    /// <param name="certId">The certificate to revoke.</param>
    /// <param name="requiredCaKeyId">
    /// When set, the certificate must belong to this CA key or the call is refused.
    /// </param>
    /// <param name="actor">Who asked, for the audit entry.</param>
    /// <remarks>
    /// The admin route is <c>ca-keys/{caKeyId}/certificates/{id}/revoke</c> and the authorization
    /// handler resolves the CA from <c>caKeyId</c> — the caller's OWN key. Nothing then checked
    /// that <c>{id}</c> belonged to it, and SshCertificateEntity carries no space query filter,
    /// so cert.revoke on any one SSH CA was enough to revoke every SSH certificate in the
    /// deployment, one id at a time.
    /// </remarks>
    public async Task<bool> RevokeCertificateAsync(Guid certId, Guid? requiredCaKeyId = null, SshCaActor? actor = null)
    {
        var cert = await _db.SshCertificates.FindAsync(certId);
        if (cert == null) return false;
        if (requiredCaKeyId.HasValue && cert.SshCaKeyId != requiredCaKeyId.Value) return false;
        cert.Revoke(DateTime.UtcNow);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SshCertRevoked, actor?.UserId, actor?.Username,
            "SshCertificate", certId.ToString(), sourceIp: actor?.SourceIp);
        return true;
    }

    /// <summary>
    /// Retrieves a single SSH certificate by its unique identifier.
    /// </summary>
    public async Task<SshCertificateEntity?> GetCertificateByIdAsync(Guid certId)
    {
        return await _db.SshCertificates.AsNoTracking().FirstOrDefaultAsync(c => c.Id == certId);
    }

    /// <summary>
    /// Builds the binary KRL (key revocation list) of an SSH CA key: a certificate section for
    /// the CA public key listing the serials of its revoked certificates. It is built here from
    /// the public key on the row. A KRL is not signed, so no signer and no private key take
    /// part, and a host that only validates builds it as any other does.
    /// </summary>
    /// <remarks>
    /// With nothing revoked the result follows <see cref="ServeKrlWithNoEntries"/>: a KRL with
    /// no entries, or no bytes at all. Nothing is written to the audit: the list is public,
    /// the public route is anonymous and asked by every server on a timer, and what changes a
    /// KRL, a revocation, has its own entry.
    /// </remarks>
    public async Task<byte[]> GenerateKrlAsync(Guid caKeyId) => (await BuildKrlAsync(caKeyId)).Bytes;

    /// <summary>
    /// Builds the KRL of an SSH CA key together with what it says about itself. The bytes are
    /// the same on every call until a certificate of the key is revoked: the version is the
    /// number of revoked certificates and the generation time is that of the newest revocation
    /// (<see cref="KrlGeneratedAt"/>), never the time of the call. The ETag is computed from
    /// the rows this KRL was built from, so it never names bytes other than these.
    /// </summary>
    /// <exception cref="InvalidOperationException">There is no such key, or its public key cannot be read.</exception>
    public async Task<SshKrlFile> BuildKrlAsync(Guid caKeyId)
    {
        var caKey = await _db.SshCaKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == caKeyId)
            ?? throw new InvalidOperationException("SSH CA key not found");

        var revoked = await _db.SshCertificates.AsNoTracking()
            .Where(c => c.SshCaKeyId == caKeyId && c.IsRevoked)
            .Select(c => new { c.SerialNumber, c.RevokedAt })
            .ToListAsync();

        if (revoked.Count == 0 && !ServeKrlWithNoEntries)
            return new SshKrlFile(Array.Empty<byte>(), null);

        var caPublicKey = TryParseCaKey(caKey.PublicKey)
            ?? throw new InvalidOperationException(KrlKeyUnreadable);

        var state = KrlStateOf(caKey.Id, caPublicKey, caKey.CreatedAt, revoked.Count, revoked.Max(c => c.RevokedAt));
        var bytes = SshKrl.Encode(caPublicKey, revoked.Select(c => unchecked((ulong)c.SerialNumber)), state.Version,
            new DateTimeOffset(state.GeneratedAt));
        return new SshKrlFile(bytes, state);
    }

    /// <summary>
    /// What the KRL of an SSH CA key says about itself now, read without building it: one query
    /// for the key, the number of its revoked certificates and the newest revocation time.
    /// </summary>
    /// <exception cref="InvalidOperationException">There is no such key, or its public key cannot be read.</exception>
    public async Task<SshKrlState> GetKrlStateAsync(Guid caKeyId)
    {
        var rows = await KrlRowsAsync(_db.SshCaKeys.Where(k => k.Id == caKeyId));
        if (rows.Count == 0)
            throw new InvalidOperationException("SSH CA key not found");
        return rows[0].State ?? throw new InvalidOperationException(KrlKeyUnreadable);
    }

    /// <summary>
    /// The KRL state of each of <paramref name="caKeyIds"/>, in one query. A key that does not
    /// exist, or whose public key cannot be read, is left out.
    /// </summary>
    public async Task<IReadOnlyDictionary<Guid, SshKrlState>> GetKrlStatesAsync(IReadOnlyCollection<Guid> caKeyIds)
    {
        var ids = caKeyIds.Distinct().ToList();
        if (ids.Count == 0)
            return new Dictionary<Guid, SshKrlState>();
        return (await KrlRowsAsync(_db.SshCaKeys.Where(k => ids.Contains(k.Id))))
            .Where(r => r.State != null)
            .ToDictionary(r => r.Id, r => r.State!);
    }

    /// <summary>What both KRL reads say of a key row whose public key cannot be parsed.</summary>
    private const string KrlKeyUnreadable ="The public key of the SSH CA key cannot be read, so no KRL can be built for it.";

    /// <summary>Reads, for each of <paramref name="keys"/>, what its KRL state is computed from; the state is null for an unreadable public key.</summary>
    private async Task<List<(Guid Id, SshKrlState? State)>> KrlRowsAsync(IQueryable<SshCaKeyEntity> keys)
    {
        var rows = await keys.AsNoTracking()
            .Select(k => new
            {
                k.Id,
                k.PublicKey,
                k.CreatedAt,
                Revoked = _db.SshCertificates.Count(c => c.SshCaKeyId == k.Id && c.IsRevoked),
                LastRevokedAt = _db.SshCertificates.Where(c => c.SshCaKeyId == k.Id && c.IsRevoked).Max(c => c.RevokedAt),
            })
            .ToListAsync();
        return rows
            .Select(r => (r.Id, TryParseCaKey(r.PublicKey) is { } key ? KrlStateOf(r.Id, key, r.CreatedAt, r.Revoked, r.LastRevokedAt) : null))
            .ToList();
    }

    /// <summary>The state of a KRL of <paramref name="caKey"/> with <paramref name="revokedCertificates"/> entries, the newest revoked at <paramref name="lastRevokedAt"/>.</summary>
    private static SshKrlState KrlStateOf(Guid caKeyId, SshPublicKey caKey, DateTime keyCreatedAt, int revokedCertificates, DateTime? lastRevokedAt)
    {
        var version = KrlVersionOf(revokedCertificates);
        var newest = lastRevokedAt is { } at ? DateTime.SpecifyKind(at, DateTimeKind.Utc) : (DateTime?)null;
        var generatedAt = KrlGeneratedAt(newest, keyCreatedAt);
        return new SshKrlState(caKeyId, version, revokedCertificates, generatedAt.UtcDateTime, newest, KrlETagOf(caKey, version, generatedAt));
    }

    /// <summary>
    /// The <c>krl_version</c> of a KRL listing <paramref name="revokedCertificates"/> serials:
    /// their number. It is zero for an empty list and goes up by one with each revocation, and
    /// it never goes down in operation, since a revocation is never undone and a certificate
    /// row is never deleted. Restoring an older database is the one thing that lowers it.
    /// </summary>
    internal static ulong KrlVersionOf(int revokedCertificates) => (ulong)Math.Max(0, revokedCertificates);

    /// <summary>
    /// The generation time a KRL carries, in whole seconds: the time of the newest revocation
    /// known. With none known (nothing revoked, or only certificates revoked before the time
    /// was recorded) it is when the SSH CA key was created, which never changes. It is never
    /// the time of the request, so the same list is the same bytes.
    /// </summary>
    internal static DateTimeOffset KrlGeneratedAt(DateTime? lastRevokedAt, DateTime keyCreatedAt)
    {
        var at = new DateTimeOffset(DateTime.SpecifyKind(lastRevokedAt ?? keyCreatedAt, DateTimeKind.Utc));
        return DateTimeOffset.FromUnixTimeSeconds(Math.Max(0, at.ToUnixTimeSeconds()));
    }

    /// <summary>
    /// The strong ETag of a KRL: a hash of its header (version and generation time) and the CA
    /// public key, in quotes. A revocation raises the version, so the ETag changes exactly when
    /// the bytes do, and it needs no serial to compute.
    /// </summary>
    internal static string KrlETagOf(SshPublicKey caKey, ulong version, DateTimeOffset generatedAt)
    {
        var header = SshKrl.Encode(caKey, [], version, generatedAt);
        var hash = SHA256.HashData([.. header, .. caKey.Blob]);
        return $"\"{Convert.ToHexStringLower(hash.AsSpan(0, 16))}\"";
    }

    /// <summary>
    /// Writes the audit entry of an operation that failed, without letting a failure to write it
    /// replace the failure being reported. The entry never names a principal.
    /// </summary>
    private async Task AuditFailureAsync(string action, SshCaActor? actor, string targetType, string? targetId, object details, Exception failure)
    {
        try
        {
            await _audit.LogAsync(action, actor?.UserId, actor?.Username ?? "system", targetType, targetId, details,
                actor?.SourceIp, success: false, errorMessage: failure.Message);
        }
        catch (Exception auditFailure)
        {
            _logger.LogWarning(auditFailure, "The audit entry for a failed {Action} could not be written.", action);
        }
    }

    /// <summary>
    /// The algorithm of a new SSH CA key, from the key type and size a request names:
    /// <c>ed25519</c>; <c>ecdsa</c> on P-256, P-384 or P-521 (256 when no size is given); or
    /// <c>rsa</c> of 2048, 3072, 4096, 7680 or 8192 bits (3072 when no size is given).
    /// </summary>
    /// <exception cref="ArgumentException">The type is none of the three, or the size is not one of its sizes.</exception>
    private static SshCaAlgorithm AlgorithmOf(string keyType, int? keySize)
    {
        switch ((keyType ?? string.Empty).ToLowerInvariant())
        {
            case "ed25519":
                return new SshCaAlgorithm("ed25519", null, "Ed25519", string.Empty, SshKeyTypes.Ed25519);
            case "ecdsa":
                var curve = keySize ?? 256;
                if (!EcdsaSizes.Contains(curve))
                    throw new ArgumentException($"Key size {keySize} is not allowed for ecdsa. Allowed: {string.Join(", ", EcdsaSizes)}");
                return new SshCaAlgorithm("ecdsa", curve, "ECDSA", $"P-{curve}", $"ecdsa-sha2-nistp{curve}");
            case "rsa":
                var bits = keySize ?? 3072;
                if (!RsaSizes.Contains(bits))
                    throw new ArgumentException($"Key size {keySize} is not allowed for rsa. Allowed: {string.Join(", ", RsaSizes)}");
                return new SshCaAlgorithm("rsa", bits, "RSA", bits.ToString(), SshKeyTypes.Rsa);
            default:
                throw new ArgumentException($"Unsupported key type: {keyType}");
        }
    }

    /// <summary>
    /// What a key type and size come to: the type and size the row stores, the algorithm and
    /// size or curve the signer is asked for, and the OpenSSH key type the result must have.
    /// </summary>
    private sealed record SshCaAlgorithm(string KeyType, int? KeySize, string Algorithm, string SizeOrCurve, string SshKeyType);

    /// <summary>
    /// Reads the public key a certificate is asked for: one authorized_keys line of a type that
    /// can be certified. Anything else is an <see cref="InvalidRequestException"/>, and so is a
    /// DSA key, which the parser reads only so that it can be named here.
    /// </summary>
    private static SshPublicKey ParseSubjectKey(string publicKey)
    {
        SshPublicKey subject;
        try
        {
            subject = SshPublicKey.ParseAuthorizedKey(publicKey ?? string.Empty);
        }
        catch (FormatException ex)
        {
            throw new InvalidRequestException($"The SSH public key cannot be used: {ex.Message}");
        }
        if (subject.KeyType == SshKeyTypes.Dss)
            throw new InvalidRequestException(
                "DSA (ssh-dss) public keys are not certified: OpenSSH no longer accepts DSA. Use an Ed25519, ECDSA or RSA key.");
        return subject;
    }

    /// <summary>The public key on an <c>SshCaKeys</c> row, or null when the row holds no key that can be read.</summary>
    private static SshPublicKey? TryParseCaKey(string? authorizedKey)
    {
        try
        {
            return SshPublicKey.ParseAuthorizedKey(authorizedKey ?? string.Empty);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>The fingerprint of the public key on a row, for the audit entry; null when it cannot be read.</summary>
    private static string? FingerprintOf(string authorizedKey) => TryParseCaKey(authorizedKey)?.Fingerprint;

    /// <summary>
    /// The comment written after a stored public key or certificate, which an operator reads
    /// and pastes into a file of one key to a line: letters, digits, spaces and <c>- _ . @</c>
    /// only, at most <see cref="MaxCommentLength"/> characters, and null when nothing is left.
    /// </summary>
    private static string? CommentOf(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        var kept = new string(text.Where(c => char.IsLetterOrDigit(c) || c is ' ' or '-' or '_' or '.' or '@').ToArray()).Trim();
        if (kept.Length > MaxCommentLength)
            kept = kept[..MaxCommentLength];
        return kept.Length == 0 ? null : kept;
    }

    /// <summary>A certificate's time, in Unix seconds, as the row stores it; a time past the calendar is its last moment.</summary>
    private static DateTime TimeOf(ulong unixSeconds)
        => unixSeconds >= (ulong)DateTimeOffset.MaxValue.ToUnixTimeSeconds()
            ? DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc)
            : DateTimeOffset.FromUnixTimeSeconds((long)unixSeconds).UtcDateTime;
}
