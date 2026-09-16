using System.Security.Cryptography;
using System.Text;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;

namespace ModularCA.Core.Services.Msae.Kerberos;

/// <summary>Which kind of Active Directory account holds the service principal. Decides the password salt.</summary>
public enum KerberosAccountKind
{
    /// <summary>A user (service) account: salt is the realm plus the case-exact account name.</summary>
    User,
    /// <summary>A computer account: salt is the realm plus <c>host</c> plus the lower-case host name.</summary>
    Computer,
}

/// <summary>The editable fields of a realm binding. The realm itself is fixed once keys exist.</summary>
public sealed record KerberosRealmSpec(
    string Realm,
    string? DnsDomain,
    string ServicePrincipal,
    Guid EnrollmentUserId,
    bool AllowMachines = true,
    bool AllowUsers = true,
    bool IsEnabled = true,
    string? Notes = null);

/// <summary>What an import accepted, and what it dropped.</summary>
/// <param name="Kvno">The key version the accepted keys carry.</param>
/// <param name="EncryptionTypes">Accepted encryption type names.</param>
/// <param name="Dropped">Entries ignored: other realms, other principals, non-AES types.</param>
/// <param name="Retired">Older key versions given a retirement time by this import.</param>
public sealed record KerberosKeyImportResult(int Kvno, IReadOnlyList<string> EncryptionTypes, int Dropped, int Retired);

/// <summary>
/// Manages realm bindings and their keys, and serves them to the acceptor. Keys live under Data
/// Protection and leave this class only as <see cref="KerberosKey"/> objects for validation;
/// there is no export. Import accepts a keytab or derives from a password with the Active
/// Directory salt rules, and a rotation keeps the previous version usable for a grace window.
/// </summary>
public sealed class KerberosRealmService(ModularCADbContext db, IDataProtectionProvider dataProtection, TimeProvider? time = null) : IKerberosRealmKeyProvider
{
    /// <summary>Data Protection purpose string for realm keys. Changing it orphans every stored key.</summary>
    public const string ProtectorPurpose = "ModularCA.Msae.KerberosRealmKey";

    /// <summary>How long a superseded key stays usable: the default maximum ticket lifetime in a forest.</summary>
    public static readonly TimeSpan RotationGrace = TimeSpan.FromHours(10);

    private static readonly HashSet<EncryptionType> AllowedTypes = new()
    {
        EncryptionType.AES128_CTS_HMAC_SHA1_96,
        EncryptionType.AES256_CTS_HMAC_SHA1_96,
    };

    private readonly IDataProtector _protector = dataProtection.CreateProtector(ProtectorPurpose);
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    // ── Acceptor side ──

    /// <inheritdoc />
    public async Task<KerberosRealmKeys?> FindAsync(string realm, CancellationToken cancellation = default)
    {
        var upper = realm.ToUpperInvariant();
        var entity = await db.KerberosRealms.AsNoTracking()
            .Include(r => r.Keys)
            .Include(r => r.EnrollmentUser)
            .FirstOrDefaultAsync(r => r.Realm == upper && r.IsEnabled, cancellation);
        if (entity == null)
            return null;

        var now = _time.GetUtcNow().UtcDateTime;
        var keys = entity.Keys
            .Where(k => k.RetireAfter == null || k.RetireAfter > now)
            .OrderByDescending(k => k.Kvno).ThenByDescending(k => k.CreatedAt)
            .Select(k => ToKey(entity, k))
            .ToList();

        return new KerberosRealmKeys(entity.Realm, entity.TenantId, entity.ServicePrincipal, entity.DnsDomain,
            entity.EnrollmentUserId, entity.EnrollmentUser?.Username ?? string.Empty, entity.AllowMachines, entity.AllowUsers, keys);
    }

    /// <summary>Records that a ticket from the realm was accepted.</summary>
    public async Task TouchAsync(string realm, CancellationToken cancellation = default)
    {
        var upper = realm.ToUpperInvariant();
        var entity = await db.KerberosRealms.FirstOrDefaultAsync(r => r.Realm == upper, cancellation);
        if (entity == null) return;
        entity.LastUsedAt = _time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellation);
    }

    // ── Management ──

    /// <summary>The tenant's bindings with their key versions, newest realm first.</summary>
    public Task<List<KerberosRealmEntity>> ListAsync(Guid tenantId)
        => db.KerberosRealms.AsNoTracking().Include(r => r.Keys).Include(r => r.EnrollmentUser)
            .Where(r => r.TenantId == tenantId).OrderBy(r => r.Realm).ToListAsync();

    /// <summary>One binding with its keys, or null.</summary>
    public Task<KerberosRealmEntity?> GetAsync(Guid id)
        => db.KerberosRealms.AsNoTracking().Include(r => r.Keys).Include(r => r.EnrollmentUser).FirstOrDefaultAsync(r => r.Id == id);

    /// <summary>Creates a binding. The realm must be new across every tenant.</summary>
    public async Task<KerberosRealmEntity> CreateAsync(Guid tenantId, KerberosRealmSpec spec)
    {
        var realm = NormalizeRealm(spec.Realm);
        if (await db.KerberosRealms.AnyAsync(r => r.Realm == realm))
            throw new InvalidOperationException($"Realm '{realm}' is already bound.");
        await ValidateSpecAsync(spec);

        var entity = new KerberosRealmEntity
        {
            TenantId = tenantId,
            Realm = realm,
            DnsDomain = NormalizeDnsDomain(spec.DnsDomain, realm),
            ServicePrincipal = NormalizeSpn(spec.ServicePrincipal),
            EnrollmentUserId = spec.EnrollmentUserId,
            AllowMachines = spec.AllowMachines,
            AllowUsers = spec.AllowUsers,
            IsEnabled = spec.IsEnabled,
            Notes = spec.Notes,
            CreatedAt = _time.GetUtcNow().UtcDateTime,
        };
        db.KerberosRealms.Add(entity);
        await db.SaveChangesAsync();
        return entity;
    }

    /// <summary>Updates the non-key fields. The realm name cannot change once a key exists, since keys are salted with it.</summary>
    public async Task<KerberosRealmEntity> UpdateAsync(Guid id, KerberosRealmSpec spec)
    {
        var entity = await db.KerberosRealms.Include(r => r.Keys).FirstOrDefaultAsync(r => r.Id == id)
            ?? throw new KeyNotFoundException("Realm binding not found.");
        var realm = NormalizeRealm(spec.Realm);
        if (realm != entity.Realm)
        {
            if (entity.Keys.Count > 0)
                throw new InvalidOperationException("The realm cannot be renamed while it has keys; create a new binding.");
            if (await db.KerberosRealms.AnyAsync(r => r.Realm == realm && r.Id != id))
                throw new InvalidOperationException($"Realm '{realm}' is already bound.");
            entity.Realm = realm;
        }
        await ValidateSpecAsync(spec);
        entity.DnsDomain = NormalizeDnsDomain(spec.DnsDomain, realm);
        entity.ServicePrincipal = NormalizeSpn(spec.ServicePrincipal);
        entity.EnrollmentUserId = spec.EnrollmentUserId;
        entity.AllowMachines = spec.AllowMachines;
        entity.AllowUsers = spec.AllowUsers;
        entity.IsEnabled = spec.IsEnabled;
        entity.Notes = spec.Notes;
        await db.SaveChangesAsync();
        return entity;
    }

    /// <summary>Deletes a binding and every key. Refused while a CA of the tenant has Kerberos on and this is its last enabled realm.</summary>
    public async Task DeleteAsync(Guid id)
    {
        var entity = await db.KerberosRealms.FirstOrDefaultAsync(r => r.Id == id)
            ?? throw new KeyNotFoundException("Realm binding not found.");
        var others = await db.KerberosRealms.AnyAsync(r => r.TenantId == entity.TenantId && r.Id != id && r.IsEnabled);
        if (!others)
        {
            var kerberosCas = await db.CaProtocolConfigs
                .Where(p => p.Protocol == MsaeEnrollmentService.Protocol && p.MsaeAllowKerberos && p.Ca!.TenantId == entity.TenantId)
                .Select(p => p.Ca!.Label).ToListAsync();
            if (kerberosCas.Count > 0)
                throw new InvalidOperationException($"Kerberos is enabled on {string.Join(", ", kerberosCas)}; disable it there first or bind another realm.");
        }
        db.KerberosRealms.Remove(entity);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Adds the AES keys of a keytab that name this realm's service principal. The file is not
    /// kept. Refuses a file with nothing usable.
    /// </summary>
    public async Task<KerberosKeyImportResult> ImportKeytabAsync(Guid id, byte[] keytab)
    {
        var entity = await LoadForKeysAsync(id);
        KeyTable table;
        try
        {
            table = new KeyTable(keytab);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("The file is not a keytab.", ex);
        }

        var accepted = new List<(int Kvno, EncryptionType Type, byte[] Key)>();
        var dropped = 0;
        foreach (var entry in table.Entries)
        {
            var principal = entry.Principal;
            var etype = entry.EncryptionType ?? entry.Key?.EncryptionType ?? EncryptionType.NULL;
            var matchesRealm = string.Equals(principal?.Realm, entity.Realm, StringComparison.OrdinalIgnoreCase);
            var matchesSpn = principal != null && string.Equals(string.Join("/", principal.Name ?? []), entity.ServicePrincipal, StringComparison.OrdinalIgnoreCase);
            if (!matchesRealm || !matchesSpn || !AllowedTypes.Contains(etype) || entry.Key == null)
            {
                dropped++;
                continue;
            }
            accepted.Add((entry.Version, etype, entry.Key.GetKey().ToArray()));
        }
        if (accepted.Count == 0)
            throw new InvalidOperationException($"The keytab holds no AES key for {entity.ServicePrincipal}@{entity.Realm}; {dropped} other entries were ignored.");

        var kvno = accepted.Max(a => a.Kvno);
        var newest = accepted.Where(a => a.Kvno == kvno).ToList();
        var retired = await StoreAsync(entity, kvno, newest.Select(a => (a.Type, a.Key)), KerberosKeySource.Keytab);
        return new KerberosKeyImportResult(kvno, newest.Select(a => a.Type.ToString()).Distinct().ToList(), dropped + accepted.Count - newest.Count, retired);
    }

    /// <summary>
    /// Derives the AES-128 and AES-256 keys the forest holds for the account, from its password
    /// and the Active Directory salt rules, and stores them under <paramref name="kvno"/>. The
    /// password is not kept.
    /// </summary>
    public async Task<KerberosKeyImportResult> ImportPasswordAsync(Guid id, string accountName, KerberosAccountKind kind, string password, int kvno, KerberosKeySource source = KerberosKeySource.Password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        if (kvno < 1) throw new ArgumentOutOfRangeException(nameof(kvno), "Key version numbers start at 1.");
        var entity = await LoadForKeysAsync(id);

        var keys = AllowedTypes.OrderByDescending(t => t).Select(t => (t, DeriveKey(entity, accountName, kind, password, t))).ToList();
        var retired = await StoreAsync(entity, kvno, keys, source);
        return new KerberosKeyImportResult(kvno, keys.Select(k => k.t.ToString()).ToList(), 0, retired);
    }

    /// <summary>
    /// Generates a strong password, derives and stores its keys, and returns the password once
    /// for the operator to set on the account. It is never stored or logged.
    /// </summary>
    public async Task<(KerberosKeyImportResult Result, string Password)> GeneratePasswordAsync(Guid id, string accountName, KerberosAccountKind kind, int kvno)
    {
        var password = GeneratePassword();
        var result = await ImportPasswordAsync(id, accountName, kind, password, kvno, KerberosKeySource.Generated);
        return (result, password);
    }

    /// <summary>Refuses a key version from now on. Used when compromise is suspected.</summary>
    public async Task RetireKeyAsync(Guid id, int kvno)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        var live = await db.KerberosRealmKeys
            .Where(k => k.RealmId == id && k.Kvno == kvno && (k.RetireAfter == null || k.RetireAfter > now))
            .ToListAsync();
        if (live.Count == 0)
            throw new KeyNotFoundException($"No live key with version {kvno}.");
        foreach (var key in live) key.RetireAfter = now;
        await db.SaveChangesAsync();
    }

    /// <summary>Removes keys whose retirement time has passed. Called by the cleanup job.</summary>
    public async Task<int> SweepRetiredKeysAsync(CancellationToken cancellation = default)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        var dead = await db.KerberosRealmKeys.Where(k => k.RetireAfter != null && k.RetireAfter <= now).ToListAsync(cancellation);
        db.KerberosRealmKeys.RemoveRange(dead);
        await db.SaveChangesAsync(cancellation);
        return dead.Count;
    }

    /// <summary>
    /// The PowerShell an operator runs in the forest, plus the Group Policy values, generated
    /// from the binding. The password line is included only when one was just generated.
    /// </summary>
    public static string SetupScript(KerberosRealmEntity realm, string tenantName, string? policyUrl, string? accountName, string? generatedPassword)
    {
        var account = string.IsNullOrWhiteSpace(accountName) ? "svc-modularca-enroll" : accountName.TrimEnd('$');
        var sb = new StringBuilder();
        sb.AppendLine($"# Generated by ModularCA for realm {realm.Realm} (tenant {tenantName})");
        sb.AppendLine("# Run in the forest as a domain administrator. Nothing here is a secret except the password line, if present.");
        sb.AppendLine();
        sb.AppendLine("# 1. Service account holding the enrollment SPN, AES only.");
        sb.AppendLine($"New-ADUser -Name {account} -SamAccountName {account} `");
        sb.AppendLine($"  -UserPrincipalName {account}@{realm.DnsDomain} `");
        sb.AppendLine("  -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true `");
        sb.AppendLine("  -KerberosEncryptionType AES128,AES256 `");
        sb.AppendLine(generatedPassword != null
            ? $"  -AccountPassword (ConvertTo-SecureString '{generatedPassword.Replace("'", "''")}' -AsPlainText -Force)"
            : "  -AccountPassword (Read-Host -AsSecureString 'Password entered in ModularCA')");
        sb.AppendLine($"setspn -S {realm.ServicePrincipal} {account}");
        sb.AppendLine();
        sb.AppendLine("# 2. Group Policy (Computer and/or User Configuration > Policies > Windows Settings > Security Settings > Public Key Policies)");
        sb.AppendLine("#    Certificate Services Client - Certificate Enrollment Policy:");
        sb.AppendLine($"#      URI:            {policyUrl ?? "https://<host>/msae/<ca-label>/cep"}");
        sb.AppendLine("#      Authentication: Windows integrated");
        sb.AppendLine("#    Certificate Services Client - Auto-Enrollment: Enabled, renew expired, update pending, remove revoked");
        sb.AppendLine("#    Trusted Root Certification Authorities: the tenant CA root");
        return sb.ToString();
    }

    // ── Internals ──

    private async Task<KerberosRealmEntity> LoadForKeysAsync(Guid id)
        => await db.KerberosRealms.Include(r => r.Keys).FirstOrDefaultAsync(r => r.Id == id)
            ?? throw new KeyNotFoundException("Realm binding not found.");

    /// <summary>Stores one key version. Same version and type replaces; older live versions get a retirement time. Returns how many were retired.</summary>
    private async Task<int> StoreAsync(KerberosRealmEntity entity, int kvno, IEnumerable<(EncryptionType Type, byte[] Key)> keys, KerberosKeySource source)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        foreach (var (type, key) in keys)
        {
            var existing = entity.Keys.Where(k => k.Kvno == kvno && k.EncryptionType == type.ToString()).ToList();
            foreach (var e in existing) db.KerberosRealmKeys.Remove(e);
            db.KerberosRealmKeys.Add(new KerberosRealmKeyEntity
            {
                RealmId = entity.Id,
                Kvno = kvno,
                EncryptionType = type.ToString(),
                ProtectedKey = Convert.ToBase64String(_protector.Protect(key)),
                Source = source,
                CreatedAt = now,
            });
        }

        var retired = 0;
        foreach (var older in entity.Keys.Where(k => k.Kvno < kvno && k.RetireAfter == null))
        {
            older.RetireAfter = now + RotationGrace;
            retired++;
        }
        await db.SaveChangesAsync();
        return retired;
    }

    private KerberosKey ToKey(KerberosRealmEntity realm, KerberosRealmKeyEntity key)
    {
        var raw = _protector.Unprotect(Convert.FromBase64String(key.ProtectedKey));
        var etype = Enum.Parse<EncryptionType>(key.EncryptionType);
        var principal = new PrincipalName(PrincipalNameType.NT_SRV_INST, realm.Realm, realm.ServicePrincipal.Split('/'));
        return new KerberosKey(key: raw, principal: principal, etype: etype, kvno: key.Kvno);
    }

    /// <summary>
    /// The forest's key for an account: PBKDF2 over the password with the Active Directory salt.
    /// A user account salts with the realm plus the case-exact name; a computer account with the
    /// realm, <c>host</c>, and its lower-case DNS name, as MS-KILE specifies.
    /// </summary>
    internal static byte[] DeriveKey(KerberosRealmEntity realm, string accountName, KerberosAccountKind kind, string password, EncryptionType etype)
    {
        KerberosKey key = kind switch
        {
            KerberosAccountKind.User => new KerberosKey(password,
                new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm.Realm, new[] { accountName }),
                etype: etype, saltType: SaltType.ActiveDirectoryUser),
            KerberosAccountKind.Computer => new KerberosKey(password,
                new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm.Realm, new[] { accountName }),
                host: $"{accountName.TrimEnd('$').ToLowerInvariant()}.{realm.DnsDomain}",
                etype: etype, saltType: SaltType.ActiveDirectoryService),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        return key.GetKey().ToArray();
    }

    private async Task ValidateSpecAsync(KerberosRealmSpec spec)
    {
        NormalizeSpn(spec.ServicePrincipal);
        if (!await db.Users.AnyAsync(u => u.Id == spec.EnrollmentUserId))
            throw new InvalidOperationException("The enrollment user does not exist.");
    }

    /// <summary>Upper-case, trimmed, and shaped like a DNS name. Anything else is refused.</summary>
    internal static string NormalizeRealm(string realm)
    {
        var r = (realm ?? string.Empty).Trim().ToUpperInvariant();
        if (r.Length < 3 || r.Length > 255 || r.Any(c => char.IsWhiteSpace(c) || c == '@' || c == '/') || !r.Contains('.'))
            throw new InvalidOperationException("Realm must be a DNS-style name such as CORP.EXAMPLE.LOCAL.");
        return r;
    }

    internal static string NormalizeDnsDomain(string? dnsDomain, string realm)
    {
        var d = string.IsNullOrWhiteSpace(dnsDomain) ? realm : dnsDomain.Trim();
        return d.ToLowerInvariant();
    }

    /// <summary><c>service/host</c>, exactly one slash, no realm.</summary>
    internal static string NormalizeSpn(string spn)
    {
        var s = (spn ?? string.Empty).Trim();
        var parts = s.Split('/');
        if (parts.Length != 2 || parts.Any(p => p.Length == 0 || p.Any(char.IsWhiteSpace)) || s.Contains('@'))
            throw new InvalidOperationException("Service principal must look like HTTP/host.example.net.");
        return $"{parts[0].ToUpperInvariant()}/{parts[1].ToLowerInvariant()}";
    }

    private static string GeneratePassword()
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!";
        return string.Create(32, alphabet, static (span, a) =>
        {
            for (var i = 0; i < span.Length; i++)
                span[i] = a[RandomNumberGenerator.GetInt32(a.Length)];
        });
    }
}
