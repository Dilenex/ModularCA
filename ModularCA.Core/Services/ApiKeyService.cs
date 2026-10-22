using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>The integrations an API key can open.</summary>
public static class ApiKeyIntegrations
{
    /// <summary>The infrastructure API, for tools such as Terraform and Ansible.</summary>
    public const string Infrastructure = "integration";

    /// <summary>The Kubernetes cert-manager external issuer.</summary>
    public const string CertManager = "cert-manager";

    public static readonly IReadOnlyList<string> All = [Infrastructure, CertManager];
}

/// <summary>Why an API key was not created.</summary>
public sealed class ApiKeyRefusedException(string message) : Exception(message);

/// <summary>Who is creating or revoking an API key.</summary>
public sealed record ApiKeyActor(Guid? UserId, string Name, string? SourceIp = null);

/// <summary>
/// Who an integration request was admitted as: one of the integration's named keys, or the
/// single key in the configuration that predates them.
/// </summary>
/// <param name="KeyId">The named key's id; null for the configuration's key.</param>
/// <param name="KeyName">The named key's name; null for the configuration's key.</param>
/// <param name="Scope">The CAs the request may reach.</param>
public sealed record IntegrationCaller(Guid? KeyId, string? KeyName, IntegrationSpaceScope Scope)
{
    /// <summary>The name an audit record gives this caller: the integration, and the key when it has a name.</summary>
    public string Actor(string integration) => KeyName == null ? integration : $"{integration}:{KeyName}";
}

/// <summary>What became of a request that presented, or did not present, an API key.</summary>
public enum IntegrationAdmissionStatus
{
    /// <summary>Admitted; the caller is named.</summary>
    Admitted,

    /// <summary>The integration is switched off.</summary>
    Disabled,

    /// <summary>The integration is on and has no key at all, in the configuration or named.</summary>
    Unconfigured,

    /// <summary>No key was presented.</summary>
    MissingKey,

    /// <summary>The key presented is not a working key of this integration.</summary>
    InvalidKey,

    /// <summary>The key is good, and scoped outside what the integration itself is allowed.</summary>
    OutOfScope,
}

/// <summary>The outcome of <see cref="IApiKeyService.AdmitAsync"/>.</summary>
/// <param name="Caller">Who was admitted; null unless <paramref name="Status"/> is <see cref="IntegrationAdmissionStatus.Admitted"/>.</param>
/// <param name="Detail">A sentence for the client when the status alone does not say enough.</param>
public sealed record IntegrationAdmission(IntegrationAdmissionStatus Status, IntegrationCaller? Caller = null, string? Detail = null);

/// <summary>Named, individually revocable API keys for the integrations.</summary>
public interface IApiKeyService
{
    /// <summary>
    /// Judges a request to an integration by the key it presented. Both integrations go through
    /// here, so a key is judged one way.
    /// </summary>
    /// <param name="integration">One of <see cref="ApiKeyIntegrations"/>.</param>
    /// <param name="enabled">Whether the integration is switched on.</param>
    /// <param name="configuredKey">The single key in the configuration, which keeps working beside the named ones.</param>
    /// <param name="integrationScope">The CAs the integration as a whole is allowed.</param>
    /// <param name="presented">The key the request carried, or null.</param>
    Task<IntegrationAdmission> AdmitAsync(string integration, bool enabled, string? configuredKey,
        IntegrationSpaceScope integrationScope, string? presented, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a key and returns it with its row. The key is returned here once and is not
    /// stored; only its hash is.
    /// </summary>
    /// <param name="integration">One of <see cref="ApiKeyIntegrations"/>.</param>
    /// <param name="name">What to call the key; distinct among the integration's working keys.</param>
    /// <param name="spaceScope">A space id, <c>instance</c>, or null for whatever the integration is allowed.</param>
    /// <param name="expiresAt">When the key stops working, or null for never.</param>
    /// <exception cref="ApiKeyRefusedException">The integration, name, scope or expiry is not acceptable.</exception>
    Task<(ApiKeyEntity Key, string Plaintext)> CreateAsync(string integration, string name, string? spaceScope, DateTime? expiresAt, ApiKeyActor actor, CancellationToken cancellationToken = default);

    /// <summary>Every key, working or not, newest first; of one integration when <paramref name="integration"/> is given.</summary>
    Task<IReadOnlyList<ApiKeyEntity>> ListAsync(string? integration = null, CancellationToken cancellationToken = default);

    /// <summary>Revokes a key. False when there is no such key; true when it is revoked, whether by this call or before.</summary>
    Task<bool> RevokeAsync(Guid id, ApiKeyActor actor, CancellationToken cancellationToken = default);

    /// <summary>
    /// The working key of <paramref name="integration"/> that <paramref name="presented"/> is, or
    /// null: not a key of ours, of another integration, revoked or expired. Notes the use.
    /// </summary>
    Task<ApiKeyEntity?> AuthenticateAsync(string integration, string? presented, CancellationToken cancellationToken = default);

    /// <summary>Whether <paramref name="integration"/> has a key that works now.</summary>
    Task<bool> AnyWorkingAsync(string integration, CancellationToken cancellationToken = default);
}

/// <inheritdoc />
public sealed class ApiKeyService(ModularCADbContext db, IAuditService audit, ILogger<ApiKeyService> logger) : IApiKeyService
{
    /// <summary>What every generated key starts with, so one is recognisable in a configuration file or a leak scan.</summary>
    public const string Prefix = "mca_";

    /// <summary>How often, at most, a key's last use is written.</summary>
    private static readonly TimeSpan LastUsedGranularity = TimeSpan.FromMinutes(5);

    /// <summary>SHA-256 over the UTF-8 of a key.</summary>
    public static byte[] Hash(string key) => SHA256.HashData(Encoding.UTF8.GetBytes(key));

    /// <summary>A new key: the prefix and 256 random bits in base64url.</summary>
    public static string Generate() =>
        Prefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <inheritdoc />
    public async Task<IntegrationAdmission> AdmitAsync(string integration, bool enabled, string? configuredKey,
        IntegrationSpaceScope integrationScope, string? presented, CancellationToken cancellationToken = default)
    {
        if (!enabled)
            return new IntegrationAdmission(IntegrationAdmissionStatus.Disabled);

        var hasConfiguredKey = !string.IsNullOrWhiteSpace(configuredKey);
        if (!hasConfiguredKey && !await AnyWorkingAsync(integration, cancellationToken))
            return new IntegrationAdmission(IntegrationAdmissionStatus.Unconfigured);
        if (string.IsNullOrWhiteSpace(presented))
            return new IntegrationAdmission(IntegrationAdmissionStatus.MissingKey);

        var named = await AuthenticateAsync(integration, presented, cancellationToken);
        if (named != null)
        {
            var keyScope = IntegrationSpaceScope.Parse(named.SpaceScope);
            return TryNarrow(integrationScope, keyScope, out var scope)
                ? new IntegrationAdmission(IntegrationAdmissionStatus.Admitted, new IntegrationCaller(named.Id, named.Name, scope))
                : new IntegrationAdmission(IntegrationAdmissionStatus.OutOfScope,
                    Detail: $"This key is limited to {keyScope}, which is outside what the integration is allowed: {integrationScope}.");
        }

        // Compared as digests, so the comparison takes the same time whatever was presented.
        if (hasConfiguredKey && CryptographicOperations.FixedTimeEquals(Hash(configuredKey!), Hash(presented)))
            return new IntegrationAdmission(IntegrationAdmissionStatus.Admitted, new IntegrationCaller(null, null, integrationScope));

        return new IntegrationAdmission(IntegrationAdmissionStatus.InvalidKey);
    }

    /// <summary>
    /// The scope a named key works under: its own when the integration is unrestricted, the
    /// integration's when the key names none, and either when they agree. A key scoped somewhere
    /// the integration is not allowed has no scope to work under.
    /// </summary>
    internal static bool TryNarrow(IntegrationSpaceScope integration, IntegrationSpaceScope key, out IntegrationSpaceScope scope)
    {
        scope = integration;
        if (!key.IsRestricted) return true;
        if (!integration.IsRestricted || integration == key)
        {
            scope = key;
            return true;
        }
        return false;
    }

    /// <inheritdoc />
    public async Task<(ApiKeyEntity Key, string Plaintext)> CreateAsync(string integration, string name, string? spaceScope, DateTime? expiresAt, ApiKeyActor actor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!ApiKeyIntegrations.All.Contains(integration))
            throw new ApiKeyRefusedException($"'{integration}' is not an integration. Use one of: {string.Join(", ", ApiKeyIntegrations.All)}.");

        name = (name ?? string.Empty).Trim();
        if (name.Length is 0 or > 100)
            throw new ApiKeyRefusedException("A key needs a name of 1 to 100 characters.");

        var now = DateTime.UtcNow;
        if (expiresAt is { } expiry && expiry.ToUniversalTime() <= now)
            throw new ApiKeyRefusedException("A key cannot expire in the past.");

        var scope = string.IsNullOrWhiteSpace(spaceScope) ? null : spaceScope.Trim();
        if (scope != null)
        {
            var parsed = IntegrationSpaceScope.Parse(scope);
            if (parsed.Kind == IntegrationScopeKind.Space
                && !await db.Spaces.AsNoTracking().AnyAsync(s => s.Id == parsed.SpaceId, cancellationToken))
                throw new ApiKeyRefusedException($"There is no space {parsed.SpaceId}.");
            if (parsed.Kind is not (IntegrationScopeKind.Space or IntegrationScopeKind.Instance))
                throw new ApiKeyRefusedException($"A key's scope is a space id or '{IntegrationSpaceScope.InstanceValue}'.");
            scope = parsed.Kind == IntegrationScopeKind.Instance ? IntegrationSpaceScope.InstanceValue : parsed.SpaceId!.Value.ToString();
        }

        var working = await db.ApiKeys.AsNoTracking()
            .Where(k => k.Integration == integration && k.RevokedAt == null && (k.ExpiresAt == null || k.ExpiresAt > now))
            .Select(k => k.Name)
            .ToListAsync(cancellationToken);
        if (working.Any(existing => string.Equals(existing, name, StringComparison.OrdinalIgnoreCase)))
            throw new ApiKeyRefusedException($"A working key of this integration is already named '{name}'. Revoke it first, or choose another name.");

        var plaintext = Generate();
        var key = new ApiKeyEntity
        {
            Integration = integration,
            Name = name,
            KeyHash = Hash(plaintext),
            Hint = plaintext[^4..],
            SpaceScope = scope,
            CreatedAt = now,
            CreatedByUserId = actor.UserId,
            CreatedByName = actor.Name,
            ExpiresAt = expiresAt?.ToUniversalTime(),
        };
        db.ApiKeys.Add(key);
        await db.SaveChangesAsync(cancellationToken);

        await audit.LogAsync(AuditActionType.ApiKeyCreated, actor.UserId, actor.Name,
            targetEntityType: "ApiKey", targetEntityId: key.Id.ToString(),
            details: new { key.Integration, key.Name, key.SpaceScope, key.ExpiresAt },
            sourceIp: actor.SourceIp);
        return (key, plaintext);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ApiKeyEntity>> ListAsync(string? integration = null, CancellationToken cancellationToken = default)
    {
        var query = db.ApiKeys.AsNoTracking();
        if (!string.IsNullOrEmpty(integration))
            query = query.Where(k => k.Integration == integration);
        return await query.OrderByDescending(k => k.CreatedAt).ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> RevokeAsync(Guid id, ApiKeyActor actor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var key = await db.ApiKeys.FirstOrDefaultAsync(k => k.Id == id, cancellationToken);
        if (key == null) return false;
        if (key.RevokedAt != null) return true;

        key.RevokedAt = DateTime.UtcNow;
        key.RevokedByName = actor.Name;
        await db.SaveChangesAsync(cancellationToken);

        await audit.LogAsync(AuditActionType.ApiKeyRevoked, actor.UserId, actor.Name,
            targetEntityType: "ApiKey", targetEntityId: key.Id.ToString(),
            details: new { key.Integration, key.Name },
            sourceIp: actor.SourceIp);
        return true;
    }

    /// <inheritdoc />
    public async Task<ApiKeyEntity?> AuthenticateAsync(string integration, string? presented, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(presented) || !presented.StartsWith(Prefix, StringComparison.Ordinal))
            return null;

        // Found by the hash, which is unique and indexed: the comparison is the database's, of
        // two digests, and tells a caller nothing about a key it does not already hold.
        var hash = Hash(presented);
        var key = await db.ApiKeys.FirstOrDefaultAsync(k => k.KeyHash == hash, cancellationToken);
        var now = DateTime.UtcNow;
        if (key == null || key.Integration != integration || key.RevokedAt != null || key.ExpiresAt <= now)
            return null;

        if (key.LastUsedAt == null || now - key.LastUsedAt.Value > LastUsedGranularity)
        {
            key.LastUsedAt = now;
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException ex)
            {
                // The key is good whether or not its last use could be written down.
                logger.LogDebug(ex, "The last use of API key {KeyId} was not recorded.", key.Id);
            }
        }
        return key;
    }

    /// <inheritdoc />
    public Task<bool> AnyWorkingAsync(string integration, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        return db.ApiKeys.AsNoTracking()
            .AnyAsync(k => k.Integration == integration && k.RevokedAt == null && (k.ExpiresAt == null || k.ExpiresAt > now), cancellationToken);
    }
}
