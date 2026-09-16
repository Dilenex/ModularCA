using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// Singleton IP whitelist service. Owns an immutable in-memory snapshot of
/// the <c>Whitelists</c> table (plus a label -&gt; Guid map for CAs, needed
/// for <c>Ca</c> / <c>Protocol</c> scope lookups from short-URL paths) and
/// serves <see cref="Evaluate(string, IPAddress?)"/> from that snapshot
/// without touching the database. The snapshot is built once at construction
/// time, re-built at the end of bootstrap after the seeder runs, and
/// re-built again after every admin CRUD mutation via
/// <see cref="ReloadAsync(CancellationToken)"/>. Pre-bootstrap failures to
/// read the table (first install, pending migrations, connection refused)
/// are tolerated — the service logs a warning, stays on an empty snapshot,
/// and flips <see cref="IsWarm"/> to false so the middleware knows to fall
/// back to <c>WhitelistDefaults.InternalOnlyCidrs</c> for setup paths.
/// </summary>
public class WhitelistService : IWhitelistService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<WhitelistService> _logger;

    private volatile IReadOnlyList<WhitelistRule> _snapshot = Array.Empty<WhitelistRule>();
    private volatile IReadOnlyDictionary<string, Guid> _caLabelMap =
        new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);
    private volatile bool _isWarm;

    /// <summary>
    /// Constructs the service with an empty snapshot and <see cref="IsWarm"/> = false.
    /// No database access happens here — the initial load is driven exclusively by an
    /// explicit <see cref="ReloadAsync(CancellationToken)"/> call from the startup
    /// warmup in <c>StartModularCA.cs</c>, which is skipped in setup mode so a missing
    /// <c>config.yaml</c> / invalid DB credentials never produce EF command-logger
    /// error spam. The middleware's pre-bootstrap fallback handles <c>/setup/*</c>
    /// while the service remains cold.
    /// </summary>
    /// <param name="scopeFactory">Factory used to create a DI scope for
    /// every DbContext resolution (this service is a singleton so it cannot
    /// inject <c>ModularCADbContext</c> directly).</param>
    /// <param name="logger">Standard logger for warm/cold and reload events.</param>
    public WhitelistService(IServiceScopeFactory scopeFactory, ILogger<WhitelistService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _isWarm = false;
    }

    /// <inheritdoc />
    public bool IsWarm => _isWarm;

    private volatile bool _hasSnapshot;

    /// <inheritdoc />
    public bool HasSnapshot => _hasSnapshot;

    /// <inheritdoc />
    public async Task ReloadAsync(CancellationToken ct = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

        try
        {
            var rows = await db.Whitelists.AsNoTracking().ToListAsync(ct);

            var newSnapshot = new List<WhitelistRule>(rows.Count);
            foreach (var row in rows)
            {
                var networks = CidrMatcher.ParseNetworks(row.CidrList);
                newSnapshot.Add(new WhitelistRule(
                    row.Id,
                    row.Scope,
                    row.CertificateAuthorityId,
                    row.Protocol,
                    row.IsEnabled,
                    networks));
            }

            // Load the CA label -> Guid map at the same time so short-URL
            // paths (e.g. /acme/my-ca/directory) can resolve to a Guid for
            // Ca / Protocol scope lookups without a per-request DB hit.
            var caLabelPairs = await db.CertificateAuthorities
                .AsNoTracking()
                .Where(c => c.Label != null)
                .Select(c => new { c.Id, c.Label })
                .ToListAsync(ct);

            var newLabelMap = new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in caLabelPairs)
            {
                if (!string.IsNullOrWhiteSpace(pair.Label))
                    newLabelMap[pair.Label!] = pair.Id;
            }

            // Atomic reference replacement. Readers observe either the old
            // or the new snapshot; no tearing is possible.
            _snapshot = newSnapshot;
            _caLabelMap = newLabelMap;
            _isWarm = true;
            _hasSnapshot = true;

            _logger.LogInformation(
                "WhitelistService reloaded with {Count} rules.",
                newSnapshot.Count);
        }
        catch (Exception ex)
        {
            // Keep the last-known-good snapshot if one exists. IsWarm drops so the
            // middleware knows the data may be stale; HasSnapshot stays true so it
            // keeps evaluating against that data rather than passing traffic
            // through. Before HasSnapshot existed the middleware treated "not
            // warm" as "pre-bootstrap" and let every non-admin path through
            // unchecked, for as long as the next successful reload took, which
            // with no re-warm timer was the life of the process.
            _isWarm = false;
            _logger.LogWarning(
                "WhitelistService reload failed — staying on previous snapshot (IsWarm=false). Error: {Message}",
                ex.Message);
        }
    }

    /// <inheritdoc />
    public WhitelistDecision Evaluate(string path, IPAddress? remoteIp)
    {
        if (remoteIp == null)
            return WhitelistDecision.Deny;

        // Normalize IPv4-mapped IPv6 to real IPv4 so rules written as
        // 127.0.0.0/8 still match a client that Kestrel surfaces as
        // ::ffff:127.0.0.1 on dual-stack sockets.
        if (remoteIp.IsIPv4MappedToIPv6)
            remoteIp = remoteIp.MapToIPv4();

        if (string.IsNullOrEmpty(path))
            return WhitelistDecision.NotCovered;

        // Derive the scope bucket (and, where applicable, the CA label /
        // protocol triple) from the path. Unknown paths return NotCovered
        // without touching the snapshot so admin / SPA / static routes pass
        // through with zero overhead.
        var bucket = DerivePathBucket(path);
        if (bucket == null)
            return WhitelistDecision.NotCovered;

        // Walk the candidate chain from most specific (Protocol) to most
        // general (System), returning the first enabled rule's verdict.
        var chain = BuildLookupChain(bucket);
        foreach (var candidate in chain)
        {
            var rule = FindRule(candidate.Scope, candidate.CaId, candidate.Protocol);
            if (rule != null)
            {
                return CidrMatcher.IsAllowed(remoteIp, rule.ParsedNetworks)
                    ? WhitelistDecision.Allow
                    : WhitelistDecision.Deny;
            }
        }

        return WhitelistDecision.NotCovered;
    }

    /// <inheritdoc />
    public async Task<List<WhitelistEntity>> GetAllAsync(CancellationToken ct = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        return await db.Whitelists
            .AsNoTracking()
            .OrderBy(w => w.Scope)
            .ThenBy(w => w.Name)
            .ToListAsync(ct);
    }

    /// <inheritdoc />
    public async Task<WhitelistEntity?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        return await db.Whitelists
            .AsNoTracking()
            .FirstOrDefaultAsync(w => w.Id == id, ct);
    }

    /// <inheritdoc />
    public async Task<WhitelistEntity> CreateAsync(WhitelistEntity entity, CancellationToken ct = default)
    {
        using (var scope = _scopeFactory.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

            if (entity.Id == Guid.Empty)
                entity.Id = Guid.NewGuid();

            // Operators cannot mint system-default rules through the API.
            // Only the bootstrap seeder is allowed to set this flag.
            entity.IsSystemDefault = false;

            var now = DateTime.UtcNow;
            entity.CreatedAt = now;
            entity.UpdatedAt = now;

            db.Whitelists.Add(entity);
            await db.SaveChangesAsync(ct);
        }

        // Reload outside the original scope so the snapshot reflects the
        // newly-committed row.
        await ReloadAsync(ct);
        return entity;
    }

    /// <inheritdoc />
    public async Task<WhitelistEntity?> UpdateAsync(Guid id, WhitelistEntity updates, CancellationToken ct = default)
    {
        WhitelistEntity? existing;
        using (var scope = _scopeFactory.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            existing = await db.Whitelists.FirstOrDefaultAsync(w => w.Id == id, ct);
            if (existing == null)
                return null;

            // Only mutate the fields the admin UI is allowed to change.
            // Scope / CertificateAuthorityId / Protocol are part of the
            // unique index and are intentionally immutable: changing any of
            // them would break the identity of the row and invalidate the
            // composite uniqueness constraint. IsSystemDefault is also
            // immutable from the API surface.
            existing.Name = updates.Name;
            existing.Description = updates.Description;
            existing.Cidrs = updates.Cidrs;
            existing.IsEnabled = updates.IsEnabled;
            existing.UpdatedAt = DateTime.UtcNow;

            await db.SaveChangesAsync(ct);
        }

        await ReloadAsync(ct);
        return existing;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        using (var scope = _scopeFactory.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            var existing = await db.Whitelists.FirstOrDefaultAsync(w => w.Id == id, ct);
            if (existing == null)
                return false;

            // System-default rows can be edited but not deleted — the
            // controller maps this return value to a 409 response. Enforced
            // here as the authoritative boundary.
            if (existing.IsSystemDefault)
                return false;

            db.Whitelists.Remove(existing);
            await db.SaveChangesAsync(ct);
        }

        await ReloadAsync(ct);
        return true;
    }

    // --------------------------------------------------------------
    // Private helpers
    // --------------------------------------------------------------

    /// <summary>
    /// Scans the snapshot for the first enabled rule matching the given
    /// scope triple. Returns null when no match exists at this specificity.
    /// </summary>
    private WhitelistRule? FindRule(WhitelistScope scope, Guid? caId, string? protocol)
    {
        var snapshot = _snapshot;
        for (int i = 0; i < snapshot.Count; i++)
        {
            var rule = snapshot[i];
            if (!rule.IsEnabled) continue;
            if (rule.Scope != scope) continue;
            if (rule.CertificateAuthorityId != caId) continue;
            if (!string.Equals(rule.Protocol, protocol, StringComparison.OrdinalIgnoreCase)) continue;
            return rule;
        }
        return null;
    }

    /// <summary>
    /// Translates a request path into the scope bucket it belongs to, plus
    /// the optional CA identifier and protocol name when the path carries a
    /// CA label and a protocol prefix. Returns null for any path that is
    /// not in the middleware's gated list — static files, admin / user
    /// management routes, SPAs, and health probes all fall through.
    /// </summary>
    private PathBucket? DerivePathBucket(string path)
    {
        // Setup wizard — most specific, checked first.
        if (StartsWith(path, "/api/v1/setup/") || StartsWith(path, "/setup/")
            || Equals(path, "/api/v1/setup") || Equals(path, "/setup"))
        {
            return new PathBucket(WhitelistScope.Setup, null, null, false);
        }

        // Admin surface — SPA routes and admin API. Seeded closed by default so
        // public deployments don't expose the admin console to the internet.
        if (StartsWith(path, "/api/v1/admin/") || StartsWith(path, "/admin/")
            || Equals(path, "/api/v1/admin") || Equals(path, "/admin")
            // The documentation SPA is meant for signed-in users, but a browser navigation
            // carries no bearer token, so the server cannot gate its static files on a session;
            // DocsAuthMiddleware can only refuse a request that volunteers an invalid header.
            // Classifying it with the admin surface gives it the admin rule's reach, internal-only
            // by default, which is the honest scope for a page that describes every admin endpoint.
            || StartsWith(path, "/docs/") || Equals(path, "/docs"))
        {
            return new PathBucket(WhitelistScope.Admin, null, null, false);
        }

        // Auth endpoints (login / refresh / MFA).
        if (StartsWith(path, "/api/v1/auth/") || StartsWith(path, "/auth/")
            || Equals(path, "/api/v1/auth") || Equals(path, "/auth"))
        {
            return new PathBucket(WhitelistScope.Auth, null, null, false);
        }

        // Signing protocols with a {label} segment. Two flavours: direct
        // /api/v1/{proto}/{label}/... and public short /{proto}/{label}/...
        var protoBucket = TryDeriveSigningProtocolBucket(path);
        if (protoBucket != null)
            return protoBucket;

        // OCSP (both direct and public short URL). The short form can
        // optionally carry a CA label via /ocsp/ca/{label}/... — otherwise
        // it falls through to the path-scope bucket (Api / ShortUrl).
        var ocspBucket = TryDeriveOcspBucket(path);
        if (ocspBucket != null)
            return ocspBucket;

        // TSA mirrors OCSP: optional CA label, same fall-through rules.
        var tsaBucket = TryDeriveTsaBucket(path);
        if (tsaBucket != null)
            return tsaBucket;

        // CRL — tagged with Protocol="CRL" so operators can write a single
        // global rule (Protocol scope, no CaId, Protocol="CRL") that opens
        // every CA's CRL endpoint without enumerating CAs. AIA / CDP URLs
        // baked into issued certs must stay publicly reachable, so the
        // bootstrap seeder seeds a Protocol(null, "CRL") row with AllAddresses.
        if (StartsWith(path, "/api/v1/public/crl/") || Equals(path, "/api/v1/public/crl"))
            return new PathBucket(WhitelistScope.Api, null, "CRL", true);
        if (StartsWith(path, "/crl/") || Equals(path, "/crl"))
            return new PathBucket(WhitelistScope.ShortUrl, null, "CRL", true);

        // Public CA cert download — same tagging story as CRL. AIA points at
        // /ca/{label} so the endpoint must be reachable by any client that
        // sees one of this CA's issued certificates.
        if (StartsWith(path, "/api/v1/public/ca/") || Equals(path, "/api/v1/public/ca"))
            return new PathBucket(WhitelistScope.Api, null, "CA", true);
        if (StartsWith(path, "/ca/") || Equals(path, "/ca"))
            return new PathBucket(WhitelistScope.ShortUrl, null, "CA", true);

        // Relying-party surface. MUST stay below the CRL / CA / OCSP / TSA checks above:
        // those are also under /api/v1/public/, and matching them here first would strip their
        // per-protocol rules and hand every one of them whatever the Public rule says. Narrow on
        // purpose — the portal SPA and the info endpoint its footer reads, nothing else.
        if (StartsWith(path, "/public/") || Equals(path, "/public")
            || Equals(path, "/api/v1/public/info"))
        {
            return new PathBucket(WhitelistScope.Public, null, null, false);
        }

        // Metrics + integration endpoints. These are /api/v1/-only (no
        // short-URL equivalent) so they always land on the Api bucket.
        if (Equals(path, "/metrics") || StartsWith(path, "/metrics/")
            || StartsWith(path, "/api/v1/integration/"))
        {
            return new PathBucket(WhitelistScope.Api, null, null, true);
        }

        // Anything else — SPA assets, favicon, static files, root path,
        // uncategorized frontend routes — falls under the System scope so
        // every request is subject to the operator's ACL. The System rule is
        // seeded with RFC1918 + loopback by default; operators can relax it
        // explicitly or add narrower scoped rules for paths they want public.
        return new PathBucket(WhitelistScope.System, null, null, false);
    }

    /// <summary>
    /// Attempts to match signing-protocol paths (ACME / SCEP / EST / CMP)
    /// in either their direct <c>/api/v1/{proto}/{label}/...</c> form or
    /// their public short <c>/{proto}/{label}/...</c> form, returning a
    /// fully-populated <see cref="PathBucket"/> with the derived protocol
    /// name plus the resolved CA Guid when the label is known.
    /// </summary>
    private PathBucket? TryDeriveSigningProtocolBucket(string path)
    {
        // RFC 7030 section 3.2.2 path. Added to the router after the other two forms, and for a
        // while known only to the feature gate, so a rule that confined EST to a device VLAN
        // still let the standard path through as a System-bucket request. Three classifiers
        // (this, the rate limiter, the feature gate) must agree on what is an EST path.
        const string estWellKnown = "/.well-known/est/";
        if (StartsWith(path, estWellKnown))
        {
            var label = ExtractFirstSegment(path, estWellKnown);
            return new PathBucket(WhitelistScope.ShortUrl, ResolveLabel(label), "EST", true);
        }

        foreach (var proto in SigningProtocols)
        {
            var apiPrefix = $"/api/v1/{proto.ToLowerInvariant()}/";
            if (StartsWith(path, apiPrefix))
            {
                var label = ExtractFirstSegment(path, apiPrefix);
                Guid? caId = ResolveLabel(label);
                return new PathBucket(WhitelistScope.Api, caId, proto, true);
            }

            var shortPrefix = $"/{proto.ToLowerInvariant()}/";
            if (StartsWith(path, shortPrefix))
            {
                var label = ExtractFirstSegment(path, shortPrefix);
                Guid? caId = ResolveLabel(label);
                return new PathBucket(WhitelistScope.ShortUrl, caId, proto, true);
            }
        }
        return null;
    }

    /// <summary>
    /// Attempts to match OCSP paths. The public short URL has two shapes:
    /// <c>/ocsp</c> (CA-less) and <c>/ocsp/ca/{label}</c>. The direct form
    /// follows <c>/api/v1/public/ocsp[/ca/{label}]</c>. A missing label
    /// falls back to the path-scope bucket with no CA / Protocol context.
    /// </summary>
    private PathBucket? TryDeriveOcspBucket(string path)
    {
        if (StartsWith(path, "/api/v1/public/ocsp"))
        {
            var label = ExtractOcspTsaLabel(path, "/api/v1/public/ocsp");
            return new PathBucket(WhitelistScope.Api, ResolveLabel(label), "OCSP", true);
        }
        if (StartsWith(path, "/ocsp"))
        {
            var label = ExtractOcspTsaLabel(path, "/ocsp");
            return new PathBucket(WhitelistScope.ShortUrl, ResolveLabel(label), "OCSP", true);
        }
        return null;
    }

    /// <summary>
    /// Attempts to match TSA paths. Mirrors the OCSP helper above —
    /// <c>/tsa</c> and <c>/tsa/ca/{label}</c> for the short URL, and
    /// <c>/api/v1/public/tsa[/ca/{label}]</c> for the direct route.
    /// </summary>
    private PathBucket? TryDeriveTsaBucket(string path)
    {
        if (StartsWith(path, "/api/v1/public/tsa"))
        {
            var label = ExtractOcspTsaLabel(path, "/api/v1/public/tsa");
            return new PathBucket(WhitelistScope.Api, ResolveLabel(label), "TSA", true);
        }
        if (StartsWith(path, "/tsa"))
        {
            var label = ExtractOcspTsaLabel(path, "/tsa");
            return new PathBucket(WhitelistScope.ShortUrl, ResolveLabel(label), "TSA", true);
        }
        return null;
    }

    /// <summary>
    /// Extracts a <c>ca/{label}</c> segment from an OCSP or TSA path
    /// (<c>/ocsp/ca/my-ca</c> or <c>/api/v1/public/ocsp/ca/my-ca</c>),
    /// returning null if the path has no such segment.
    /// </summary>
    private static string? ExtractOcspTsaLabel(string path, string prefix)
    {
        if (path.Length <= prefix.Length) return null;
        // Expect /{prefix}/ca/{label}[/...]
        var rest = path.Substring(prefix.Length);
        if (!rest.StartsWith("/ca/", StringComparison.OrdinalIgnoreCase))
            return null;
        rest = rest.Substring("/ca/".Length);
        var slash = rest.IndexOf('/');
        return slash >= 0 ? rest.Substring(0, slash) : rest;
    }

    /// <summary>
    /// Pulls the first path segment after a known prefix. For a path of
    /// <c>/acme/my-ca/directory</c> and prefix <c>/acme/</c> this returns
    /// <c>my-ca</c>. Returns null when the remainder is empty.
    /// </summary>
    private static string? ExtractFirstSegment(string path, string prefix)
    {
        if (path.Length <= prefix.Length) return null;
        var rest = path.Substring(prefix.Length);
        var slash = rest.IndexOf('/');
        var segment = slash >= 0 ? rest.Substring(0, slash) : rest;
        return string.IsNullOrWhiteSpace(segment) ? null : segment;
    }

    /// <summary>
    /// Looks up a CA label in the cached label -&gt; Guid map. Returns null
    /// when the label is unknown (unknown labels still proceed through the
    /// chain; the Ca / Protocol lookup will simply not match).
    /// </summary>
    private Guid? ResolveLabel(string? label)
    {
        if (string.IsNullOrWhiteSpace(label)) return null;
        return _caLabelMap.TryGetValue(label, out var id) ? id : null;
    }

    /// <summary>
    /// Builds the ordered list of scope triples to probe for a given path
    /// bucket, from most specific to least. Triples with missing pieces (no CA,
    /// no protocol) are skipped automatically.
    /// <para>
    /// CA-wins ordering: a per-CA any-protocol rule beats a global per-protocol
    /// rule when both could match. Operator-set per-CA visibility is a
    /// deployment-specific decision that should override protocol-level defaults.
    /// </para>
    /// <list type="number">
    /// <item><description>Protocol(CaId, Protocol) — per-CA per-protocol, most specific.</description></item>
    /// <item><description>Ca(CaId) — per-CA any-protocol.</description></item>
    /// <item><description>Protocol(null, Protocol) — global per-protocol (applies to any CA serving this protocol).</description></item>
    /// <item><description>Path-scope (Admin / Setup / Auth / Api / ShortUrl / System) — the bucket's own scope.</description></item>
    /// <item><description>System — ultimate catch-all, only consulted when a protocol-family path falls off the end of its own chain.</description></item>
    /// </list>
    /// </summary>
    private static IEnumerable<Candidate> BuildLookupChain(PathBucket bucket)
    {
        // 1. Per-CA per-protocol (most specific).
        if (bucket.CaId.HasValue && !string.IsNullOrEmpty(bucket.Protocol))
            yield return new Candidate(WhitelistScope.Protocol, bucket.CaId, bucket.Protocol);

        // 2. Per-CA any-protocol.
        if (bucket.CaId.HasValue)
            yield return new Candidate(WhitelistScope.Ca, bucket.CaId, null);

        // 3. Global per-protocol (CaId=null, Protocol=set). Lets operators
        //    write rules like "OCSP is public everywhere" without enumerating
        //    every CA.
        if (!string.IsNullOrEmpty(bucket.Protocol))
            yield return new Candidate(WhitelistScope.Protocol, null, bucket.Protocol);

        // 4. Path-scope.
        yield return new Candidate(bucket.Scope, null, null);

        // 5. System catch-all.
        if (bucket.ConsultSystemFallback && bucket.Scope != WhitelistScope.System)
            yield return new Candidate(WhitelistScope.System, null, null);
    }

    /// <summary>
    /// Helper: case-insensitive path prefix check.
    /// </summary>
    private static bool StartsWith(string path, string prefix)
        => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Helper: case-insensitive exact path match.
    /// </summary>
    private static bool Equals(string path, string value)
        => string.Equals(path, value, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The list of signing protocols that carry a <c>{label}</c> segment
    /// and therefore resolve to a CA Guid. OCSP / TSA have dedicated
    /// helpers above because their label syntax is different.
    /// </summary>
    private static readonly string[] SigningProtocols =
    {
        "ACME", "SCEP", "EST", "CMP", "MSAE",
    };

    /// <summary>
    /// A parsed whitelist rule. Identical shape to the DB entity except
    /// that the CIDR strings are pre-parsed into <see cref="IpNetwork"/>
    /// instances so per-request lookups skip JSON deserialization and CIDR
    /// parsing entirely.
    /// </summary>
    private sealed record WhitelistRule(
        Guid Id,
        WhitelistScope Scope,
        Guid? CertificateAuthorityId,
        string? Protocol,
        bool IsEnabled,
        IReadOnlyList<IpNetwork> ParsedNetworks);

    /// <summary>
    /// Classification of a request path into its scope bucket plus any
    /// optional CA / protocol context extracted from the URL segments.
    /// </summary>
    private sealed record PathBucket(
        WhitelistScope Scope,
        Guid? CaId,
        string? Protocol,
        bool ConsultSystemFallback);

    /// <summary>
    /// A single scope triple to probe during chain walking.
    /// </summary>
    private sealed record Candidate(
        WhitelistScope Scope,
        Guid? CaId,
        string? Protocol);
}
