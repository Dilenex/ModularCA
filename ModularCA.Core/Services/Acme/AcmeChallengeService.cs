using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using DnsClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Manages ACME challenge lifecycle including HTTP-01 and DNS-01 validation.
/// The http-01 validator resolves
/// A/AAAA records itself and connects directly to each resolved address
/// (up to <c>Acme.Http01.MaxAddresses</c>) with the Host header pinned to
/// the challenged identifier. Auto-redirect is disabled; a single redirect
/// hop is permitted only to the same identifier's apex and only to the
/// <c>/.well-known/acme-challenge/{token}</c> path. Private address space
/// is rejected unless the per-CA
/// <c>CaProtocolConfigEntity.AcmeAllowPrivateAddressValidation</c> flag is
/// set on the ACME protocol config row for the order's CA. When that flag is
/// set the validator additionally resolves the identifier through the OS hosts
/// file (/etc/hosts or the Windows hosts file) and tries those addresses first,
/// since the DNS-protocol resolver never consults it — letting internal
/// deployments map identifiers locally. The
/// dns-01 validator runs on a cache-disabled recursive resolver.
/// </summary>
public class AcmeChallengeService(
    ModularCADbContext db,
    IHttpClientFactory httpClientFactory,
    IServiceScopeFactory scopeFactory,
    IAcmeAccountRateLimiter accountLimiter,
    SystemConfig config) : IAcmeChallengeService
{
    private readonly ModularCADbContext _db = db;
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly IServiceScopeFactory _scopeFactory = scopeFactory;
    private readonly IAcmeAccountRateLimiter _accountLimiter = accountLimiter;
    private readonly SystemConfig _config = config;

    /// <summary>
    /// Records a failed validation against the account that
    /// owns the challenge. Fails silently if the account can't be resolved —
    /// this is a best-effort counter, not a hard dependency of the validator.
    /// </summary>
    private async Task RecordFailedValidationAsync(Guid challengeId)
    {
        try
        {
            var accountId = await _db.AcmeChallenges
                .Where(c => c.Id == challengeId)
                .Select(c => (Guid?)c.Authorization!.Order!.AccountId)
                .FirstOrDefaultAsync();
            if (accountId.HasValue)
                await _accountLimiter.TryRecordFailedValidationAsync(accountId.Value);
        }
        catch
        {
            // Best-effort only.
        }
    }

    public async Task<AcmeChallengeDto?> GetByIdAsync(Guid challengeId, string baseUrl)
    {
        var entity = await _db.AcmeChallenges.FindAsync(challengeId);
        return entity == null ? null : MapToDto(entity, baseUrl);
    }

    public async Task<AcmeChallengeDto> RespondAsync(Guid challengeId, string accountThumbprint, string baseUrl)
    {
        var entity = await _db.AcmeChallenges
            .Include(c => c.Authorization)
            .Where(c => c.Id == challengeId)
            .FirstOrDefaultAsync()
            ?? throw new InvalidOperationException("Challenge not found.");

        if (entity.Status != nameof(AcmeChallengeStatus.Pending))
            return MapToDto(entity, baseUrl);

        // Stamp AttemptCount + NextAttemptAt so the cleanup
        // reconciler can rescue challenges stuck in Processing after a crash.
        // The value is a deadline beyond which AcmeCleanupJob will re-run this
        // challenge.
        entity.Status = nameof(AcmeChallengeStatus.Processing);
        entity.AttemptCount += 1;
        entity.NextAttemptAt = DateTime.UtcNow
            .AddMinutes(Math.Max(1, _config.Acme.ChallengeProcessingTimeoutMinutes));
        await _db.SaveChangesAsync();

        // Fire validation asynchronously in a new DI scope so the DbContext
        // outlives the original request scope.
        var authorizationId = entity.AuthorizationId;
        _ = Task.Run(async () =>
        {
            using var scope = _scopeFactory.CreateScope();
            var scopedChallengeService = scope.ServiceProvider.GetRequiredService<IAcmeChallengeService>();
            var scopedAuthzService = scope.ServiceProvider.GetRequiredService<IAcmeAuthorizationService>();
            var scopedDb = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

            try
            {
                if (entity.Type == "http-01")
                    await scopedChallengeService.ValidateHttp01Async(challengeId, accountThumbprint);
                else if (entity.Type == "dns-01")
                    await scopedChallengeService.ValidateDns01Async(challengeId, accountThumbprint);
                else
                {
                    await MarkChallengeInvalidAsync(scopedDb, challengeId, "Unsupported challenge type.");
                    return;
                }

                // Evaluate authorization/order status after challenge validation
                await scopedAuthzService.EvaluateAsync(authorizationId);
            }
            catch (Exception ex)
            {
                await MarkChallengeInvalidAsync(scopedDb, challengeId, ex.Message);
            }
        });

        return MapToDto(entity, baseUrl);
    }

    /// <summary>
    /// Reconciles challenges stuck in <c>Processing</c> beyond
    /// the configured timeout. Called by <c>AcmeCleanupJob</c> on each cycle.
    /// Challenges that still have retries left are re-queued (by re-invoking
    /// http-01/dns-01 with the known account thumbprint if recoverable); those
    /// that have exhausted attempts are transitioned to <c>Invalid</c>.
    /// </summary>
    public async Task<int> ReconcileStuckChallengesAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var processing = nameof(AcmeChallengeStatus.Processing);
        var maxAttempts = Math.Max(1, _config.Acme.ChallengeMaxAttempts);

        var stuck = await _db.AcmeChallenges
            .Where(c => c.Status == processing && c.NextAttemptAt != null && c.NextAttemptAt <= now)
            .ToListAsync(cancellationToken);

        if (stuck.Count == 0) return 0;

        var processed = 0;
        foreach (var c in stuck)
        {
            if (c.AttemptCount >= maxAttempts)
            {
                c.Status = nameof(AcmeChallengeStatus.Invalid);
                c.ErrorJson = System.Text.Json.JsonSerializer.Serialize(new AcmeErrorResponse
                {
                    Type = "urn:ietf:params:acme:error:serverInternal",
                    Detail = $"Challenge exceeded {maxAttempts} validation attempts.",
                    Status = 500
                });
            }
            else
            {
                // Push out the next retry with linear backoff; the client is
                // still expected to re-POST the challenge, but we unfreeze the
                // stuck state so the server can accept that retry.
                c.Status = nameof(AcmeChallengeStatus.Pending);
                c.NextAttemptAt = null;
            }
            processed++;
        }

        await _db.SaveChangesAsync(cancellationToken);
        return processed;
    }

    /// <summary>
    /// Quick check used by <c>AcmeCleanupJob</c> to avoid
    /// scanning the table when there's nothing to reconcile.
    /// </summary>
    public async Task<bool> HasStuckChallengesAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var processing = nameof(AcmeChallengeStatus.Processing);
        return await _db.AcmeChallenges
            .AnyAsync(c => c.Status == processing && c.NextAttemptAt != null && c.NextAttemptAt <= now, cancellationToken);
    }

    /// <summary>
    /// Looks up the per-CA ACME protocol config row for the given CA label and
    /// returns its <c>AcmeAllowPrivateAddressValidation</c> setting. Defaults to
    /// false (the secure default — refuse RFC 1918) when the label is missing
    /// or no protocol config row exists for that CA + ACME pair.
    /// </summary>
    private async Task<bool> ResolveAllowPrivateAddressesAsync(string? caLabel)
    {
        if (string.IsNullOrEmpty(caLabel)) return false;

        return await _db.CaProtocolConfigs
            .Join(_db.CertificateAuthorities, pc => pc.CaId, ca => ca.Id, (pc, ca) => new { pc, ca })
            .Where(x => x.ca.Label == caLabel && x.pc.Protocol == "ACME")
            .Select(x => x.pc.AcmeAllowPrivateAddressValidation)
            .FirstOrDefaultAsync();
    }

    /// <summary>
    /// Hardened http-01 validator. Resolves A/AAAA
    /// records explicitly via <see cref="LookupClient"/>, caps the total number
    /// of addresses attempted at <c>Acme.Http01.MaxAddresses</c>, rejects
    /// private address space unless the per-CA
    /// <c>CaProtocolConfigEntity.AcmeAllowPrivateAddressValidation</c> is set,
    /// pins the Host header to the challenged identifier, and handles
    /// a single HTTP redirect manually (same-apex + well-known path only).
    /// Fails closed if any address returns a conflicting key authorization.
    /// </summary>
    public async Task ValidateHttp01Async(Guid challengeId, string accountThumbprint)
    {
        var entity = await _db.AcmeChallenges
            .Include(c => c.Authorization)
                .ThenInclude(a => a!.Order)
            .Where(c => c.Id == challengeId)
            .FirstOrDefaultAsync()
            ?? throw new InvalidOperationException("Challenge not found.");

        var domain = entity.Authorization!.IdentifierValue;
        var token = entity.Token;
        var expectedKeyAuthz = $"{token}.{accountThumbprint}";
        var wellKnownPath = $"/.well-known/acme-challenge/{token}";

        var http01 = _config.Acme.Http01 ?? new AcmeHttp01Config();
        // Per-CA toggle replaces the previous global Acme.Http01.AllowPrivateAddresses.
        // Look up the CA's ACME protocol config via the order's CaLabel.
        var allowPrivate = await ResolveAllowPrivateAddressesAsync(entity.Authorization?.Order?.CaLabel);
        var maxAddresses = Math.Clamp(http01.MaxAddresses, 1, 8);
        var perRequestTimeout = TimeSpan.FromSeconds(Math.Clamp(http01.TimeoutSeconds, 3, 30));

        try
        {
            // Resolve the domain explicitly so we can iterate the answer set
            // and pin Host ourselves. Cache disabled.
            var lookup = new LookupClient(new LookupClientOptions
            {
                UseCache = false,
                Recursion = true,
                Timeout = TimeSpan.FromSeconds(5),
                Retries = 1
            });

            var addresses = new List<IPAddress>();
            foreach (var qt in new[] { QueryType.A, QueryType.AAAA })
            {
                var result = await lookup.QueryAsync(domain, qt);
                foreach (var ans in result.Answers)
                {
                    switch (ans)
                    {
                        case DnsClient.Protocol.ARecord a when !addresses.Contains(a.Address):
                            addresses.Add(a.Address);
                            break;
                        case DnsClient.Protocol.AaaaRecord aaaa when !addresses.Contains(aaaa.Address):
                            addresses.Add(aaaa.Address);
                            break;
                    }
                }
            }

            // For internal/air-gapped deployments the operator may map the identifier
            // in the machine hosts file rather than DNS. DnsClient (like dig) speaks the
            // DNS protocol directly and never consults the OS hosts file, so when this
            // CA has private-address validation enabled we also resolve via the platform
            // hosts file (/etc/hosts on Unix, %SystemRoot%\System32\drivers\etc\hosts on
            // Windows) and try those addresses first — they take precedence over a DNS
            // answer that may point elsewhere.
            if (allowPrivate)
            {
                var hostsAddresses = await ResolveFromHostsFileAsync(domain);
                // Insert in reverse so the file's first-listed address ends up first.
                for (var i = hostsAddresses.Count - 1; i >= 0; i--)
                {
                    addresses.Remove(hostsAddresses[i]);
                    addresses.Insert(0, hostsAddresses[i]);
                }
            }

            if (addresses.Count == 0)
                throw new InvalidOperationException(
                    $"No A/AAAA records for {domain} from DNS{(allowPrivate ? " or the hosts file" : "")}.");

            // Reject private address space unless explicitly allowed.
            if (!allowPrivate)
            {
                var firstBad = addresses.FirstOrDefault(IsPrivateAddress);
                if (firstBad != null)
                    throw new InvalidOperationException($"Refusing to validate challenge against private address {firstBad} for {domain}. Enable AcmeAllowPrivateAddressValidation on this CA's ACME protocol config to allow internal validation.");
            }

            var attempted = addresses.Take(maxAddresses).ToList();
            var results = new List<(IPAddress addr, bool ok, string? body, string detail)>();

            foreach (var address in attempted)
            {
                var (ok, body, detail) = await FetchKeyAuthzAsync(address, domain, wellKnownPath, expectedKeyAuthz, perRequestTimeout, allowPrivate);
                results.Add((address, ok, body, detail));
            }

            // Fail closed on any conflicting body that is non-empty and not
            // the expected key authorization (RFC 8555 §10.2 - defend against
            // split-horizon).
            var conflicting = results.FirstOrDefault(r => !r.ok && !string.IsNullOrWhiteSpace(r.body) && r.body.Trim() != expectedKeyAuthz);
            if (conflicting.addr != null)
            {
                entity.Status = nameof(AcmeChallengeStatus.Invalid);
                entity.ErrorJson = System.Text.Json.JsonSerializer.Serialize(new AcmeErrorResponse
                {
                    Type = "urn:ietf:params:acme:error:incorrectResponse",
                    Detail = $"Address {conflicting.addr} returned a conflicting key authorization.",
                    Status = 403
                });
            }
            else if (results.Any(r => r.ok))
            {
                entity.Status = nameof(AcmeChallengeStatus.Valid);
                entity.ValidatedAt = DateTime.UtcNow;
            }
            else
            {
                // Report the actual per-address outcome (HTTP status, empty body,
                // or connection failure) rather than a blanket "mismatch", which
                // misleads operators when the real cause is a 404 or unreachable :80.
                var perAddress = string.Join("; ", results.Select(r => $"{r.addr} → {r.detail}"));
                entity.Status = nameof(AcmeChallengeStatus.Invalid);
                entity.ErrorJson = System.Text.Json.JsonSerializer.Serialize(new AcmeErrorResponse
                {
                    Type = "urn:ietf:params:acme:error:incorrectResponse",
                    Detail = $"No resolved address served the expected key authorization at http://{domain}{wellKnownPath}. Per-address results: {perAddress}",
                    Status = 403
                });
            }
        }
        catch (Exception ex)
        {
            entity.Status = nameof(AcmeChallengeStatus.Invalid);
            entity.ErrorJson = System.Text.Json.JsonSerializer.Serialize(new AcmeErrorResponse
            {
                Type = "urn:ietf:params:acme:error:connection",
                Detail = $"Failed to validate http-01 for {domain}: {ex.Message}",
                Status = 400
            });
        }
        finally
        {
            entity.NextAttemptAt = null;
        }

        await _db.SaveChangesAsync();

        if (entity.Status == nameof(AcmeChallengeStatus.Invalid))
            await RecordFailedValidationAsync(challengeId);
    }

    /// <summary>
    /// Connect to a specific resolved address while
    /// presenting the Host header of the challenged identifier. Uses a
    /// per-challenge <see cref="SocketsHttpHandler"/> with a
    /// <see cref="SocketsHttpHandler.ConnectCallback"/> that ignores DNS and
    /// connects directly to the target IP. A single redirect hop is permitted
    /// and validated.
    /// </summary>
    private async Task<(bool ok, string? body, string detail)> FetchKeyAuthzAsync(
        IPAddress targetAddress,
        string identifier,
        string wellKnownPath,
        string expectedKeyAuthz,
        TimeSpan perRequestTimeout,
        bool allowPrivateAddresses)
    {
        string? body = null;
        try
        {
            using var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                MaxConnectionsPerServer = 2,
                ConnectTimeout = perRequestTimeout,
                PooledConnectionLifetime = TimeSpan.FromSeconds(5),
                ConnectCallback = async (ctx, ct) =>
                {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(targetAddress, ctx.DnsEndPoint.Port, ct);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }
            };

            using var client = new HttpClient(handler) { Timeout = perRequestTimeout };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("ModularCA-ACME/1.0");

            // Initial request: http://{identifier}{wellKnownPath} but connects to targetAddress.
            var uri = new UriBuilder("http", identifier, 80, wellKnownPath).Uri;
            using var req = new HttpRequestMessage(HttpMethod.Get, uri);
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);

            if ((int)resp.StatusCode >= 300 && (int)resp.StatusCode < 400)
            {
                // Single manual redirect hop, allow-listed.
                var location = resp.Headers.Location;
                if (location == null)
                    return (false, null, $"HTTP {(int)resp.StatusCode} redirect without Location header");

                if (!location.IsAbsoluteUri)
                    location = new Uri(uri, location);

                if (location.Scheme != "http" && location.Scheme != "https")
                    return (false, null, $"redirect to disallowed scheme '{location.Scheme}'");

                // Path must remain on the well-known challenge path.
                if (!string.Equals(location.AbsolutePath, wellKnownPath, StringComparison.Ordinal))
                    return (false, null, $"redirect changed path to '{location.AbsolutePath}'");

                // Host must be the identifier itself, or share the same
                // registrable apex (simple eTLD+1 suffix match — rejects
                // bare IPs and mismatched domains).
                if (!IsHostAllowed(location.Host, identifier))
                    return (false, null, $"redirect to disallowed host '{location.Host}'");

                // Re-resolve the redirect target address and enforce the same
                // private-address policy as the original.
                IPAddress? redirectAddr = null;
                if (IPAddress.TryParse(location.Host, out var directIp))
                {
                    redirectAddr = directIp;
                }
                else
                {
                    try
                    {
                        var entries = await Dns.GetHostAddressesAsync(location.Host);
                        redirectAddr = entries.FirstOrDefault();
                    }
                    catch { /* handled below */ }
                }
                if (redirectAddr == null) return (false, null, $"redirect host '{location.Host}' did not resolve");

                if (!allowPrivateAddresses && IsPrivateAddress(redirectAddr))
                    return (false, null, $"redirect target {redirectAddr} is a private address");

                using var redirectHandler = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    MaxConnectionsPerServer = 2,
                    ConnectTimeout = perRequestTimeout,
                    PooledConnectionLifetime = TimeSpan.FromSeconds(5),
                    ConnectCallback = async (ctx, ct) =>
                    {
                        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                        try
                        {
                            await socket.ConnectAsync(redirectAddr, ctx.DnsEndPoint.Port, ct);
                            return new NetworkStream(socket, ownsSocket: true);
                        }
                        catch
                        {
                            socket.Dispose();
                            throw;
                        }
                    }
                };
                using var redirectClient = new HttpClient(redirectHandler) { Timeout = perRequestTimeout };
                redirectClient.DefaultRequestHeaders.UserAgent.ParseAdd("ModularCA-ACME/1.0");
                using var redirectResp = await redirectClient.GetAsync(location);
                if (!redirectResp.IsSuccessStatusCode)
                    return (false, null, $"redirect target returned HTTP {(int)redirectResp.StatusCode}");
                body = (await redirectResp.Content.ReadAsStringAsync()).Trim();
                return (body == expectedKeyAuthz, body, DescribeBody(body, expectedKeyAuthz));
            }

            if (!resp.IsSuccessStatusCode)
                return (false, null, $"HTTP {(int)resp.StatusCode}");

            body = (await resp.Content.ReadAsStringAsync()).Trim();
            return (body == expectedKeyAuthz, body, DescribeBody(body, expectedKeyAuthz));
        }
        catch (Exception ex)
        {
            return (false, body, $"connection failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Produces a short diagnostic describing how a fetched body compares to the
    /// expected key authorization: <c>ok</c>, <c>empty body (HTTP 200)</c>, or
    /// <c>content mismatch</c>. Used to build an actionable validation error.
    /// </summary>
    private static string DescribeBody(string body, string expectedKeyAuthz) =>
        body == expectedKeyAuthz ? "ok"
        : string.IsNullOrWhiteSpace(body) ? "empty body (HTTP 200)"
        : "content mismatch";

    /// <summary>
    /// Resolves <paramref name="host"/> against the operating-system hosts file
    /// (<c>/etc/hosts</c> on Unix, <c>%SystemRoot%\System32\drivers\etc\hosts</c> on
    /// Windows) and returns every matching A/AAAA address. The DNS-protocol resolver
    /// used for validation never consults the hosts file, so internal deployments that
    /// map the identifier locally would otherwise be unreachable. Comments
    /// (<c>#</c>...) are stripped and hostname matching is case- and trailing-dot
    /// insensitive. Returns an empty list on any read/parse error (best-effort).
    /// </summary>
    private static async Task<List<IPAddress>> ResolveFromHostsFileAsync(string host)
    {
        var matches = new List<IPAddress>();
        try
        {
            var path = OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts")
                : "/etc/hosts";
            if (!File.Exists(path)) return matches;

            var target = host.TrimEnd('.').ToLowerInvariant();
            foreach (var raw in await File.ReadAllLinesAsync(path))
            {
                var line = raw;
                var hash = line.IndexOf('#');
                if (hash >= 0) line = line[..hash];
                line = line.Trim();
                if (line.Length == 0) continue;

                // Format: <IP> <hostname> [aliases...] separated by whitespace.
                var tokens = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 2 || !IPAddress.TryParse(tokens[0], out var ip)) continue;

                for (var i = 1; i < tokens.Length; i++)
                {
                    if (string.Equals(tokens[i].TrimEnd('.'), target, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!matches.Contains(ip)) matches.Add(ip);
                        break;
                    }
                }
            }
        }
        catch
        {
            // Best-effort: hosts file unreadable/missing — fall back to DNS only.
        }
        return matches;
    }

    /// <summary>
    /// Allow only redirects to the same identifier or
    /// something that shares the same last-two-label apex (simple eTLD+1
    /// heuristic). Bare IPs are rejected outright.
    /// </summary>
    private static bool IsHostAllowed(string redirectHost, string challengedIdentifier)
    {
        if (IPAddress.TryParse(redirectHost, out _))
            return false; // redirect to bare IP — reject

        redirectHost = redirectHost.TrimEnd('.').ToLowerInvariant();
        var orig = challengedIdentifier.TrimEnd('.').ToLowerInvariant();

        if (redirectHost == orig) return true;

        static string Apex(string host)
        {
            var parts = host.Split('.');
            return parts.Length >= 2 ? $"{parts[^2]}.{parts[^1]}" : host;
        }

        return Apex(redirectHost) == Apex(orig);
    }

    /// <summary>
    /// Rejects RFC 1918, loopback, link-local, and ULA
    /// addresses so a public ACME deployment cannot be tricked into validating
    /// against an internal host. Also rejects <c>0.0.0.0</c>, multicast, and
    /// unspecified IPv6.
    /// </summary>
    private static bool IsPrivateAddress(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return true;

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (b[0] == 10) return true;
            // 172.16.0.0/12
            if (b[0] == 172 && (b[1] & 0xF0) == 16) return true;
            // 192.168.0.0/16
            if (b[0] == 192 && b[1] == 168) return true;
            // 169.254.0.0/16 link-local
            if (b[0] == 169 && b[1] == 254) return true;
            // 100.64.0.0/10 CGNAT
            if (b[0] == 100 && (b[1] & 0xC0) == 64) return true;
            // 127.0.0.0/8
            if (b[0] == 127) return true;
            // 0.0.0.0/8
            if (b[0] == 0) return true;
            // 224.0.0.0/4 multicast
            if ((b[0] & 0xF0) == 224) return true;
        }
        else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            // fc00::/7 ULA
            if ((b[0] & 0xFE) == 0xFC) return true;
            // fe80::/10 link-local (also caught by IsIPv6LinkLocal)
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;
        }

        return false;
    }

    /// <summary>
    /// DNS-01 validator uses an explicit
    /// <see cref="LookupClientOptions"/> with caching disabled and recursion
    /// enabled, so a stale cached TXT record can't pass validation after the
    /// record is removed. Multi-perspective DNS remains a future improvement
    /// and is tracked in the code comment below.
    /// </summary>
    public async Task ValidateDns01Async(Guid challengeId, string accountThumbprint)
    {
        var entity = await _db.AcmeChallenges
            .Include(c => c.Authorization)
            .Where(c => c.Id == challengeId)
            .FirstOrDefaultAsync()
            ?? throw new InvalidOperationException("Challenge not found.");

        var domain = entity.Authorization!.IdentifierValue;
        var keyAuthz = $"{entity.Token}.{accountThumbprint}";
        var expectedHash = Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(keyAuthz)));

        var dnsName = $"_acme-challenge.{domain}";

        try
        {
            // Disable DnsClient's internal cache and enforce
            // recursion. Future work: add multi-perspective lookups per CA/BR
            // §3.2.2.4.7 by querying multiple external resolvers and requiring
            // agreement.
            var lookup = new LookupClient(new LookupClientOptions
            {
                UseCache = false,
                Recursion = true,
                Timeout = TimeSpan.FromSeconds(5),
                Retries = 1
            });
            var result = await lookup.QueryAsync(dnsName, QueryType.TXT);
            var txtRecords = result.Answers.TxtRecords()
                .SelectMany(r => r.Text)
                .ToList();

            if (txtRecords.Contains(expectedHash))
            {
                entity.Status = nameof(AcmeChallengeStatus.Valid);
                entity.ValidatedAt = DateTime.UtcNow;
            }
            else
            {
                entity.Status = nameof(AcmeChallengeStatus.Invalid);
                entity.ErrorJson = System.Text.Json.JsonSerializer.Serialize(new AcmeErrorResponse
                {
                    Type = "urn:ietf:params:acme:error:dns",
                    Detail = $"No matching TXT record found at {dnsName}.",
                    Status = 400
                });
            }
        }
        catch (Exception ex)
        {
            entity.Status = nameof(AcmeChallengeStatus.Invalid);
            entity.ErrorJson = System.Text.Json.JsonSerializer.Serialize(new AcmeErrorResponse
            {
                Type = "urn:ietf:params:acme:error:dns",
                Detail = $"DNS lookup failed for {dnsName}: {ex.Message}",
                Status = 400
            });
        }

        entity.NextAttemptAt = null;
        await _db.SaveChangesAsync();

        if (entity.Status == nameof(AcmeChallengeStatus.Invalid))
            await RecordFailedValidationAsync(challengeId);
    }

    private static async Task MarkChallengeInvalidAsync(ModularCADbContext db, Guid challengeId, string detail)
    {
        var entity = await db.AcmeChallenges.FindAsync(challengeId);
        if (entity == null) return;

        entity.Status = nameof(AcmeChallengeStatus.Invalid);
        entity.ErrorJson = System.Text.Json.JsonSerializer.Serialize(new AcmeErrorResponse
        {
            Type = "urn:ietf:params:acme:error:serverInternal",
            Detail = detail,
            Status = 500
        });
        await db.SaveChangesAsync();
    }

    public async Task<Guid?> GetAuthorizationIdForChallengeAsync(Guid challengeId)
    {
        var entity = await _db.AcmeChallenges.FindAsync(challengeId);
        return entity?.AuthorizationId;
    }

    /// <summary>
    /// Retrieves the account ID that owns the order containing this challenge's authorization.
    /// </summary>
    public async Task<Guid?> GetAccountIdForChallengeAsync(Guid challengeId)
    {
        var challenge = await _db.AcmeChallenges
            .Include(c => c.Authorization)
                .ThenInclude(a => a!.Order)
            .FirstOrDefaultAsync(c => c.Id == challengeId);
        return challenge?.Authorization?.Order?.AccountId;
    }

    private static AcmeChallengeDto MapToDto(AcmeChallengeEntity entity, string baseUrl) => new()
    {
        Id = entity.Id,
        Type = entity.Type,
        Url = $"{baseUrl}/api/v1/acme/challenge/{entity.Id}",
        Token = entity.Token,
        Status = entity.Status.ToLowerInvariant(),
        ValidatedAt = entity.ValidatedAt,
        // Surface the stored validation-failure problem document (RFC 8555 §8) so the
        // challenge object carries the reason it went invalid.
        Error = DeserializeError(entity.ErrorJson)
    };

    /// <summary>
    /// Deserializes a challenge's stored <c>ErrorJson</c> into an
    /// <see cref="AcmeErrorResponse"/> for inclusion in the challenge object.
    /// Returns null when absent or unparseable so a malformed record never breaks
    /// the response.
    /// </summary>
    private static AcmeErrorResponse? DeserializeError(string? errorJson)
    {
        if (string.IsNullOrWhiteSpace(errorJson)) return null;
        try { return System.Text.Json.JsonSerializer.Deserialize<AcmeErrorResponse>(errorJson); }
        catch (System.Text.Json.JsonException) { return null; }
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
