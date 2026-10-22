using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Core.Services.Est;

/// <summary>
/// The set of certificates that authorise an EST client certificate, and the chain material needed
/// to validate one.
/// </summary>
/// <param name="EstCaCerts">Certificates of the CAs that had EST enabled when this was loaded.</param>
/// <param name="ChainCerts">Every other CA certificate, used only to complete a chain.</param>
/// <param name="LoadedUtc">When this snapshot was read.</param>
public sealed record EstTrustAnchorSet(
    IReadOnlyList<X509Certificate2> EstCaCerts,
    IReadOnlyList<X509Certificate2> ChainCerts,
    DateTime LoadedUtc)
{
    /// <summary>An empty set. Every certificate validated against it is rejected.</summary>
    public static readonly EstTrustAnchorSet Empty = new([], [], DateTime.MinValue);
}

/// <summary>
/// Caches the EST client-certificate trust anchors, refreshing them off the TLS handshake path.
/// </summary>
/// <remarks>
/// <para>
/// The anchor set answers "which CAs currently have EST enabled", which an administrator changes at
/// runtime from the admin UI. Reading it once at startup — the way the mTLS login anchors are read
/// — would mean enabling EST on a CA appears to succeed while every device under that CA fails the
/// TLS handshake until someone restarts the service, with nothing in the logs connecting the two.
/// That failure shape has already cost this project several days across other settings.
/// </para>
/// <para>
/// A database query cannot run per connection, so a snapshot is held and refreshed on a timer read.
/// A handshake that finds the snapshot stale uses it anyway and triggers a background refresh: the
/// connection in hand is answered with anchors that were correct a minute ago, and the next one
/// sees the new set. Blocking the handshake on a database round trip would put the database on the
/// critical path of every enrollment, inside a ten-second handshake budget.
/// </para>
/// <para>
/// A failed refresh keeps the previous snapshot rather than emptying it. An empty set rejects every
/// certificate, so treating a transient database error as "no CAs have EST enabled" would turn a
/// blip into a fleet-wide enrollment outage.
/// </para>
/// </remarks>
public sealed class EstTrustAnchorCache
{
    private readonly Func<ModularCADbContext> _dbFactory;
    private readonly Func<TimeSpan> _refreshInterval;
    private readonly Action<string>? _onError;

    private volatile EstTrustAnchorSet _current = EstTrustAnchorSet.Empty;
    private int _refreshInFlight;

    // When a refresh was last attempted, in UTC ticks. Tracked separately from the
    // snapshot's LoadedUtc so that a failed refresh throttles the next attempt without
    // pretending the snapshot is fresh. An earlier version re-stamped LoadedUtc on failure,
    // which made a CA whose EST was disabled during a database outage look freshly trusted.
    private long _lastAttemptTicks;

    /// <summary>Shortest honoured refresh interval, so a misconfigured zero cannot hammer the database.</summary>
    public static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Creates the cache with a fixed refresh interval.
    /// </summary>
    /// <param name="dbFactory">Creates a short-lived context for each refresh.</param>
    /// <param name="refreshInterval">How long a snapshot is used before a refresh is triggered.</param>
    /// <param name="onError">Receives a message when a refresh fails; the previous snapshot is kept.</param>
    public EstTrustAnchorCache(
        Func<ModularCADbContext> dbFactory,
        TimeSpan refreshInterval,
        Action<string>? onError = null)
        : this(dbFactory, () => refreshInterval, onError)
    {
    }

    /// <summary>
    /// Creates the cache with a refresh interval that is asked for each time the snapshot is
    /// read, so a change to it applies to the snapshot already held.
    /// </summary>
    /// <param name="dbFactory">Creates a short-lived context for each refresh.</param>
    /// <param name="refreshInterval">How long a snapshot is used before a refresh is triggered, as it stands now. Must not block or throw.</param>
    /// <param name="onError">Receives a message when a refresh fails; the previous snapshot is kept.</param>
    public EstTrustAnchorCache(
        Func<ModularCADbContext> dbFactory,
        Func<TimeSpan> refreshInterval,
        Action<string>? onError = null)
    {
        _dbFactory = dbFactory;
        _refreshInterval = refreshInterval;
        _onError = onError;
    }

    /// <summary>The refresh interval in force now, in ticks, never below <see cref="MinimumRefreshInterval"/>.</summary>
    private long IntervalTicks => Math.Max(_refreshInterval().Ticks, MinimumRefreshInterval.Ticks);

    /// <summary>
    /// Returns the current snapshot, triggering a background refresh when the last attempt is
    /// older than the refresh interval in force now.
    /// </summary>
    /// <remarks>
    /// Safe to call from the TLS handshake callback: it never blocks and never throws.
    /// </remarks>
    public EstTrustAnchorSet Current
    {
        get
        {
            var snapshot = _current;
            if (DateTime.UtcNow.Ticks - Interlocked.Read(ref _lastAttemptTicks) >= IntervalTicks)
                TriggerRefresh();
            return snapshot;
        }
    }

    /// <summary>
    /// Reads the anchor set synchronously. Called once at startup so the first handshake is not
    /// answered from an empty set.
    /// </summary>
    /// <returns>The number of EST-enabled CA certificates loaded.</returns>
    public int LoadNow()
    {
        Interlocked.Exchange(ref _lastAttemptTicks, DateTime.UtcNow.Ticks);
        var loaded = Read();
        if (loaded != null)
            _current = loaded;
        return _current.EstCaCerts.Count;
    }

    /// <summary>Age of the snapshot currently being served.</summary>
    public TimeSpan SnapshotAge => DateTime.UtcNow - _current.LoadedUtc;

    private void TriggerRefresh()
    {
        // One refresh at a time. A burst of connections arriving just after the interval elapses
        // would otherwise each start their own query.
        if (Interlocked.CompareExchange(ref _refreshInFlight, 1, 0) != 0)
            return;

        // Throttle the next attempt whether or not this one succeeds, so a database that is down
        // does not produce a refresh attempt per connection for as long as it stays down. The
        // snapshot's own timestamp is left alone: an old snapshot is still old.
        Interlocked.Exchange(ref _lastAttemptTicks, DateTime.UtcNow.Ticks);

        _ = Task.Run(() =>
        {
            try
            {
                var loaded = Read();
                if (loaded != null)
                    _current = loaded;
            }
            finally
            {
                Interlocked.Exchange(ref _refreshInFlight, 0);
            }
        });
    }

    /// <summary>Reads a fresh snapshot, or null when the read failed.</summary>
    private EstTrustAnchorSet? Read()
    {
        try
        {
            using var db = _dbFactory();

            var estCaIds = db.CaProtocolConfigs
                .AsNoTracking()
                .Where(c => c.Protocol == "EST" && c.IsEnabled)
                .Select(c => c.CaId)
                .Distinct()
                .ToList();

            // Every CA certificate is read, then split. The EST-enabled ones authorise; the rest are
            // chain material only, because an EST-enabled CA is often an intermediate whose issuers
            // must be present for the chain to terminate.
            // Disabled CAs anchor nothing. Disabling a CA is the operator's response to a
            // compromise, and its EST row may well still say enabled; the CA's own switch wins.
            var allCas = db.CertificateAuthorities
                .AsNoTracking()
                .Where(ca => ca.CertificateId != null && ca.IsEnabled)
                .Select(ca => new { ca.Id, CertificateId = ca.CertificateId!.Value })
                .ToList();

            var certIds = allCas.Select(c => c.CertificateId).Distinct().ToList();
            var rawById = db.Certificates
                .AsNoTracking()
                .Where(c => certIds.Contains(c.CertificateId))
                .Select(c => new { c.CertificateId, c.RawCertificate })
                .ToDictionary(c => c.CertificateId, c => c.RawCertificate);

            var estCerts = new List<X509Certificate2>();
            var chainCerts = new List<X509Certificate2>();

            foreach (var ca in allCas)
            {
                if (!rawById.TryGetValue(ca.CertificateId, out var raw) || raw == null || raw.Length == 0)
                    continue;

                X509Certificate2 cert;
                try
                {
                    cert = X509CertificateLoader.LoadCertificate(raw);
                }
                catch (Exception ex)
                {
                    // One unreadable CA certificate must not cost every other CA its anchors.
                    _onError?.Invoke($"CA {ca.Id} certificate could not be loaded — {ex.GetType().Name}: {ex.Message}");
                    continue;
                }

                if (estCaIds.Contains(ca.Id))
                    estCerts.Add(cert);
                else
                    chainCerts.Add(cert);
            }

            return new EstTrustAnchorSet(estCerts, chainCerts, DateTime.UtcNow);
        }
        catch (Exception ex)
        {
            _onError?.Invoke($"EST trust-anchor refresh failed — {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }
}
