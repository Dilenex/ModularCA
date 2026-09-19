using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>
/// The endpoint certificates for tenant hostnames, keyed by name, held in memory for the TLS
/// handshake and refreshed off it.
/// </summary>
/// <remarks>
/// <para>
/// Kestrel asks for a certificate on every connection, inside a ten-second handshake budget, so
/// the lookup here is a dictionary read and nothing else. The snapshot is rebuilt two ways: any
/// change made in this process (a name added or removed, a certificate reissued or renewed)
/// calls <see cref="Reload"/> as its last step, so the next handshake sees it; and a snapshot
/// older than the refresh interval triggers a background rebuild on the next lookup, which
/// catches a change made by another replica or a certificate renewed on disk. A failed rebuild
/// keeps the previous snapshot: serving an older certificate for a name beats serving the
/// console's certificate for a name it does not carry.
/// </para>
/// </remarks>
public sealed class TenantHostnameCertificateCache
{
    private readonly Func<IReadOnlyDictionary<string, X509Certificate2>> _load;
    private readonly TimeSpan _refreshInterval;
    private readonly Action<string>? _onError;

    private volatile IReadOnlyDictionary<string, X509Certificate2> _current =
        new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
    private long _nextRefreshTicks;
    private int _refreshInFlight;

    /// <summary>Shortest honoured refresh interval, so a misconfigured zero cannot hammer the database.</summary>
    public static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Creates the cache.
    /// </summary>
    /// <param name="load">Reads every hostname's certificate; the keys are hostnames. Called on each rebuild.</param>
    /// <param name="refreshInterval">Age after which a lookup triggers a background rebuild.</param>
    /// <param name="onError">Receives a message when a rebuild throws; the previous snapshot is kept.</param>
    public TenantHostnameCertificateCache(
        Func<IReadOnlyDictionary<string, X509Certificate2>> load,
        TimeSpan refreshInterval,
        Action<string>? onError = null)
    {
        _load = load;
        _refreshInterval = refreshInterval < MinimumRefreshInterval ? MinimumRefreshInterval : refreshInterval;
        _onError = onError;
    }

    /// <summary>Number of names in the snapshot being served.</summary>
    public int Count => _current.Count;

    /// <summary>The names in the snapshot being served.</summary>
    public IReadOnlyCollection<string> Hostnames => _current.Keys.ToArray();

    /// <summary>
    /// The certificate for a TLS server name, by exact, case-insensitive match; null when the
    /// name is unknown or the client sent none. Never blocks and never throws.
    /// </summary>
    public X509Certificate2? Find(string? serverName)
    {
        var snapshot = _current;
        if (DateTime.UtcNow.Ticks >= Interlocked.Read(ref _nextRefreshTicks))
            TriggerRefresh();
        if (string.IsNullOrEmpty(serverName)) return null;
        return snapshot.TryGetValue(serverName, out var cert) ? cert : null;
    }

    /// <summary>Rebuilds the snapshot synchronously. Returns the number of names loaded.</summary>
    public int LoadNow()
    {
        Interlocked.Exchange(ref _nextRefreshTicks, (DateTime.UtcNow + _refreshInterval).Ticks);
        var loaded = Read();
        if (loaded != null) _current = loaded;
        return _current.Count;
    }

    /// <summary>Rebuilds the snapshot after a change made in this process.</summary>
    public void Reload() => LoadNow();

    private void TriggerRefresh()
    {
        if (Interlocked.CompareExchange(ref _refreshInFlight, 1, 0) != 0) return;
        Interlocked.Exchange(ref _nextRefreshTicks, (DateTime.UtcNow + _refreshInterval).Ticks);
        _ = Task.Run(() =>
        {
            try
            {
                var loaded = Read();
                if (loaded != null) _current = loaded;
            }
            finally
            {
                Interlocked.Exchange(ref _refreshInFlight, 0);
            }
        });
    }

    private IReadOnlyDictionary<string, X509Certificate2>? Read()
    {
        try
        {
            var loaded = _load();
            // Always a case-insensitive map, whatever the loader built.
            return new Dictionary<string, X509Certificate2>(loaded, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            _onError?.Invoke(ex.Message);
            return null;
        }
    }
}

/// <summary>Picks the server certificate for a TLS connection from the name the client asked for.</summary>
public static class TlsServerCertificateSelector
{
    /// <summary>
    /// The certificate for <paramref name="serverName"/> when it is a tenant hostname with one,
    /// otherwise <paramref name="fallback"/>: the console's own certificate, which also answers the
    /// public domain, unknown names, and clients that send no SNI.
    /// </summary>
    public static X509Certificate2? Select(string? serverName, TenantHostnameCertificateCache hostnames, X509Certificate2? fallback)
        => hostnames.Find(serverName) ?? fallback;
}
