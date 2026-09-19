using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services;

/// <summary>
/// The CA certificates a node knows when it holds no keystore: the node role with a remote
/// signer never decrypts the keystore files, so the certificates the keystore used to supply
/// come from the database instead. <see cref="GetSigners"/> is the certificate of every CA
/// row that has one; <see cref="GetTrustedAuthorities"/> is every CA certificate row plus
/// every enabled trust anchor, which is what the trust keystore held. Both are refreshed at
/// most once a minute; a trust anchor registered at runtime joins the list at once, as it
/// did in the keystore registry.
/// </summary>
public sealed class DatabaseKeystoreCertificates : IKeystoreCertificates
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(60);

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<DatabaseKeystoreCertificates> _logger;
    private readonly object _lock = new();
    private readonly List<X509Certificate> _registered = new();
    private List<X509Certificate> _trusted = new();
    private List<X509Certificate> _signers = new();
    private DateTime _loadedAt = DateTime.MinValue;

    /// <summary>Creates the registry over the application database.</summary>
    public DatabaseKeystoreCertificates(IServiceScopeFactory scopes, ILogger<DatabaseKeystoreCertificates> logger)
    {
        _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public List<X509Certificate> GetTrustedAuthorities()
    {
        lock (_lock)
        {
            Refresh();
            var all = new List<X509Certificate>(_trusted);
            foreach (var cert in _registered)
            {
                if (!all.Any(t => t.SerialNumber.Equals(cert.SerialNumber)))
                    all.Add(cert);
            }
            return all;
        }
    }

    /// <inheritdoc />
    public List<CertificateAuthorityIdentity> GetSigners()
    {
        lock (_lock)
        {
            Refresh();
            return _signers.Select(c => new CertificateAuthorityIdentity(c)).ToList();
        }
    }

    /// <inheritdoc />
    public void RegisterTrustedCert(X509Certificate cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        lock (_lock)
        {
            if (!_registered.Any(t => t.SerialNumber.Equals(cert.SerialNumber)))
                _registered.Add(cert);
        }
    }

    /// <summary>
    /// Reloads both lists from the database once the cache has aged out. A read that fails
    /// keeps what was loaded before, so a database blip does not empty the node's view of its
    /// CAs; the failure is logged.
    /// </summary>
    private void Refresh()
    {
        if (_loadedAt + Ttl > DateTime.UtcNow)
            return;
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

            var caCertificateIds = db.CertificateAuthorities.AsNoTracking()
                .Where(ca => !ca.IsDeleted && ca.CertificateId != null)
                .Select(ca => ca.CertificateId!.Value)
                .ToList();
            var caRows = db.Certificates.AsNoTracking()
                .Where(c => c.IsCA)
                .ToList();
            var anchors = db.TrustAnchors.AsNoTracking()
                .Where(a => a.IsEnabled)
                .ToList();

            var byId = new Dictionary<Guid, X509Certificate>();
            var trusted = new List<X509Certificate>();
            foreach (var row in caRows)
            {
                var cert = TryParse(row.RawCertificate, row.Pem);
                if (cert == null) continue;
                byId[row.CertificateId] = cert;
                trusted.Add(cert);
            }
            foreach (var anchor in anchors)
            {
                var cert = TryParse(anchor.RawCertificate, anchor.Pem);
                if (cert != null && !trusted.Any(t => t.SerialNumber.Equals(cert.SerialNumber)))
                    trusted.Add(cert);
            }

            _signers = caCertificateIds.Where(byId.ContainsKey).Select(id => byId[id]).ToList();
            _trusted = trusted;
            _loadedAt = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "The CA certificates could not be read from the database; keeping the {Count} loaded before.", _signers.Count);
            _loadedAt = DateTime.UtcNow - Ttl + TimeSpan.FromSeconds(5);
        }
    }

    private static X509Certificate? TryParse(byte[]? raw, string? pem)
    {
        try
        {
            if (raw is { Length: > 0 })
                return new X509Certificate(raw);
            if (!string.IsNullOrWhiteSpace(pem))
                return CertificateUtil.ParseFromPem(pem);
        }
        catch
        {
            // An unparseable row is not a CA the node can name; skipped.
        }
        return null;
    }
}
