using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>
/// The CA certificates that anchor client-certificate validation for mTLS, loaded once at start
/// and shared by the TLS handshake on the mTLS auth subdomain and by <c>MtlsMiddleware</c>, so
/// both trust the same set.
/// </summary>
public sealed class MtlsTrustAnchors
{
    /// <summary>The anchors that loaded.</summary>
    public List<X509Certificate2> Certificates { get; } = [];

    /// <summary>One line per configured path or database row that did not load, and why.</summary>
    public List<string> Failures { get; } = [];

    /// <summary>
    /// Loads the anchors. Each <see cref="MtlsConfig.TrustedCaCertPaths"/> entry is read, a relative
    /// path resolved against the application base directory, not the working directory, which
    /// differs between a console run, a systemd unit and a Windows service. When none loads, mTLS
    /// is on, this is not setup mode and <paramref name="appConnStr"/> is given, the certificates
    /// of the CAs groups name as their mTLS signing CA (<c>CaGroups.MtlsSigningCaId</c>) are used
    /// instead: every client certificate the mTLS login issues comes from one of them. Paths win
    /// when any loads, since an operator who lists them is asserting a narrower or external trust
    /// set. Failures are recorded, reported to the console and the log, and never thrown.
    /// </summary>
    /// <param name="config">The configuration.</param>
    /// <param name="appConnStr">The application database, or null to read the configured paths only.</param>
    /// <param name="isSetupMode">True while the setup wizard runs; the database is not read then.</param>
    public static MtlsTrustAnchors Load(SystemConfig config, string? appConnStr, bool isSetupMode)
    {
        var anchors = new MtlsTrustAnchors();
        foreach (var path in config.Mtls.TrustedCaCertPaths ?? [])
        {
            if (string.IsNullOrWhiteSpace(path))
                continue;
            var anchorPath = Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
            try
            {
                if (!File.Exists(anchorPath))
                {
                    anchors.Failures.Add($"{path} — file not found (resolved to {anchorPath})");
                    continue;
                }
                anchors.Certificates.Add(X509CertificateLoader.LoadCertificateFromFile(anchorPath));
            }
            catch (Exception ex)
            {
                anchors.Failures.Add($"{path} — {ex.GetType().Name}: {ex.Message}");
            }
        }

        if (anchors.Failures.Count > 0)
        {
            Console.WriteLine("[mTLS WARNING] One or more Mtls.TrustedCaCertPaths entries could not be loaded:");
            foreach (var failure in anchors.Failures)
                Console.WriteLine($"               {failure}");
            Log.Warning("[SECURITY] {Count} configured mTLS trust anchor(s) failed to load: {Failures}",
                anchors.Failures.Count, string.Join(" | ", anchors.Failures));
        }

        if (anchors.Certificates.Count == 0 && !isSetupMode && config.Mtls.Enabled && !string.IsNullOrEmpty(appConnStr))
            anchors.SeedFromDatabase(appConnStr);
        return anchors;
    }

    private void SeedFromDatabase(string appConnStr)
    {
        try
        {
            using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(appConnStr).Options);
            var mtlsCaIds = db.CaGroups.AsNoTracking()
                .Where(g => g.MtlsSigningCaId != null)
                .Select(g => g.MtlsSigningCaId!.Value)
                .Distinct()
                .ToList();
            var caCertIds = db.CertificateAuthorities.AsNoTracking()
                .Where(ca => mtlsCaIds.Contains(ca.Id) && ca.CertificateId != null)
                .Select(ca => ca.CertificateId!.Value)
                .Distinct()
                .ToList();
            var raws = db.Certificates.AsNoTracking()
                .Where(c => caCertIds.Contains(c.CertificateId))
                .Select(c => c.RawCertificate)
                .ToList();

            foreach (var raw in raws)
            {
                if (raw == null || raw.Length == 0)
                    continue;
                try
                {
                    Certificates.Add(X509CertificateLoader.LoadCertificate(raw));
                }
                catch (Exception ex)
                {
                    Failures.Add($"database-seeded anchor — {ex.GetType().Name}: {ex.Message}");
                }
            }

            if (Certificates.Count > 0)
                Console.WriteLine($"[mTLS] Seeded {Certificates.Count} trust anchor(s) from enrolled mTLS signing CAs (Mtls.TrustedCaCertPaths is empty).");
        }
        catch (Exception ex)
        {
            // Not the same as "no anchors exist": the startup refusal names the cause.
            Failures.Add($"database anchor lookup failed — {ex.GetType().Name}: {ex.Message}");
            Log.Warning(ex, "[SECURITY] Could not read enrolled mTLS signing CAs for trust-anchor seeding.");
        }
    }
}
