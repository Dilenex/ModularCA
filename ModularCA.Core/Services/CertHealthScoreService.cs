using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Shared.Models.Config;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Text.Json;

namespace ModularCA.Core.Services;

/// <summary>
/// Evaluates certificate health by inspecting key strength, signature algorithm,
/// validity window, revocation status, vulnerability findings, CT submission,
/// and wildcard usage. Scores start at 100 and are reduced by each failing factor.
/// </summary>
public class CertHealthScoreService : ICertHealthScoreService
{
    private readonly ModularCADbContext _db;
    private readonly ILogger<CertHealthScoreService> _logger;
    private readonly ComplianceScanConfig _compliance;

    /// <summary>
    /// The CA/Browser Forum maximum for publicly trusted TLS. A fixed property of public web PKI
    /// rather than a setting of this installation, so it stays a constant — but it is only applied
    /// to certificates that are actually TLS certificates.
    /// </summary>
    private const int PublicTlsMaxValidityDays = 398;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertHealthScoreService"/> class.
    /// </summary>
    /// <param name="db">Database context for certificate and vulnerability lookups.</param>
    /// <param name="logger">Logger for diagnostic output.</param>
    /// <param name="systemConfig">Supplies the compliance scanner's validity threshold.</param>
    public CertHealthScoreService(ModularCADbContext db, ILogger<CertHealthScoreService> logger, SystemConfig systemConfig)
    {
        _db = db;
        _logger = logger;
        _compliance = systemConfig.ComplianceScan;
    }

    /// <inheritdoc />
    public async Task<CertHealthScore> CalculateScoreAsync(Guid certificateId)
    {
        var cert = await _db.Certificates
            .AsNoTracking()
            .Include(c => c.CertProfile)
            .FirstOrDefaultAsync(c => c.CertificateId == certificateId);

        if (cert == null)
            throw new KeyNotFoundException($"Certificate {certificateId} not found.");

        var vulnerabilities = await _db.CertComplianceFindings
            .AsNoTracking()
            .Where(v => v.CertificateId == certificateId && !v.IsResolved)
            .ToListAsync();

        return Evaluate(cert, vulnerabilities);
    }

    /// <inheritdoc />
    public async Task<List<CertHealthScore>> CalculateBulkScoresAsync(List<Guid> certificateIds)
    {
        if (certificateIds == null || certificateIds.Count == 0)
            return new List<CertHealthScore>();

        var certs = await _db.Certificates
            .AsNoTracking()
            .Include(c => c.CertProfile)
            .Where(c => certificateIds.Contains(c.CertificateId))
            .ToListAsync();

        var vulns = await _db.CertComplianceFindings
            .AsNoTracking()
            .Where(v => certificateIds.Contains(v.CertificateId) && !v.IsResolved)
            .ToListAsync();

        var vulnsByCert = vulns
            .GroupBy(v => v.CertificateId)
            .ToDictionary(g => g.Key, g => g.ToList());

        var results = new List<CertHealthScore>();
        foreach (var cert in certs)
        {
            vulnsByCert.TryGetValue(cert.CertificateId, out var certVulns);
            results.Add(Evaluate(cert, certVulns ?? new List<CertComplianceFindingEntity>()));
        }

        return results;
    }

    /// <summary>
    /// Runs all scoring rules against a single certificate entity and its active vulnerabilities.
    /// </summary>
    private CertHealthScore Evaluate(CertificateEntity cert, List<CertComplianceFindingEntity> vulnerabilities)
    {
        var factors = new List<CertHealthFactor>();
        var now = DateTime.UtcNow;

        // --- Parse the certificate via BouncyCastle to inspect key and signature ---
        X509Certificate? x509 = null;
        AsymmetricKeyParameter? pubKey = null;
        try
        {
            if (cert.RawCertificate != null && cert.RawCertificate.Length > 0)
            {
                x509 = new X509Certificate(cert.RawCertificate);
            }
            else if (!string.IsNullOrWhiteSpace(cert.Pem))
            {
                x509 = ModularCA.Shared.Utils.CertificateUtil.ParseFromPem(cert.Pem);
            }

            if (x509 != null)
                pubKey = x509.GetPublicKey();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse certificate {CertId} for health scoring", cert.CertificateId);
        }

        // --- Key strength checks ---
        if (pubKey is RsaKeyParameters rsa)
        {
            var bits = rsa.Modulus.BitLength;
            if (bits < 2048)
            {
                factors.Add(new CertHealthFactor
                {
                    Name = "WeakRsaKey",
                    Points = 40,
                    Description = $"RSA key is {bits} bits, below the 2048-bit minimum.",
                    Severity = "Critical"
                });
            }
            else if (bits == 2048)
            {
                factors.Add(new CertHealthFactor
                {
                    Name = "RsaKey2048",
                    Points = 10,
                    Description = "RSA 2048-bit key is considered weak by 2030 standards.",
                    Severity = "Warning"
                });
            }
        }

        // --- Post-quantum key checks ---
        if (pubKey is MLDsaPublicKeyParameters || pubKey is SlhDsaPublicKeyParameters)
        {
            factors.Add(new CertHealthFactor
            {
                Name = "PqcKey",
                Points = -5,
                Description = "Certificate uses a post-quantum key algorithm, providing quantum-resistant security.",
                Severity = "Info"
            });
        }

        // --- Signature algorithm checks ---
        if (x509 != null)
        {
            var sigAlg = x509.SigAlgName.ToUpperInvariant();

            if (sigAlg.Contains("MD5"))
            {
                factors.Add(new CertHealthFactor
                {
                    Name = "Md5Signature",
                    Points = 50,
                    Description = "Certificate uses MD5 signature algorithm which is cryptographically broken.",
                    Severity = "Critical"
                });
            }
            else if (sigAlg.Contains("SHA1") || sigAlg.Contains("SHA-1"))
            {
                factors.Add(new CertHealthFactor
                {
                    Name = "Sha1Signature",
                    Points = 40,
                    Description = "Certificate uses SHA-1 signature algorithm which is deprecated.",
                    Severity = "Critical"
                });
            }
        }

        // --- Validity period checks ---
        // Both thresholds used to be literals — 825 and 398 — applied to every certificate in the
        // installation. That is public web PKI's rulebook scoring a private CA's work: a five-year
        // device identity, entirely legitimate and deliberately issued, was marked unhealthy
        // forever with no setting anywhere to say otherwise. The upper bound now comes from the
        // compliance scanner's own configured threshold, and the public TLS limit is applied only
        // to certificates that are actually TLS certificates.
        var validityDays = (cert.NotAfter - cert.NotBefore).TotalDays;
        var complianceThreshold = _compliance.WarnOverValidityDays;
        bool isTls = IsTlsCertificate(cert);

        if (complianceThreshold > 0 && validityDays > complianceThreshold)
        {
            factors.Add(new CertHealthFactor
            {
                Name = "OverLongValidity",
                Points = 25,
                Description = $"Validity period is {(int)validityDays} days, exceeding the configured {complianceThreshold}-day compliance threshold.",
                Severity = "Warning"
            });
        }
        else if (isTls && validityDays > PublicTlsMaxValidityDays)
        {
            factors.Add(new CertHealthFactor
            {
                Name = "OverLongValidityPublicTls",
                Points = 15,
                Description = $"Validity period is {(int)validityDays} days, exceeding the {PublicTlsMaxValidityDays}-day CA/Browser Forum limit for publicly trusted TLS.",
                Severity = "Warning"
            });
        }

        // --- SAN check for TLS certificates ---
        bool isTlsCert = isTls;
        if (isTlsCert)
        {
            var hasSans = !string.IsNullOrWhiteSpace(cert.SubjectAlternativeNamesJson)
                && cert.SubjectAlternativeNamesJson != "[]";
            if (!hasSans)
            {
                factors.Add(new CertHealthFactor
                {
                    Name = "MissingSans",
                    Points = 20,
                    Description = "TLS certificate has no Subject Alternative Names.",
                    Severity = "Warning"
                });
            }
        }

        // --- Expiry checks (most specific first, only one applies) ---
        if (cert.NotAfter < now)
        {
            factors.Add(new CertHealthFactor
            {
                Name = "Expired",
                Points = 50,
                Description = $"Certificate expired on {cert.NotAfter:yyyy-MM-dd}.",
                Severity = "Critical"
            });
        }
        else if ((cert.NotAfter - now).TotalDays <= 7)
        {
            factors.Add(new CertHealthFactor
            {
                Name = "ExpiringWithin7Days",
                Points = 30,
                Description = $"Certificate expires in {(int)(cert.NotAfter - now).TotalDays} day(s).",
                Severity = "Critical"
            });
        }
        else if ((cert.NotAfter - now).TotalDays <= 30)
        {
            factors.Add(new CertHealthFactor
            {
                Name = "ExpiringWithin30Days",
                Points = 15,
                Description = $"Certificate expires in {(int)(cert.NotAfter - now).TotalDays} days.",
                Severity = "Warning"
            });
        }

        // --- Revocation ---
        if (cert.Revoked)
        {
            factors.Add(new CertHealthFactor
            {
                Name = "Revoked",
                Points = 100,
                Description = "Certificate has been revoked.",
                Severity = "Critical"
            });
        }

        // --- Active vulnerabilities ---
        if (vulnerabilities.Count > 0)
        {
            foreach (var vuln in vulnerabilities)
            {
                factors.Add(new CertHealthFactor
                {
                    Name = $"Vulnerability:{vuln.Type}",
                    Points = 5,
                    Description = vuln.Description,
                    Severity = vuln.Severity
                });
            }
        }

        // --- CT log submission check ---
        bool ctEnabled = cert.CertProfile?.CtEnabled ?? false;
        if (ctEnabled)
        {
            bool hasCtSubmission = !string.IsNullOrWhiteSpace(cert.SctJson)
                && cert.SctJson != "[]";
            if (!hasCtSubmission)
            {
                factors.Add(new CertHealthFactor
                {
                    Name = "NoCTSubmission",
                    Points = 10,
                    Description = "Certificate has CT enabled in its profile but no SCTs recorded.",
                    Severity = "Info"
                });
            }
        }

        // --- Wildcard check ---
        if (IsWildcard(cert))
        {
            factors.Add(new CertHealthFactor
            {
                Name = "WildcardCert",
                Points = 5,
                Description = "Wildcard certificates have a broader attack surface.",
                Severity = "Info"
            });
        }

        // --- Compute final score ---
        int totalDeductions = factors.Sum(f => f.Points);
        int score = Math.Max(0, 100 - totalDeductions);

        return new CertHealthScore
        {
            CertificateId = cert.CertificateId,
            Score = score,
            Grade = ScoreToGrade(score),
            Factors = factors
        };
    }

    /// <summary>
    /// Determines whether a certificate is used for TLS based on its extended key usages.
    /// </summary>
    private static bool IsTlsCertificate(CertificateEntity cert)
    {
        if (string.IsNullOrWhiteSpace(cert.ExtendedKeyUsagesJson))
            return false;

        try
        {
            var ekus = JsonSerializer.Deserialize<List<string>>(cert.ExtendedKeyUsagesJson);
            if (ekus == null) return false;
            // OID 1.3.6.1.5.5.7.3.1 = serverAuth
            return ekus.Any(e =>
                e == "1.3.6.1.5.5.7.3.1"
                || e.Equals("serverAuth", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks whether the certificate subject or SANs contain a wildcard entry.
    /// </summary>
    private static bool IsWildcard(CertificateEntity cert)
    {
        if (cert.SubjectDN.Contains("*.", StringComparison.Ordinal))
            return true;

        if (!string.IsNullOrWhiteSpace(cert.SubjectAlternativeNamesJson))
        {
            try
            {
                var sans = JsonSerializer.Deserialize<List<string>>(cert.SubjectAlternativeNamesJson);
                if (sans != null && sans.Any(s => s.Contains("*.", StringComparison.Ordinal)))
                    return true;
            }
            catch { /* ignore parse errors */ }
        }

        return false;
    }

    /// <summary>
    /// Maps a numeric score to a letter grade.
    /// </summary>
    private static string ScoreToGrade(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _ => "F"
    };
}
