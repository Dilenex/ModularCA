using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using System.Globalization;
using System.Text;

namespace ModularCA.Core.Services;

/// <summary>
/// Generates compliance reports by querying the certificate inventory, vulnerability findings,
/// CA hierarchy, and health scores. Supports optional CA-scoped filtering and CSV export.
/// </summary>
public class ComplianceReportService : IComplianceReportService
{
    private readonly ModularCADbContext _db;
    private readonly ICertHealthScoreService _healthScoreService;
    private readonly ILogger<ComplianceReportService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ComplianceReportService"/> class.
    /// </summary>
    /// <param name="db">Database context for certificate, CA, and vulnerability queries.</param>
    /// <param name="healthScoreService">Service for calculating per-certificate health scores.</param>
    /// <param name="logger">Logger for diagnostic output.</param>
    public ComplianceReportService(
        ModularCADbContext db,
        ICertHealthScoreService healthScoreService,
        ILogger<ComplianceReportService> logger)
    {
        _db = db;
        _healthScoreService = healthScoreService;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<ComplianceReport> GenerateReportAsync(ComplianceReportRequest request)
    {
        // Compliance reports aggregate the full certificate history for
        // a tenant, which may legitimately exceed the default 30s command timeout on busy
        // installs. Bump to 5 minutes for this call only.
        _db.Database.SetCommandTimeout(TimeSpan.FromMinutes(5));

        var now = DateTime.UtcNow;
        var report = new ComplianceReport
        {
            GeneratedAt = now,
            FromDate = request.FromDate,
            ToDate = request.ToDate,
            CaId = request.CaId
        };

        // Build the base query for all certificates, optionally filtered by CA
        var certQuery = _db.Certificates.AsNoTracking().AsQueryable();

        string? caIssuerDn = null;
        if (request.CaId.HasValue)
        {
            var ca = await _db.CertificateAuthorities
                .AsNoTracking()
                .Include(c => c.Certificate)
                .FirstOrDefaultAsync(c => c.Id == request.CaId.Value);

            if (ca?.Certificate != null)
            {
                caIssuerDn = ca.Certificate.SubjectDN;
                certQuery = certQuery.Where(c => c.Issuer == caIssuerDn);
            }
        }

        var allCerts = await certQuery.ToListAsync();

        // --- Certificate Inventory ---
        report.Inventory = new CertificateInventory
        {
            Total = allCerts.Count,
            Active = allCerts.Count(c => !c.Revoked && c.NotAfter >= now),
            Expired = allCerts.Count(c => c.NotAfter < now),
            Revoked = allCerts.Count(c => c.Revoked)
        };

        // --- Algorithm Distribution ---
        report.AlgorithmDistribution = BuildAlgorithmDistribution(allCerts);

        // --- Vulnerability Summary ---
        var certIds = allCerts.Select(c => c.CertificateId).ToList();
        var unresolvedVulns = await _db.CertComplianceFindings
            .AsNoTracking()
            .Where(v => certIds.Contains(v.CertificateId) && !v.IsResolved)
            .ToListAsync();

        report.VulnerabilitySummary = new VulnerabilitySummary
        {
            TotalUnresolved = unresolvedVulns.Count,
            BySeverity = unresolvedVulns
                .GroupBy(v => v.Severity)
                .ToDictionary(g => g.Key, g => g.Count()),
            ByType = unresolvedVulns
                .GroupBy(v => v.Type)
                .ToDictionary(g => g.Key, g => g.Count())
        };

        // --- Policy Violations (active critical/warning vulnerabilities on active certs) ---
        var activeCertIds = allCerts
            .Where(c => !c.Revoked && c.NotAfter >= now)
            .Select(c => c.CertificateId)
            .ToHashSet();

        var activeViolations = unresolvedVulns
            .Where(v => activeCertIds.Contains(v.CertificateId)
                && (v.Severity == "Critical" || v.Severity == "Warning"));

        var certLookup = allCerts.ToDictionary(c => c.CertificateId);
        report.PolicyViolations = activeViolations.Select(v =>
        {
            certLookup.TryGetValue(v.CertificateId, out var cert);
            return new PolicyViolationEntry
            {
                SerialNumber = cert?.SerialNumber ?? string.Empty,
                SubjectDN = cert?.SubjectDN ?? string.Empty,
                ViolationType = v.Type,
                Severity = v.Severity,
                Description = v.Description
            };
        }).ToList();

        // --- Expiry Forecast (from now, active non-revoked certs only) ---
        var activeCerts = allCerts.Where(c => !c.Revoked && c.NotAfter >= now).ToList();
        report.ExpiryForecast = new ExpiryForecast
        {
            Within30Days = activeCerts.Count(c => c.NotAfter <= now.AddDays(30)),
            Within60Days = activeCerts.Count(c => c.NotAfter <= now.AddDays(60)),
            Within90Days = activeCerts.Count(c => c.NotAfter <= now.AddDays(90)),
            Within180Days = activeCerts.Count(c => c.NotAfter <= now.AddDays(180)),
            Within365Days = activeCerts.Count(c => c.NotAfter <= now.AddDays(365))
        };

        // --- Revocation History (within reporting period) ---
        report.RevocationHistory = allCerts
            .Where(c => c.Revoked
                && c.RevocationDate.HasValue
                && c.RevocationDate.Value >= request.FromDate
                && c.RevocationDate.Value <= request.ToDate)
            .Select(c => new RevocationHistoryEntry
            {
                SerialNumber = c.SerialNumber,
                SubjectDN = c.SubjectDN,
                Issuer = c.Issuer,
                RevocationDate = c.RevocationDate,
                RevocationReason = c.RevocationReason ?? string.Empty
            })
            .OrderByDescending(r => r.RevocationDate)
            .ToList();

        // --- Issuance History (within reporting period) ---
        report.IssuanceHistory = allCerts
            .Where(c => c.NotBefore >= request.FromDate && c.NotBefore <= request.ToDate)
            .Select(c => new IssuanceHistoryEntry
            {
                SerialNumber = c.SerialNumber,
                SubjectDN = c.SubjectDN,
                Issuer = c.Issuer,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter
            })
            .OrderByDescending(i => i.NotBefore)
            .ToList();

        // --- CA Hierarchy ---
        var caQuery = _db.CertificateAuthorities
            .AsNoTracking()
            .Include(ca => ca.Certificate)
            .AsQueryable();

        if (request.CaId.HasValue)
            caQuery = caQuery.Where(ca => ca.Id == request.CaId.Value);

        var cas = await caQuery.ToListAsync();
        report.CaHierarchy = cas.Select(ca => new CaHierarchyEntry
        {
            CaId = ca.Id,
            Name = ca.Name,
            Type = ca.Type,
            IsEnabled = ca.IsEnabled,
            ParentCaId = ca.ParentCaId,
            SubjectDN = ca.Certificate?.SubjectDN ?? string.Empty
        }).ToList();

        // --- Certificate Rows for CSV ---
        var vulnCountByCert = unresolvedVulns
            .GroupBy(v => v.CertificateId)
            .ToDictionary(g => g.Key, g => g.Count());

        // Compute health scores in bulk
        var healthScores = new Dictionary<Guid, int>();
        if (certIds.Count > 0)
        {
            try
            {
                var scores = await _healthScoreService.CalculateBulkScoresAsync(certIds);
                foreach (var s in scores)
                    healthScores[s.CertificateId] = s.Score;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to compute bulk health scores for compliance report");
            }
        }

        report.CertificateRows = allCerts.Select(c =>
        {
            var (algo, keySize) = ExtractAlgorithmInfo(c);
            vulnCountByCert.TryGetValue(c.CertificateId, out var vulnCount);
            healthScores.TryGetValue(c.CertificateId, out var health);

            string status;
            if (c.Revoked)
                status = "Revoked";
            else if (c.NotAfter < now)
                status = "Expired";
            else
                status = "Active";

            return new CertificateReportRow
            {
                SerialNumber = c.SerialNumber,
                SubjectDN = c.SubjectDN,
                Issuer = c.Issuer,
                Algorithm = algo,
                KeySize = keySize,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter,
                Status = status,
                HealthScore = health,
                VulnerabilityCount = vulnCount
            };
        }).ToList();

        return report;
    }

    /// <inheritdoc />
    public Task<byte[]> ExportCsvAsync(ComplianceReport report)
    {
        var sb = new StringBuilder();

        // Header row
        sb.AppendLine("Serial,Subject,Issuer,Algorithm,KeySize,NotBefore,NotAfter,Status,HealthScore,Findings");

        foreach (var row in report.CertificateRows)
        {
            sb.Append(CsvEscape(row.SerialNumber)).Append(',');
            sb.Append(CsvEscape(row.SubjectDN)).Append(',');
            sb.Append(CsvEscape(row.Issuer)).Append(',');
            sb.Append(CsvEscape(row.Algorithm)).Append(',');
            sb.Append(CsvEscape(row.KeySize)).Append(',');
            sb.Append(row.NotBefore.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)).Append(',');
            sb.Append(row.NotAfter.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)).Append(',');
            sb.Append(CsvEscape(row.Status)).Append(',');
            sb.Append(row.HealthScore).Append(',');
            sb.AppendLine(row.VulnerabilityCount.ToString(CultureInfo.InvariantCulture));
        }

        return Task.FromResult(Encoding.UTF8.GetBytes(sb.ToString()));
    }

    /// <summary>
    /// Builds a distribution of certificates grouped by algorithm and key size.
    /// </summary>
    private List<AlgorithmDistributionEntry> BuildAlgorithmDistribution(List<CertificateEntity> certs)
    {
        var groups = new Dictionary<(string Algo, string Size), int>();
        foreach (var cert in certs)
        {
            var (algo, keySize) = ExtractAlgorithmInfo(cert);
            var key = (algo, keySize);
            if (groups.ContainsKey(key))
                groups[key]++;
            else
                groups[key] = 1;
        }

        return groups.Select(g => new AlgorithmDistributionEntry
        {
            Algorithm = g.Key.Algo,
            KeySize = g.Key.Size,
            Count = g.Value
        })
        .OrderByDescending(e => e.Count)
        .ToList();
    }

    /// <summary>
    /// Extracts algorithm name and key size from a certificate entity by parsing
    /// its raw certificate or PEM data via BouncyCastle.
    /// </summary>
    private (string Algorithm, string KeySize) ExtractAlgorithmInfo(CertificateEntity cert)
    {
        try
        {
            X509Certificate? x509 = null;

            if (cert.RawCertificate != null && cert.RawCertificate.Length > 0)
                x509 = new X509Certificate(cert.RawCertificate);
            else if (!string.IsNullOrWhiteSpace(cert.Pem))
                x509 = ModularCA.Shared.Utils.CertificateUtil.ParseFromPem(cert.Pem);

            if (x509 == null)
                return ("Unknown", "Unknown");

            var pubKey = x509.GetPublicKey();

            if (pubKey is RsaKeyParameters rsa)
                return ("RSA", rsa.Modulus.BitLength.ToString(CultureInfo.InvariantCulture));

            if (pubKey is ECPublicKeyParameters ec)
            {
                return ("ECDSA", MapEcCurveOidToFriendlyName(ec));
            }

            if (pubKey is Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters)
                return ("Ed25519", "256");

            if (pubKey is Org.BouncyCastle.Crypto.Parameters.Ed448PublicKeyParameters)
                return ("Ed448", "456");

            return (x509.SigAlgName, "Unknown");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to extract algorithm info for certificate {Serial}", cert.SerialNumber);
            return ("Unknown", "Unknown");
        }
    }

    /// <summary>
    /// Maps a BouncyCastle EC curve OID to the friendly NIST/SEC name the rest of the
    /// codebase uses (<c>P-256</c>, <c>P-384</c>, <c>P-521</c>). Falls back to the
    /// SEC/ANSI name via <c>ECNamedCurveTable</c>, then to a bit-size fallback so the
    /// compliance report never surfaces raw <c>1.2.840.10045.*</c> OIDs to operators.
    /// </summary>
    private static string MapEcCurveOidToFriendlyName(ECPublicKeyParameters ec)
    {
        var oid = ec.PublicKeyParamSet?.Id;
        switch (oid)
        {
            case "1.2.840.10045.3.1.1": return "P-192";   // secp192r1 / prime192v1
            case "1.3.132.0.33":        return "P-224";   // secp224r1
            case "1.2.840.10045.3.1.7": return "P-256";   // secp256r1 / prime256v1
            case "1.3.132.0.34":        return "P-384";   // secp384r1
            case "1.3.132.0.35":        return "P-521";   // secp521r1
            case "1.3.132.0.10":        return "secp256k1";
        }

        if (ec.PublicKeyParamSet != null)
        {
            var secName = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetName(ec.PublicKeyParamSet);
            if (!string.IsNullOrEmpty(secName)) return secName;
        }

        return $"{ec.Parameters.Curve.FieldSize}-bit";
    }

    /// <summary>
    /// Escapes a value for safe inclusion in a CSV field.
    /// Neutralizes spreadsheet formula injection (a leading =,+,-,@,tab,CR that Excel/Sheets would
    /// execute as a formula) by prefixing a single quote, then wraps in double quotes if the value
    /// contains commas, quotes, or newlines.
    /// </summary>
    private static string CsvEscape(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        // OWASP CSV injection defense: a leading formula-trigger char is escaped with a single quote.
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            value = "'" + value;

        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
            return "\"" + value.Replace("\"", "\"\"") + "\"";

        return value;
    }
}
