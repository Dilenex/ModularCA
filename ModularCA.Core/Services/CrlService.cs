using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Scheduler;
using ModularCA.Shared.Utils;
using NCrontab;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Text;

namespace ModularCA.Core.Services;

/// <summary>
/// Generates and manages full and delta CRLs using BouncyCastle, storing them in the database.
/// </summary>
/// <remarks>
/// Highlights:
/// <list type="bullet">
/// <item>Signing algorithm is derived from the CA's own public key via
/// <see cref="KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey"/>, not from
/// the signature the parent CA produced on the CA cert.</item>
/// <item>All lookups are by <c>CaCertificateId</c> / <c>CertificateId</c> rather than the
/// stringified SubjectDN.</item>
/// <item>Expired certs are no longer included in the CRL — entries with
/// <c>NotAfter &lt; now</c> are excluded per RFC 5280 §3.3.</item>
/// <item>Per-CA monotonic CRL number counter stored on <see cref="CrlConfigurationEntity.LastCrlNumber"/>
/// and incremented under <c>SELECT ... FOR UPDATE</c>.</item>
/// <item><see cref="GenerateCrlAsync"/> and <see cref="GenerateDeltaCrlAsync"/> emit an
/// <c>IssuingDistributionPoint</c> extension.</item>
/// <item>Delta <c>removeFromCRL</c> lookup uses a single batched <c>WHERE IN (...)</c> query
/// instead of N individual round-trips.</item>
/// </list>
/// </remarks>
public class CrlService : ICrlService
{
    private readonly ModularCADbContext _dbContext;
    private readonly IKeystoreCertificates _keystore;
    private readonly ILogger<CrlService> _logger;
    private readonly IAuditService _audit;

    /// <summary>
    /// Resolves the CA's published CDP URLs — the same ones <c>CertificateBuilderService</c>
    /// stamps into issued certificates — so the CRL's IssuingDistributionPoint can name the
    /// identical distribution point. See <see cref="AddIssuingDistributionPoint"/>.
    /// </summary>
    private readonly ICaServiceUrlService _caServiceUrls;

    /// <summary>
    /// Decrypts the LDAP publisher bind password before the fire-and-forget CRL publish hands it
    /// to a background task — the scoped protector must be used while this scope is still alive.
    /// </summary>
    private readonly ILdapSecretProtector _ldapSecretProtector;

    /// <summary>
    /// Constructs the CRL service. The unused <c>IFeatureFlagService</c> dependency
    /// that was wired in but never referenced has been removed.
    /// Added <see cref="IAuditService"/> so each
    /// successful full or delta CRL generation emits an
    /// <see cref="AuditActionType.CrlGenerated"/> record (distinct from the
    /// scheduler's <c>CrlExported</c> dispatch event).
    /// </summary>
    public CrlService(ModularCADbContext dbContext, IKeystoreCertificates keystore, ILogger<CrlService> logger, IAuditService audit,
        ICaServiceUrlService caServiceUrls, ILdapSecretProtector ldapSecretProtector)
    {
        _dbContext = dbContext;
        _keystore = keystore;
        _logger = logger;
        _audit = audit;
        _caServiceUrls = caServiceUrls;
        _ldapSecretProtector = ldapSecretProtector;
    }

    /// <summary>
    /// Generates a new full CRL for the specified CA certificate. Signs with the CA's own
    /// public key algorithm (not the issuer's), excludes expired entries, increments the
    /// monotonic CRL number atomically, and emits the <c>IssuingDistributionPoint</c>
    /// extension when the configuration scopes over a subset. Emits an
    /// <see cref="AuditActionType.CrlGenerated"/> audit record after successful persistence,
    /// with <c>IsDelta=false</c> in the details payload.
    /// </summary>
    public async Task<string> GenerateCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Override the default 30s command timeout — CRLs for CAs with
        // large revoked-cert histories can legitimately take several minutes to assemble.
        _dbContext.Database.SetCommandTimeout(TimeSpan.FromMinutes(5));

        var ca = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == caCertificateId, cancellationToken);

        if (ca == null)
            throw new InvalidOperationException($"CA certificate {caCertificateId} not found.");

        var (caPubKey, caKeyHandle) = ResolveCaKey(ca);

        // Look up the config by CaCertificateId — not SubjectDN — and
        // reject disabled configs.
        var crlJob = await _dbContext.CrlConfigurations
            .Where(j => j.CaCertificateId == caCertificateId && !j.IsDelta)
            .FirstOrDefaultAsync(cancellationToken);

        if (crlJob == null)
            throw new InvalidOperationException($"No CRL configuration exists for CA certificate {caCertificateId}.");

        if (!crlJob.Enabled)
        {
            _logger.LogInformation("CRL config {TaskId} for CA {CaId} is disabled; skipping generation.",
                crlJob.TaskId, caCertificateId);
            var existing = await _dbContext.Crls
                .AsNoTracking()
                .Where(c => c.TaskId == crlJob.TaskId && !c.IsDelta)
                .OrderByDescending(c => c.CrlNumber)
                .FirstOrDefaultAsync(cancellationToken);
            return BuildPem(existing?.RawData) ?? string.Empty;
        }

        var now = DateTime.UtcNow;
        var parsedUpdate = CrontabSchedule.Parse(crlJob.UpdateInterval);
        var nextUpdate = parsedUpdate.GetNextOccurrence(now);

        byte[] encoded;
        string pemString;
        long newCrlNumber;
        int revokedCount = 0;

        // Use RepeatableRead + row-level lock on the CrlConfigurations row
        // so two concurrent generators can't issue the same number. The in-process
        // MySql `SELECT ... FOR UPDATE` is simple and enough for single-node. HA distributed
        // lock lives in the scheduler.
        using var transaction = await _dbContext.Database.BeginTransactionAsync(
            System.Data.IsolationLevel.RepeatableRead, cancellationToken);
        try
        {
            var lockedCrlJob = await _dbContext.CrlConfigurations
                .FromSqlRaw("SELECT * FROM CrlConfigurations WHERE TaskId = {0} FOR UPDATE", crlJob.TaskId)
                .FirstOrDefaultAsync(cancellationToken)
                ?? crlJob;

            // Persistent per-CA counter. Start from max(existing CRL numbers,
            // LastCrlNumber) so legacy installs where the counter is still 0 don't regress.
            //
            // Scope this by ISSUER, not by TaskId. The unique index is (IssuerName, CrlNumber)
            // and the delta path already allocates across the issuer's whole history so that
            // full and delta share one sequence. Scoping the full path per-config meant that as
            // soon as a separate delta configuration existed, the delta would take number N and
            // the next full CRL — seeing only its own TaskId's rows — would recompute N and hit
            // a duplicate-key violation. That failure is permanent: every subsequent run
            // recomputes the same number, so the CA silently stops publishing CRLs for good.
            var existingMax = await _dbContext.Crls
                .Where(c => c.IssuerName == ca.SubjectDN)
                .Select(c => (long?)c.CrlNumber)
                .MaxAsync(cancellationToken) ?? 0L;
            newCrlNumber = Math.Max(lockedCrlJob.LastCrlNumber, existingMax) + 1;
            lockedCrlJob.LastCrlNumber = newCrlNumber;

            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(caPubKey.SubjectDN);
            crlGen.SetThisUpdate(now);
            crlGen.SetNextUpdate(nextUpdate);

            // Filter by issuer certificate FK when set, fall back to
            // Issuer-DN match for legacy rows pre-migration. Exclude expired entries per
            // RFC 5280 §3.3.
            var issuerDnString = caPubKey.SubjectDN.ToString();
            var revokedCerts = await _dbContext.Certificates
                .Where(c => c.Revoked
                    && c.NotAfter > now
                    && ((c.IssuerCertificateId != null && c.IssuerCertificateId == caCertificateId)
                        || (c.IssuerCertificateId == null && c.Issuer == issuerDnString)))
                .AsNoTracking()
                .ToListAsync(cancellationToken);
            revokedCount = revokedCerts.Count;

            foreach (var cert in revokedCerts)
            {
                var revocationDate = cert.RevocationDate ?? now;
                var reasonCode = GetCrlReasonCode(cert.RevocationReason);
                var extensions = BuildEntryExtensions(cert);
                if (extensions != null)
                    crlGen.AddCrlEntry(new BigInteger(cert.SerialNumber, 16), revocationDate, extensions);
                else
                    crlGen.AddCrlEntry(new BigInteger(cert.SerialNumber, 16), revocationDate, reasonCode);
            }

            crlGen.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(BigInteger.ValueOf(newCrlNumber)));

            var caPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caPubKey.GetPublicKey());
            var aki = X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caPubKeyInfo);
            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, aki);

            // IssuingDistributionPoint extension.
            var fullCdp = (await _caServiceUrls.ResolveForCaAsync(ca.CertificateId)).CdpUrls;
            AddIssuingDistributionPoint(crlGen, ca, lockedCrlJob, isDelta: false, fullCdp);

            // Sign with the CA's own public-key algorithm, not the SigAlgName
            // field that reflects how its parent signed this cert.
            var sigAlg = KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caPubKey.GetPublicKey());
            var signer = new PrivateKeyHandleSignatureFactory(CertificateUtil.NormalizeSigAlgName(sigAlg), caKeyHandle);
            var crl = crlGen.Generate(signer);
            encoded = crl.GetEncoded();

            pemString = BuildPemString(encoded);

            // === Single source of truth: persist CRL + schedule in one place ===
            var existingCrl = await _dbContext.Crls
                .Where(c => c.TaskId == lockedCrlJob.TaskId && !c.IsDelta)
                .FirstOrDefaultAsync(cancellationToken);

            if (existingCrl != null)
            {
                existingCrl.NextUpdate = nextUpdate;
                existingCrl.RawData = encoded;
                existingCrl.PemData = pemString;
                existingCrl.BaseCrlNumber = null; // full CRLs leave this null
                existingCrl.GeneratedAt = now;
                existingCrl.CrlNumber = newCrlNumber;
                existingCrl.ThisUpdate = now;
                _dbContext.Crls.Update(existingCrl);
            }
            else
            {
                _dbContext.Crls.Add(new CrlEntity
                {
                    CrlNumber = newCrlNumber,
                    IsDelta = false,
                    RawData = encoded,
                    PemData = pemString,
                    BaseCrlNumber = null,
                    GeneratedAt = now,
                    IssuerName = issuerDnString,
                    ThisUpdate = now,
                    NextUpdate = nextUpdate,
                    TaskId = lockedCrlJob.TaskId
                });
            }

            lockedCrlJob.LastUpdatedUtc = now;
            lockedCrlJob.LastGenerated = now;
            lockedCrlJob.NextUpdateUtc = nextUpdate;
            _dbContext.CrlConfigurations.Update(lockedCrlJob);

            await _dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }

        // Resolve the CertificateAuthority entity ID for the FK-based LDAP config lookup.
        var caAuthorityId = await _dbContext.CertificateAuthorities
            .Where(ca => ca.CertificateId == caCertificateId)
            .Select(ca => (Guid?)ca.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (caAuthorityId.HasValue)
            FireAndForgetLdapCrlPublish(encoded, caAuthorityId.Value, caPubKey.SubjectDN.ToString());

        // CRL generation is a security-relevant lifecycle
        // event distinct from the scheduler's CrlExported dispatch. Wrapped so an audit
        // failure cannot mask a successful CRL emission.
        try
        {
            await _audit.LogAsync(
                AuditActionType.CrlGenerated,
                actorUserId: null,
                actorUsername: "scheduler",
                targetEntityType: "CRL",
                targetEntityId: caCertificateId.ToString(),
                details: new
                {
                    CaCertificateId = caCertificateId,
                    CrlNumber = newCrlNumber,
                    ThisUpdate = now,
                    NextUpdate = nextUpdate,
                    RevokedCount = revokedCount,
                    IsDelta = false,
                },
                certificateAuthorityId: caAuthorityId);
        }
        catch (Exception auditEx)
        {
            _logger.LogWarning(auditEx, "Audit emission for CrlGenerated failed for CA {CaId}; CRL was still persisted.", caCertificateId);
        }

        stopwatch.Stop();
        MetricsService.CrlGenerationDuration.Observe(stopwatch.Elapsed.TotalSeconds);
        MetricsService.CrlGenerations.WithLabels(caPubKey.SubjectDN.ToString()).Inc();

        return pemString;
    }

    /// <summary>
    /// Generates a delta CRL containing only revocations since the last full CRL.
    /// RFC 5280 §5.2.4 — includes DeltaCRLIndicator and IssuingDistributionPoint extensions.
    /// Audit findings #26: emits an <see cref="AuditActionType.CrlGenerated"/> audit record
    /// with <c>IsDelta=true</c> in the details payload after successful persistence.
    /// </summary>
    public async Task<string> GenerateDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        _dbContext.Database.SetCommandTimeout(TimeSpan.FromMinutes(5));

        var ca = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == caCertificateId, cancellationToken);

        if (ca == null)
            throw new InvalidOperationException($"CA certificate {caCertificateId} not found.");

        var (caPubKey, caKeyHandle) = ResolveCaKey(ca);
        var issuerDn = caPubKey.SubjectDN.ToString();

        // Find the latest full CRL — the delta is relative to this
        var baseFullCrl = await _dbContext.Crls
            .Where(c => c.IssuerName == issuerDn && !c.IsDelta)
            .OrderByDescending(c => c.CrlNumber)
            .FirstOrDefaultAsync(cancellationToken);

        if (baseFullCrl == null)
            throw new InvalidOperationException("No base full CRL exists. Generate a full CRL first before creating a delta.");

        // By CaCertificateId, not DN.
        var deltaCrlJob = await _dbContext.CrlConfigurations
            .Where(j => j.CaCertificateId == caCertificateId && j.IsDelta)
            .FirstOrDefaultAsync(cancellationToken);

        var fullCrlJob = await _dbContext.CrlConfigurations
            .Where(j => j.CaCertificateId == caCertificateId && !j.IsDelta)
            .FirstOrDefaultAsync(cancellationToken);

        if (deltaCrlJob == null && fullCrlJob == null)
            throw new InvalidOperationException("Could not find CRL configuration for delta CRL generation.");

        var now = DateTime.UtcNow;
        DateTime nextUpdate;

        if (deltaCrlJob != null && !string.IsNullOrWhiteSpace(deltaCrlJob.DeltaInterval))
        {
            var parsedDelta = CrontabSchedule.Parse(deltaCrlJob.DeltaInterval);
            nextUpdate = parsedDelta.GetNextOccurrence(now);
        }
        else if (fullCrlJob != null && !string.IsNullOrWhiteSpace(fullCrlJob.DeltaInterval))
        {
            var parsedDelta = CrontabSchedule.Parse(fullCrlJob.DeltaInterval);
            nextUpdate = parsedDelta.GetNextOccurrence(now);
        }
        else
        {
            nextUpdate = now.AddHours(1);
        }

        byte[] encoded;
        string pemString;
        long newCrlNumber;
        int revokedCount = 0;

        using var transaction = await _dbContext.Database.BeginTransactionAsync(
            System.Data.IsolationLevel.RepeatableRead, cancellationToken);
        try
        {
            var counterRow = deltaCrlJob ?? fullCrlJob!;
            var lockedCounter = await _dbContext.CrlConfigurations
                .FromSqlRaw("SELECT * FROM CrlConfigurations WHERE TaskId = {0} FOR UPDATE", counterRow.TaskId)
                .FirstOrDefaultAsync(cancellationToken)
                ?? counterRow;

            var existingMax = await _dbContext.Crls
                .Where(c => c.IssuerName == issuerDn)
                .Select(c => (long?)c.CrlNumber)
                .MaxAsync(cancellationToken) ?? 0L;
            // Per-CA monotonic counter. We use the max across the CA's
            // entire CRL history (full + delta) so full and delta CRLs share one sequence.
            newCrlNumber = Math.Max(lockedCounter.LastCrlNumber, existingMax) + 1;
            lockedCounter.LastCrlNumber = newCrlNumber;

            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(caPubKey.SubjectDN);
            crlGen.SetThisUpdate(now);
            crlGen.SetNextUpdate(nextUpdate);

            // Delta CRL includes only entries revoked AFTER the base full CRL was generated
            // and still unexpired (RFC 5280 §3.3).
            var revokedSinceBase = await _dbContext.Certificates
                .Where(c => c.Revoked
                    && c.NotAfter > now
                    && c.RevocationDate != null
                    && c.RevocationDate > baseFullCrl.GeneratedAt
                    && ((c.IssuerCertificateId != null && c.IssuerCertificateId == caCertificateId)
                        || (c.IssuerCertificateId == null && c.Issuer == issuerDn)))
                .AsNoTracking()
                .ToListAsync(cancellationToken);
            revokedCount = revokedSinceBase.Count;

            foreach (var cert in revokedSinceBase)
            {
                var extensions = BuildEntryExtensions(cert);
                var revocationDate = cert.RevocationDate ?? cert.NotAfter;
                if (extensions != null)
                    crlGen.AddCrlEntry(new BigInteger(cert.SerialNumber, 16), revocationDate, extensions);
                else
                    crlGen.AddCrlEntry(new BigInteger(cert.SerialNumber, 16), revocationDate, GetCrlReasonCode(cert.RevocationReason));
            }

            // Batched removeFromCRL lookup. Collect base CRL serials into a
            // HashSet and query the matching unrevoked cert rows in one shot rather than N
            // per-entry round-trips.
            var baseFullCrlObj = new X509CrlParser().ReadCrl(baseFullCrl.RawData);
            var revokedInBase = baseFullCrlObj?.GetRevokedCertificates();
            if (revokedInBase != null)
            {
                var baseSerials = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var baseEntries = new Dictionary<string, X509CrlEntry>(StringComparer.OrdinalIgnoreCase);
                foreach (X509CrlEntry entry in revokedInBase)
                {
                    var serialHex = CertificateUtil.FormatSerialNumber(entry.SerialNumber);
                    baseSerials.Add(serialHex);
                    baseEntries[serialHex] = entry;
                }

                if (baseSerials.Count > 0)
                {
                    // One query — "which base-CRL serials are now not revoked anymore?"
                    var reinstated = await _dbContext.Certificates
                        .Where(c => baseSerials.Contains(c.SerialNumber)
                            && !c.Revoked
                            && ((c.IssuerCertificateId != null && c.IssuerCertificateId == caCertificateId)
                                || (c.IssuerCertificateId == null && c.Issuer == issuerDn)))
                        .Select(c => c.SerialNumber)
                        .AsNoTracking()
                        .ToListAsync(cancellationToken);

                    foreach (var serialHex in reinstated)
                    {
                        if (baseEntries.TryGetValue(serialHex, out var entry))
                            crlGen.AddCrlEntry(entry.SerialNumber, now, CrlReason.RemoveFromCrl);
                    }
                }
            }

            crlGen.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(BigInteger.ValueOf(newCrlNumber)));
            crlGen.AddExtension(X509Extensions.DeltaCrlIndicator, true, new DerInteger(BigInteger.ValueOf(baseFullCrl.CrlNumber)));

            var caPubKeyInfo2 = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caPubKey.GetPublicKey());
            var aki = X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caPubKeyInfo2);
            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, aki);

            var deltaCdp = (await _caServiceUrls.ResolveForCaAsync(ca.CertificateId)).CdpUrls;
            AddIssuingDistributionPoint(crlGen, ca, lockedCounter, isDelta: true, deltaCdp);

            var sigAlg = KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caPubKey.GetPublicKey());
            var signer = new PrivateKeyHandleSignatureFactory(CertificateUtil.NormalizeSigAlgName(sigAlg), caKeyHandle);
            var crl = crlGen.Generate(signer);
            encoded = crl.GetEncoded();
            pemString = BuildPemString(encoded);

            var taskId = lockedCounter.TaskId;

            var existingDelta = await _dbContext.Crls
                .Where(c => c.IssuerName == issuerDn && c.IsDelta)
                .OrderByDescending(c => c.CrlNumber)
                .FirstOrDefaultAsync(cancellationToken);

            if (existingDelta != null)
            {
                existingDelta.NextUpdate = nextUpdate;
                existingDelta.RawData = encoded;
                existingDelta.PemData = pemString;
                existingDelta.BaseCrlNumber = baseFullCrl.CrlNumber;
                existingDelta.GeneratedAt = now;
                existingDelta.CrlNumber = newCrlNumber;
                existingDelta.ThisUpdate = now;
                _dbContext.Crls.Update(existingDelta);
            }
            else
            {
                _dbContext.Crls.Add(new CrlEntity
                {
                    CrlNumber = newCrlNumber,
                    IsDelta = true,
                    RawData = encoded,
                    PemData = pemString,
                    BaseCrlNumber = baseFullCrl.CrlNumber,
                    GeneratedAt = now,
                    IssuerName = issuerDn,
                    ThisUpdate = now,
                    NextUpdate = nextUpdate,
                    TaskId = taskId
                });
            }

            if (deltaCrlJob != null)
            {
                deltaCrlJob.LastUpdatedUtc = now;
                deltaCrlJob.LastGenerated = now;
                deltaCrlJob.NextUpdateUtc = nextUpdate;
                _dbContext.CrlConfigurations.Update(deltaCrlJob);
            }
            _dbContext.CrlConfigurations.Update(lockedCounter);

            await _dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }

        // Resolve the CertificateAuthority entity ID for the FK-based LDAP config lookup.
        var caAuthorityIdDelta = await _dbContext.CertificateAuthorities
            .Where(ca => ca.CertificateId == caCertificateId)
            .Select(ca => (Guid?)ca.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (caAuthorityIdDelta.HasValue)
            FireAndForgetLdapCrlPublish(encoded, caAuthorityIdDelta.Value, issuerDn);

        // Delta CRL generation gets the same audit record
        // shape as a full CRL with IsDelta=true so SIEM can distinguish them by the details
        // payload. Wrapped so an audit failure cannot mask a successful delta emission.
        try
        {
            await _audit.LogAsync(
                AuditActionType.CrlGenerated,
                actorUserId: null,
                actorUsername: "scheduler",
                targetEntityType: "CRL",
                targetEntityId: caCertificateId.ToString(),
                details: new
                {
                    CaCertificateId = caCertificateId,
                    CrlNumber = newCrlNumber,
                    ThisUpdate = now,
                    NextUpdate = nextUpdate,
                    RevokedCount = revokedCount,
                    BaseCrlNumber = baseFullCrl.CrlNumber,
                    IsDelta = true,
                },
                certificateAuthorityId: caAuthorityIdDelta);
        }
        catch (Exception auditEx)
        {
            _logger.LogWarning(auditEx, "Audit emission for CrlGenerated (delta) failed for CA {CaId}; delta CRL was still persisted.", caCertificateId);
        }

        stopwatch.Stop();
        MetricsService.CrlGenerationDuration.Observe(stopwatch.Elapsed.TotalSeconds);
        MetricsService.CrlGenerations.WithLabels(issuerDn).Inc();

        return pemString;
    }

    /// <summary>
    /// Resolves the CA public cert + private key handle from the
    /// database-backed <see cref="CertificateEntity"/> without round-tripping through the
    /// <c>SubjectDN</c> string. Uses <c>RawCertificate</c> when present, otherwise falls back
    /// to the pub-key stored in the keystore for legacy rows.
    /// </summary>
    private (X509Certificate Cert, IPrivateKeyHandle KeyHandle) ResolveCaKey(CertificateEntity ca)
    {
        X509Certificate? caCert = null;
        if (ca.RawCertificate != null && ca.RawCertificate.Length > 0)
        {
            try { caCert = new X509Certificate(ca.RawCertificate); }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse RawCertificate for CA {CaId}; will fall back to keystore lookup.", ca.CertificateId);
            }
        }

        if (caCert == null)
        {
            caCert = _keystore.GetTrustedAuthorities()
                .FirstOrDefault(c => c.SubjectDN.ToString() == ca.SubjectDN)
                ?? throw new InvalidOperationException($"CA certificate {ca.CertificateId} not found in keystore.");
        }

        var handle = _keystore.GetPrivateKeyFor(caCert)
            ?? throw new InvalidOperationException($"Private key not found for CA: {caCert.SubjectDN}");

        return (caCert, handle);
    }

    /// <summary>
    /// Builds the per-entry CRL extension set — always the reason code,
    /// plus the invalidity date when the cert carries one. Returns null when no extensions
    /// are needed so the caller can use the reason-only overload.
    /// </summary>
    private static X509Extensions? BuildEntryExtensions(CertificateEntity cert)
    {
        if (cert.InvalidityDate == null)
            return null;

        var ext = new Dictionary<DerObjectIdentifier, X509Extension>
        {
            [X509Extensions.ReasonCode] = new X509Extension(false,
                new DerOctetString(new CrlReason(GetCrlReasonCode(cert.RevocationReason)))),
            [X509Extensions.InvalidityDate] = new X509Extension(false,
                new DerOctetString(new Org.BouncyCastle.Asn1.X509.Time(cert.InvalidityDate.Value.ToUniversalTime()))),
        };
        return new X509Extensions(ext);
    }

    /// <summary>
    /// Adds the <c>IssuingDistributionPoint</c> extension. The CDP URI is
    /// not directly tracked on <see cref="CrlConfigurationEntity"/>, so we set the scope bits
    /// (<c>onlyContainsUserCerts</c> / <c>onlyContainsCACerts</c>) and the
    /// <c>indirectCRL</c>/<c>onlySomeReasons</c> defaults. The extension is marked critical.
    /// </summary>
    private static void AddIssuingDistributionPoint(
        X509V2CrlGenerator crlGen,
        CertificateEntity ca,
        CrlConfigurationEntity config,
        bool isDelta,
        IReadOnlyList<string> cdpUrls)
    {
        // The distributionPoint here must name the SAME point the covered certificates carry in
        // their CRLDistributionPoints extension, because RFC 5280 §6.3.3(b)(2)(i) matches the two
        // by name. Issued certificates get a uniformResourceIdentifier
        // (CertificateBuilderService: GeneralName.UniformResourceIdentifier), so a URI is the
        // only name form that can ever match.
        //
        // This used to synthesise a directoryName from the CA's subject DN when no CDP URI was
        // to hand. A directoryName never matches a URI, and the extension is CRITICAL, so every
        // CRL this CA published was rejected by any validator that performs the check —
        // `openssl verify -crl_check` among them. Revocation checking did not work at all.
        //
        // When no CDP URL is configured we now omit the distributionPoint rather than inventing
        // one. Per §6.3.3(b)(2), an IDP with no distributionPoint simply does not trigger the
        // name-matching test, so the CRL covers the issuer's certificates as intended — and we
        // skip the extension entirely when it would carry no information at all.
        DistributionPointName? dpName = null;
        if (cdpUrls.Count > 0)
        {
            var names = cdpUrls
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Select(u => new GeneralName(GeneralName.UniformResourceIdentifier, u))
                .ToArray();
            if (names.Length > 0)
                dpName = new DistributionPointName(DistributionPointName.FullName, new GeneralNames(names));
        }

        var scoped = config.OnlyContainsUserCerts || config.OnlyContainsCACerts;
        if (dpName == null && !scoped)
            return;

        var idp = new IssuingDistributionPoint(
            distributionPoint: dpName,
            onlyContainsUserCerts: config.OnlyContainsUserCerts,
            onlyContainsCACerts: config.OnlyContainsCACerts,
            onlySomeReasons: null,
            indirectCRL: false,
            onlyContainsAttributeCerts: false);

        // RFC 5280 §5.2.5: when present, IssuingDistributionPoint MUST be critical.
        crlGen.AddExtension(X509Extensions.IssuingDistributionPoint, true, idp);
    }

    /// <summary>
    /// Looks up enabled LDAP configurations for the given CA and, if any
    /// have <c>PublishCRL</c> enabled, publishes the DER-encoded CRL to each
    /// configured LDAP directory in a fire-and-forget background task.
    /// Snapshots all values before starting the task so the scoped
    /// DbContext is not touched inside <see cref="Task.Run(Action)"/>.
    /// </summary>
    private void FireAndForgetLdapCrlPublish(byte[] crlDer, Guid caId, string issuerDn)
    {
        // Snapshot LDAP configs before the task starts — the DbContext will be disposed
        // when the enclosing scope ends.
        var ldapConfigs = _dbContext.LdapConfigurations
            .Where(c => c.Enabled && c.CertificateAuthorityId == caId && c.PublishCRL)
            .AsNoTracking()
            .ToList();

        if (ldapConfigs.Count == 0)
            return;

        // Snapshot: build all LdapScheduleOptions instances up front. The task only closes
        // over value-type snapshots (no _dbContext reference).
        var snapshots = ldapConfigs.Select(cfg => new LdapScheduleOptions
        {
            LdapHost = cfg.Host,
            LdapPort = cfg.Port,
            UseSsl = cfg.UseSsl,
            BaseDn = cfg.BaseDn,
            Username = cfg.Username,
            // Decrypted on this thread, while the request scope and its protector are still
            // alive. A row still holding a plaintext password reads through unchanged; the
            // scheduled publisher owns upgrading those, since this path has no writable context.
            Password = _ldapSecretProtector.Unprotect(cfg.Password),
            CertificateAuthorityId = cfg.CertificateAuthorityId,
            PublishCRL = true,
            TaskId = cfg.Id,
        }).ToList();

        var logger = _logger;
        var derCopy = (byte[])crlDer.Clone();

        _ = Task.Run(() =>
        {
            foreach (var options in snapshots)
            {
                try
                {
                    using var connection = LdapPublishHelper.Connect(options, timeout: null, logger: logger);
                    LdapPublishHelper.PublishCrl(connection, options, derCopy, logger);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Fire-and-forget LDAP CRL publish failed for issuer {Issuer}", issuerDn);
                }
            }
        });
    }

    /// <summary>
    /// Maps a stored <see cref="RevocationReason"/> enum name back to its
    /// RFC 5280 §5.3.1 integer code. Throws on unknown values so a typo in the DB surfaces
    /// immediately instead of being laundered through <c>CrlReason.Unspecified</c>.
    /// </summary>
    internal static int GetCrlReasonCode(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
            return CrlReason.Unspecified;

        if (!Enum.TryParse<RevocationReason>(reason, ignoreCase: true, out var parsed))
            throw new InvalidOperationException(
                $"Unknown revocation reason '{reason}'. Expected one of: {string.Join(", ", Enum.GetNames<RevocationReason>())}.");

        return parsed switch
        {
            RevocationReason.Unspecified => CrlReason.Unspecified,
            RevocationReason.KeyCompromise => CrlReason.KeyCompromise,
            RevocationReason.CACompromise => CrlReason.CACompromise,
            RevocationReason.AffiliationChanged => CrlReason.AffiliationChanged,
            RevocationReason.Superseded => CrlReason.Superseded,
            RevocationReason.CessationOfOperation => CrlReason.CessationOfOperation,
            RevocationReason.CertificateHold => CrlReason.CertificateHold,
            RevocationReason.PrivilegeWithdrawn => CrlReason.PrivilegeWithdrawn,
            RevocationReason.AaCompromise => CrlReason.AACompromise,
            _ => throw new InvalidOperationException($"Unmapped revocation reason '{parsed}'."),
        };
    }

    public async Task<string?> GetLatestCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var blob = await GetLatestCrlRawAsync(caCertificateId, cancellationToken);
        return blob == null ? null : BuildPem(blob.Der);
    }

    public async Task<string?> GetLatestDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var blob = await GetLatestDeltaCrlRawAsync(caCertificateId, cancellationToken);
        return blob == null ? null : BuildPem(blob.Der);
    }

    /// <summary>
    /// Returns the raw DER bytes of the latest full CRL plus cache
    /// metadata the controllers need for HTTP cache headers. Avoids the PEM round-trip on
    /// every public CRL fetch.
    /// </summary>
    public async Task<CrlBlob?> GetLatestCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var ca = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == caCertificateId, cancellationToken);

        if (ca == null)
            return null;

        // Look up CRL rows via the config/CaCertificateId FK when available,
        // falling back to IssuerName for legacy rows inserted before the migration.
        var blob = await _dbContext.Crls
            .AsNoTracking()
            .Where(c => !c.IsDelta
                && ((c.Task != null && c.Task.CaCertificateId == caCertificateId)
                    || c.IssuerName == ca.SubjectDN))
            .OrderByDescending(c => c.CrlNumber)
            .Select(c => new { c.RawData, c.ThisUpdate, c.NextUpdate, c.CrlNumber })
            .FirstOrDefaultAsync(cancellationToken);

        if (blob?.RawData == null || blob.RawData.Length == 0)
            return null;

        return new CrlBlob(blob.RawData, blob.ThisUpdate, blob.NextUpdate, blob.CrlNumber);
    }

    /// <summary>
    /// Raw-DER variant of <see cref="GetLatestDeltaCrlAsync"/>.
    /// </summary>
    public async Task<CrlBlob?> GetLatestDeltaCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
    {
        var ca = await _dbContext.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == caCertificateId, cancellationToken);

        if (ca == null)
            return null;

        var blob = await _dbContext.Crls
            .AsNoTracking()
            .Where(c => c.IsDelta
                && ((c.Task != null && c.Task.CaCertificateId == caCertificateId)
                    || c.IssuerName == ca.SubjectDN))
            .OrderByDescending(c => c.CrlNumber)
            .Select(c => new { c.RawData, c.ThisUpdate, c.NextUpdate, c.CrlNumber })
            .FirstOrDefaultAsync(cancellationToken);

        if (blob?.RawData == null || blob.RawData.Length == 0)
            return null;

        return new CrlBlob(blob.RawData, blob.ThisUpdate, blob.NextUpdate, blob.CrlNumber);
    }

    private static string? BuildPem(byte[]? der)
    {
        if (der == null || der.Length == 0)
            return null;
        return BuildPemString(der);
    }

    private static string BuildPemString(byte[] encoded)
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN X509 CRL-----");
        sb.AppendLine(Convert.ToBase64String(encoded, Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine("-----END X509 CRL-----");
        return sb.ToString();
    }
}
