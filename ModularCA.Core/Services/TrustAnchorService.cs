using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.TrustAnchors;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace ModularCA.Core.Services;

/// <summary>
/// CRUD service for managing imported trust anchor certificates used in cross-certification.
/// Handles parsing, validation, persistence, and runtime registration of external CA certificates.
/// </summary>
public class TrustAnchorService(
    ModularCADbContext db,
    IKeystoreCertificates keystore,
    ILogger<TrustAnchorService> logger)
{
    /// <summary>
    /// Retrieves all trust anchors from the database.
    /// </summary>
    /// <returns>A list of all trust anchors as DTOs.</returns>
    public async Task<List<TrustAnchorDto>> GetAllAsync()
    {
        return await db.TrustAnchors
            .AsNoTracking()
            .OrderByDescending(t => t.ImportedAt)
            .Select(t => MapToDto(t))
            .ToListAsync();
    }

    /// <summary>
    /// Retrieves a single trust anchor by its unique identifier.
    /// </summary>
    /// <param name="id">The trust anchor ID.</param>
    /// <returns>The trust anchor DTO, or null if not found.</returns>
    public async Task<TrustAnchorDto?> GetByIdAsync(Guid id)
    {
        var entity = await db.TrustAnchors.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
        return entity == null ? null : MapToDto(entity);
    }

    /// <summary>
    /// Imports an external CA certificate as a trust anchor. The certificate is parsed from
    /// PEM or base64-encoded DER, validated to have BasicConstraints CA=true, persisted to the
    /// database, and registered in the runtime trusted list.
    /// </summary>
    /// <param name="pemOrBase64">PEM-encoded certificate or base64-encoded DER bytes.</param>
    /// <param name="label">Optional human-readable label.</param>
    /// <param name="description">Optional description of the trust anchor.</param>
    /// <param name="userId">The ID of the importing user.</param>
    /// <param name="username">The username of the importing user.</param>
    /// <returns>The created trust anchor DTO.</returns>
    /// <exception cref="InvalidOperationException">If the certificate is not a CA or is a duplicate.</exception>
    public async Task<TrustAnchorDto> ImportAsync(string pemOrBase64, string? label, string? description, Guid? userId, string? username)
    {
        // Parse the certificate from PEM or base64 DER
        X509Certificate cert;
        string pem;

        if (CertificateUtil.IsPemFormat(pemOrBase64))
        {
            cert = CertificateUtil.ParseFromPem(pemOrBase64);
            pem = pemOrBase64;
        }
        else
        {
            // Assume base64-encoded DER
            var derBytes = Convert.FromBase64String(pemOrBase64);
            cert = new X509Certificate(derBytes);
            pem = CertificateUtil.ConvertDerToPem(derBytes, "CERTIFICATE");
        }

        // Validate that this is a CA certificate via BasicConstraints
        var bcExt = cert.GetExtensionValue(X509Extensions.BasicConstraints);
        if (bcExt != null)
        {
            var constraints = BasicConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(bcExt));
            if (!constraints.IsCA())
                throw new InvalidOperationException("Certificate is not a CA certificate (BasicConstraints CA=false).");
        }
        else
        {
            throw new InvalidOperationException("Certificate does not have BasicConstraints extension — cannot verify it is a CA.");
        }

        var serialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber);

        // Check for duplicate
        var existing = await db.TrustAnchors.AnyAsync(t => t.SerialNumber == serialNumber);
        if (existing)
            throw new InvalidOperationException($"A trust anchor with serial number {serialNumber} already exists.");

        var entity = new TrustAnchorEntity
        {
            SubjectDN = cert.SubjectDN.ToString(),
            Issuer = cert.IssuerDN.ToString(),
            SerialNumber = serialNumber,
            Pem = pem,
            RawCertificate = cert.GetEncoded(),
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Label = label,
            Description = description,
            IsEnabled = true,
            ImportedByUserId = userId,
            ImportedByUsername = username,
            ImportedAt = DateTime.UtcNow,
            Thumbprints = CertificateUtil.GetThumbprints(cert)
        };

        db.TrustAnchors.Add(entity);
        await db.SaveChangesAsync();

        // Add to runtime trusted list
        keystore.RegisterTrustedCert(cert);
        logger.LogInformation("Trust anchor registered at runtime: {Subject} (serial {Serial})", entity.SubjectDN, serialNumber);

        return MapToDto(entity);
    }

    /// <summary>
    /// Deletes a trust anchor from the database. The certificate remains in the runtime
    /// trusted list until the application is restarted.
    /// </summary>
    /// <param name="id">The trust anchor ID to delete.</param>
    /// <returns>True if the trust anchor was found and deleted; false if not found.</returns>
    public async Task<bool> DeleteAsync(Guid id)
    {
        var entity = await db.TrustAnchors.FindAsync(id);
        if (entity == null)
            return false;

        db.TrustAnchors.Remove(entity);
        await db.SaveChangesAsync();

        logger.LogInformation("Trust anchor deleted: {Subject} (serial {Serial}). Will be removed from runtime on restart.",
            entity.SubjectDN, entity.SerialNumber);

        return true;
    }

    /// <summary>
    /// Enables or disables a trust anchor. Disabled trust anchors will not be loaded
    /// into the runtime trusted list on the next application restart.
    /// </summary>
    /// <param name="id">The trust anchor ID.</param>
    /// <param name="enabled">Whether to enable or disable the trust anchor.</param>
    /// <returns>The updated trust anchor DTO, or null if not found.</returns>
    public async Task<TrustAnchorDto?> ToggleAsync(Guid id, bool enabled)
    {
        var entity = await db.TrustAnchors.FindAsync(id);
        if (entity == null)
            return null;

        entity.IsEnabled = enabled;
        await db.SaveChangesAsync();

        logger.LogInformation("Trust anchor {Action}: {Subject} (serial {Serial})",
            enabled ? "enabled" : "disabled", entity.SubjectDN, entity.SerialNumber);

        return MapToDto(entity);
    }

    /// <summary>
    /// Maps a trust anchor entity to its DTO representation.
    /// </summary>
    private static TrustAnchorDto MapToDto(TrustAnchorEntity entity)
    {
        return new TrustAnchorDto
        {
            Id = entity.Id,
            SubjectDN = entity.SubjectDN,
            Issuer = entity.Issuer,
            SerialNumber = entity.SerialNumber,
            NotBefore = entity.NotBefore,
            NotAfter = entity.NotAfter,
            Label = entity.Label,
            Description = entity.Description,
            IsEnabled = entity.IsEnabled,
            ImportedByUsername = entity.ImportedByUsername,
            ImportedAt = entity.ImportedAt,
            Thumbprints = entity.Thumbprints
        };
    }
}
