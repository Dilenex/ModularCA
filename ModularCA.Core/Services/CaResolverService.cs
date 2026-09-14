using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Core.Services;

/// <summary>
/// Resolves the appropriate CA and its protocol-specific profile configuration from a label and protocol.
/// </summary>
public class CaResolverService(ModularCADbContext db) : ICaResolverService
{
    /// <summary>
    /// Resolves the CA, protocol-specific signing/cert profile, and optional request profile
    /// from the given label and protocol identifier.
    /// </summary>
    public async Task<ResolvedCaContext> ResolveAsync(string? caLabel, string protocol)
    {
        var ca = await ResolveCaEntityAsync(caLabel)
            ?? throw new InvalidOperationException(
                caLabel != null
                    ? $"CA with label '{caLabel}' not found or disabled."
                    : "No enabled Certificate Authority found. Run bootstrap or create a CA.");

        // SSH CAs cannot serve X.509 protocols
        if (ca.IsSshCa)
            throw new InvalidOperationException(
                $"CA '{ca.Name}' is an SSH CA and does not support X.509 protocol '{protocol}'.");

        var protocolUpper = protocol.ToUpperInvariant();
        var config = await db.CaProtocolConfigs
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CaId == ca.Id && c.Protocol == protocolUpper);

        if (config != null && !config.IsEnabled)
            throw new InvalidOperationException(
                $"Protocol '{protocol}' is disabled for CA '{ca.Name}'.");

        if (config?.SigningProfileId == null || config?.CertProfileId == null)
            throw new InvalidOperationException(
                $"Protocol '{protocol}' is not fully configured for CA '{ca.Name}'. " +
                $"Assign both a signing profile and certificate profile in the Protocol Configuration page.");

        return new ResolvedCaContext
        {
            Ca = ca,
            SigningProfileId = config.SigningProfileId.Value,
            CertProfileId = config.CertProfileId.Value,
            RequestProfileId = config.RequestProfileId
        };
    }

    /// <summary>
    /// Resolves the CA, signing profile, cert profile, and optional request profile
    /// from a named certificate template. Throws if the template is not found or disabled.
    /// </summary>
    public async Task<ResolvedCaContext> ResolveByTemplateAsync(string templateName)
    {
        var template = await db.CertificateTemplates
            .AsNoTracking()
            .Include(t => t.Ca)
            .FirstOrDefaultAsync(t => t.Name == templateName)
            ?? throw new InvalidOperationException(
                $"Certificate template '{templateName}' not found.");

        if (!template.IsEnabled)
            throw new InvalidOperationException(
                $"Certificate template '{templateName}' is disabled.");

        if (template.Ca == null || !template.Ca.IsEnabled)
            throw new InvalidOperationException(
                $"CA for template '{templateName}' is not found or disabled.");

        return new ResolvedCaContext
        {
            Ca = template.Ca,
            SigningProfileId = template.SigningProfileId,
            CertProfileId = template.CertProfileId,
            RequestProfileId = template.RequestProfileId
        };
    }

    /// <inheritdoc />
    public async Task<CertificateAuthorityEntity?> ResolveCaEntityAsync(string? caLabel)
    {
        if (!string.IsNullOrWhiteSpace(caLabel))
        {
            return await db.CertificateAuthorities
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Label == caLabel && c.IsEnabled);
        }

        // Try default CA first, then any enabled CA
        return await db.CertificateAuthorities
            .AsNoTracking()
            .Where(c => c.IsEnabled)
            .OrderByDescending(c => c.IsDefault)
            .FirstOrDefaultAsync();
    }
}
