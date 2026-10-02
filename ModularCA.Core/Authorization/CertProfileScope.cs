using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;

namespace ModularCA.Core.Authorization;

/// <summary>
/// Which certificate profiles a CA may issue under. A profile bound to no space and no CA is
/// instance-wide and admitted everywhere; any other profile is admitted only by a CA of its own
/// scope (its space, or the instance for a null tenant) and, when it is bound to a CA, only by
/// that CA. This replaced the query filter that once hid other scopes' profiles.
/// </summary>
public static class CertProfileScope
{
    /// <summary>Whether <paramref name="issuingCa"/> may issue under <paramref name="profile"/>.</summary>
    public static bool Admits(CertProfileEntity profile, CertificateAuthorityEntity issuingCa)
        => Admits(profile.TenantId, profile.CertificateAuthorityId, issuingCa.Id, issuingCa.TenantId);

    /// <summary>
    /// Whether a profile of <paramref name="profileTenantId"/> bound to
    /// <paramref name="profileCaId"/> may be used by CA <paramref name="caId"/> of
    /// <paramref name="caTenantId"/>.
    /// </summary>
    public static bool Admits(Guid? profileTenantId, Guid? profileCaId, Guid caId, Guid? caTenantId)
        => (profileTenantId == null && profileCaId == null)
           || (profileTenantId == caTenantId && (profileCaId == null || profileCaId == caId));

    /// <summary>
    /// Throws <see cref="ConfigurationValidationException"/> (<see cref="ErrorCodes.CertProfileOutOfScope"/>)
    /// when <see cref="Admits(Guid?, Guid?, Guid, Guid?)"/> refuses.
    /// </summary>
    public static void Ensure(Guid? profileTenantId, Guid? profileCaId, Guid caId, Guid? caTenantId)
    {
        if (!Admits(profileTenantId, profileCaId, caId, caTenantId))
            throw new ConfigurationValidationException(
                "The certificate profile belongs to another scope than the issuing CA. Use a profile of the CA's own "
                + "space, one bound to this CA, or an instance-wide profile.", ErrorCodes.CertProfileOutOfScope);
    }
}
