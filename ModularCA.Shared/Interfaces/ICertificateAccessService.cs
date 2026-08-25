namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Manages certificate-level access control entries (ACLs) when certificates are issued or reissued.
/// </summary>
public interface ICertificateAccessService
{
    /// <summary>
    /// Copies access permissions from the previous certificate to a reissued certificate.
    /// </summary>
    Task UpdatePermissionsOntoReissuedCertificate(Guid newCertId, Guid userContext, Guid? previousCertId);

    /// <summary>
    /// Grants the requesting user manage-level access to a newly issued certificate.
    /// </summary>
    Task SetPermissionsOnNewCertificate(Guid certId, Guid userContext);
}
