using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;

namespace ModularCA.Auth.Implementations
{
    /// <summary>
    /// Evaluates certificate access by checking all four grant sources:
    /// group direct grants, group role assignments, user direct grants, and user role assignments.
    /// Falls back to explicit per-cert ACL entries.
    /// </summary>
    public class CertificateAccessEvaluator : ICertificateAccessEvaluator
    {
        private readonly ModularCADbContext _db;

        public CertificateAccessEvaluator(ModularCADbContext db)
        {
            _db = db;
        }

        /// <summary>
        /// Checks if the user has the given capability for the given CA across all 4 grant sources.
        /// </summary>
        private bool HasCapabilityForCa(Guid userId, string capability, Guid? caId, Guid? spaceId)
        {
            // Source 1: group direct grants (system, space, CA-scoped). The `caId != null` guard mirrors
            // sources 3/4 — without it a null caId made `CertificateAuthorityId == caId` match every
            // space-wide group (CA id null) across ALL spaces.
            if (_db.CapabilityGrants.Any(g =>
                    g.Group.Members.Any(m => m.UserId == userId) &&
                    g.Capability == capability && g.ResourceType == null &&
                    (g.Group.IsSystemGroup
                     || (caId != null && g.Group.CertificateAuthorityId == caId)
                     || (spaceId != null && g.Group.CertificateAuthorityId == null && !g.Group.IsSystemGroup && g.Group.SpaceId == spaceId))))
                return true;

            // Source 2: role via group
            if (_db.RoleAssignments.Any(ra =>
                    ra.GroupId != null &&
                    ra.Group!.Members.Any(m => m.UserId == userId) &&
                    ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null) &&
                    (ra.Group.IsSystemGroup
                     || (caId != null && ra.Group.CertificateAuthorityId == caId)
                     || (spaceId != null && ra.Group.CertificateAuthorityId == null && !ra.Group.IsSystemGroup && ra.Group.SpaceId == spaceId))))
                return true;

            // Source 3: direct user grants
            if (_db.UserCapabilityGrants.Any(ug =>
                    ug.UserId == userId && ug.Capability == capability && ug.ResourceType == null &&
                    ((ug.SpaceId == null && ug.CertificateAuthorityId == null)
                     || (spaceId != null && ug.SpaceId == spaceId && ug.CertificateAuthorityId == null)
                     || (caId != null && ug.CertificateAuthorityId == caId))))
                return true;

            // Source 4: role via user
            if (_db.RoleAssignments.Any(ra =>
                    ra.UserId == userId && ra.GroupId == null &&
                    ra.Role.Capabilities.Any(rc => rc.Capability == capability && rc.ResourceType == null) &&
                    ((ra.SpaceId == null && ra.CertificateAuthorityId == null)
                     || (spaceId != null && ra.SpaceId == spaceId && ra.CertificateAuthorityId == null)
                     || (caId != null && ra.CertificateAuthorityId == caId))))
                return true;

            return false;
        }

        /// <summary>
        /// Resolves the (CA, space) scope that gates a certificate: the CA that owns it as a CA
        /// certificate (current or superseded), else the CA that owns its issuer certificate
        /// (current or superseded), per <see cref="IssuerChainResolver.OwnerOf(ModularCADbContext, CertificateEntity)"/>.
        /// The console's list filters use the same ownership, so the two agree. Returning null
        /// here used to collapse space scoping and over-grant access across spaces.
        /// </summary>
        private (Guid? caId, Guid? spaceId) ResolveCertScope(CertificateEntity cert)
        {
            var owner = IssuerChainResolver.OwnerOf(_db, cert);
            if (owner == null && cert.IssuerCertificateId is Guid issuerId && issuerId != cert.CertificateId)
                owner = IssuerChainResolver.OwnerOf(_db, issuerId);
            return (owner?.CaId, owner?.SpaceId);
        }

        /// <summary>
        /// Determines whether the user can view the specified certificate.
        /// </summary>
        public bool CanViewCertificate(Guid userId, Guid certificateId)
        {
            var cert = _db.Certificates.FirstOrDefault(c => c.CertificateId == certificateId);
            if (cert == null) return false;

            var (caId, spaceId) = ResolveCertScope(cert);

            if (HasCapabilityForCa(userId, Capabilities.CertView, caId, spaceId))
                return true;

            // Original requestor can always view their own cert
            if (_db.CertificateRequests.Any(r =>
                r.IssuedCertificateId == certificateId && r.RequestorUserId == userId))
                return true;

            // Explicit ACL
            return _db.CertificateAccessLists.Any(a =>
                a.UserId == userId && a.CertificateId == certificateId &&
                a.AccessLevel >= CertificateAccessLevel.View);
        }

        /// <summary>
        /// Determines whether the user can manage (revoke, reissue, etc.) the specified certificate.
        /// </summary>
        public bool CanManageCertificate(Guid userId, Guid certificateId)
        {
            var cert = _db.Certificates.FirstOrDefault(c => c.CertificateId == certificateId);
            if (cert == null) return false;

            var (caId, spaceId) = ResolveCertScope(cert);

            if (HasCapabilityForCa(userId, Capabilities.SystemManage, caId, spaceId))
                return true;
            if (HasCapabilityForCa(userId, Capabilities.CertRevoke, caId, spaceId))
                return true;

            // The original requestor gets self-service over the certificate they asked for:
            // export the key the CA generated for them, renew it, revoke it. CanViewCertificate
            // has always had this clause and this one did not, which left a user able to SEE a
            // server-generated certificate but never to export its key — making the key
            // permanently unreachable to the only person who needs it — and unable to revoke
            // their own certificate through an endpoint named RevokeOwnCertificate.
            //
            // Two exclusions, because "I requested it" must not confer control over the CA's
            // own machinery: CA certificates, and infrastructure certificates (OCSP/TSA
            // responders), where a revoke would take out the CA's responder.
            if (!cert.IsCA && _db.CertificateRequests.Any(r =>
                    r.IssuedCertificateId == certificateId
                    && r.RequestorUserId == userId
                    && !r.IsInfrastructureCert))
                return true;

            // Explicit ACL
            return _db.CertificateAccessLists.Any(a =>
                a.UserId == userId && a.CertificateId == certificateId &&
                a.AccessLevel == CertificateAccessLevel.Manage);
        }
    }
}
