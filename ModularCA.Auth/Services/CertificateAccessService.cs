using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Auth.Services
{
    /// <summary>
    /// Manages certificate-level ACLs by copying permissions on reissue and granting
    /// initial manage access to the requestor on new issuance. Reissue is a no-op when
    /// no prior certificate with the same <c>SubjectDN</c> exists (brand-new subject) —
    /// the caller's grant path runs separately so the new cert still ends up with the
    /// requestor's manage permission.
    /// </summary>
    public class CertificateAccessService(
        ModularCADbContext dbContext,
        TimeProvider? timeProvider = null) : ICertificateAccessService
    {
        private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

        /// <summary>
        /// Copies access permissions from the certificate being reissued onto its replacement.
        /// </summary>
        /// <param name="newCertId">The newly issued certificate.</param>
        /// <param name="userContext">The operator performing the reissue, recorded as grantor.</param>
        /// <param name="previousCertId">
        /// The certificate actually being replaced. When null, nothing is inherited.
        /// </param>
        /// <remarks>
        /// The predecessor is passed in explicitly because every caller already knows it — the
        /// reissue request names it by id, by serial, or via the CSR's IssuedCertificateId.
        /// <para>
        /// This method used to FIND the predecessor itself, by <c>SubjectDN</c> string equality
        /// across the whole Certificates table, ordered by NotBefore. CertificateEntity carries
        /// no tenant query filter, so that search spanned every CA in every tenant: any
        /// certificate anywhere sharing the subject — and holding a newer NotBefore — donated its
        /// ACL rows to this one. Two tenants both issuing CN=vpn.example.com cross-pollinated
        /// permissions on every renewal with no attacker involved, and a user who could get a
        /// certificate issued with a chosen subject on any CA could plant a Manage grant that
        /// landed on someone else's production certificate at its next reissue — from there,
        /// PFX export hands over the private key.
        /// </para>
        /// <para>
        /// Fails closed: an unknown predecessor inherits nothing rather than guessing.
        /// </para>
        /// </remarks>
        public async Task UpdatePermissionsOntoReissuedCertificate(Guid newCertId, Guid userContext, Guid? previousCertId)
        {
            var newCert = await dbContext.Certificates.FindAsync(newCertId);
            if (newCert == null)
                throw new InvalidOperationException("New certificate not found");

            if (previousCertId == null || previousCertId == newCertId)
                return; // Nothing identified to inherit from. Caller's own grant path runs separately.

            var oldCert = await dbContext.Certificates
                .FirstOrDefaultAsync(c => c.CertificateId == previousCertId.Value);

            if (oldCert == null)
                return; // Predecessor no longer present — inherit nothing rather than guess.

            // Copy permissions from old certificate to new certificate.
            var permissions = await dbContext.CertificateAccessLists
                .Where(c => c.CertificateId == oldCert.CertificateId)
                .ToListAsync();

            // Users that already hold an ACL row on the new cert — e.g. the requestor's manage grant
            // added by the issuance path. The (UserId, CertificateId) unique index means re-inserting
            // any of these throws a duplicate-key DbUpdateException (the reissue 500), so skip them.
            var alreadyGranted = (await dbContext.CertificateAccessLists
                .Where(c => c.CertificateId == newCert.CertificateId)
                .Select(c => c.UserId)
                .ToListAsync()).ToHashSet();

            foreach (var permission in permissions)
            {
                // HashSet.Add returns false when the user is already present (pre-existing row, or a
                // duplicate within this copy) — skip to honor the unique constraint.
                if (!alreadyGranted.Add(permission.UserId))
                    continue;

                dbContext.CertificateAccessLists.Add(new CertificateAccessListEntity
                {
                    UserId = permission.UserId,
                    CertificateId = newCert.CertificateId,
                    AccessLevel = permission.AccessLevel,
                    GrantedAt = _timeProvider.GetUtcNow().UtcDateTime,
                    GrantedByUserId = userContext
                });
            }
            await dbContext.SaveChangesAsync();
        }

        /// <summary>
        /// Grants manage-level access to the user who originally requested the certificate.
        /// </summary>
        public async Task SetPermissionsOnNewCertificate(Guid certId, Guid userContext)
        {
            var cert = await dbContext.Certificates.FindAsync(certId);
            if (cert == null)
                throw new InvalidOperationException("Certificate not found");

            var csrEntry = await dbContext.CertificateRequests.Where(c => c.IssuedCertificateId == certId).FirstOrDefaultAsync();
            if (csrEntry == null)
                throw new InvalidOperationException("Certificate request not found");
            var userId = csrEntry.RequestorUserId;
            if (userId == null)
                throw new InvalidOperationException("User not found");

            var permission = new CertificateAccessListEntity
            {
                UserId = userId.Value,
                CertificateId = cert.CertificateId,
                AccessLevel = CertificateAccessLevel.Manage,
                GrantedAt = _timeProvider.GetUtcNow().UtcDateTime,
                GrantedByUserId = userContext
            };
            dbContext.CertificateAccessLists.Add(permission);
            await dbContext.SaveChangesAsync();
        }
    }
}
