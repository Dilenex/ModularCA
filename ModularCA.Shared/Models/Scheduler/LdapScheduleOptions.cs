namespace ModularCA.Shared.Models.Scheduler
{
    public class LdapScheduleOptions
    {
        /// <summary>FK to the certificate authority this LDAP publish run targets.</summary>
        public Guid CertificateAuthorityId { get; set; }
        public string LdapHost { get; set; } = string.Empty;
        public int LdapPort { get; set; } = 389;

        /// <summary>
        /// Whether the bind runs over TLS (LDAPS), mirroring
        /// <c>LdapConfigurationEntity.UseSsl</c>.
        /// <para>
        /// This field did not exist, which is what made the operator-facing "Use SSL" checkbox
        /// inert: the column was written, read back and rendered, but the value stopped at the
        /// entity and never reached <c>LdapPublishHelper.Connect</c>. Every publisher bind — the
        /// scheduled run, the CRL hook, and the admin "Test Connection" button that reported
        /// success — was a cleartext simple bind carrying the directory credential.
        /// </para>
        /// </summary>
        public bool UseSsl { get; set; }

        public string BaseDn { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool PublishCRL { get; set; }
        public bool PublishDelta { get; set; }
        public bool PublishCACert { get; set; }

        /// <summary>
        /// When true, recently-issued end-entity certificates are published to
        /// the <c>userCertificate;binary</c> attribute of the corresponding LDAP user entry.
        /// </summary>
        public bool PublishUserCerts { get; set; }

        /// <summary>
        /// Template used to derive the target LDAP DN for a user certificate.
        /// Use <c>{email}</c> for the subject email and <c>{cn}</c> for the subject CN.
        /// Example: <c>uid={email},ou=People,dc=example,dc=com</c>.
        /// When empty the helper falls back to <c>cn={cn},{BaseDn}</c>.
        /// </summary>
        public string UserDnTemplate { get; set; } = string.Empty;

        public Guid TaskId { get; set; }
    }
}
