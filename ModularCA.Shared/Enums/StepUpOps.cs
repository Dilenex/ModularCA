namespace ModularCA.Shared.Enums;

/// <summary>
/// Canonical, compile-time-safe constants for every step-up MFA
/// protected operation. Every call-site that invokes
/// <c>MfaStepUpController.ValidateStepUpTokenAsync</c> must pass one of these
/// constants instead of a raw string literal so the registry cannot drift from
/// reality and renames are caught at compile time.
/// <para>
/// The <see cref="All"/> set is the enforcement allow-list: it is consulted inside
/// <c>MfaStepUpController.IssueStepUpTokenAsync</c> so a client cannot request a
/// token for an arbitrary operation string.
/// </para>
/// </summary>
public static class StepUpOps
{
    // Certificate revocation
    /// <summary>Broadening a session's access badge: taking one off, or switching to one that keeps more.</summary>
    public const string SwitchBadge = "switch-badge";
    /// <summary>Creating, changing, keying or deleting a Kerberos realm binding for Windows autoenrollment.</summary>
    public const string ManageKerberosRealm = "manage-kerberos-realm";
    /// <summary>Adding, removing or reissuing the certificate of a hostname a tenant is reached by.</summary>
    public const string ManageTenantHostname = "manage-tenant-hostname";
    public const string RevokeCert = "revoke-cert";
    public const string HoldCert = "hold-cert";
    public const string UnholdCert = "unhold-cert";

    // User self-service revocation of an owned end-entity certificate
    public const string RevokeSelfCert = "revoke-self-cert";

    // Certificate reissuance
    public const string ReissueCert = "reissue-cert";

    // Certificate export
    public const string ExportCert = "export-cert";

    // Per-certificate ACL changes (grant/change/revoke a user's view/manage access on a cert)
    public const string UpdateCertAcl = "update-cert-acl";

    // User management
    public const string CreateUser = "create-user";
    public const string UpdateUser = "update-user";
    public const string DeleteUser = "delete-user";

    // Group membership
    public const string AddGroupMember = "add-group-member";
    public const string RemoveGroupMember = "remove-group-member";

    // Bulk user-group edit (add + remove groups for one user in a single step-up-gated batch; each
    // controlled change still spawns its own ceremony)
    public const string UpdateUserGroups = "update-user-groups";

    // Group lifecycle (CA-scoped authorization groups)
    public const string CreateGroup = "create-group";
    public const string DeleteGroup = "delete-group";
    public const string UpdateGroup = "update-group";

    // Direct user capability grants
    public const string GrantUserCapability = "grant-user-capability";
    public const string RevokeUserCapability = "revoke-user-capability";

    // Role catalog (named bundles of capabilities)
    public const string CreateRole = "create-role";
    public const string UpdateRole = "update-role";
    public const string DeleteRole = "delete-role";

    // Role assignments (binding a role to a user/group with optional scope)
    public const string AssignRole = "assign-role";
    public const string UnassignRole = "unassign-role";

    // Password & MFA resets
    public const string ResetPassword = "reset-password";
    public const string ResetMfa = "reset-mfa";
    public const string ChangePassword = "change-password";

    // Self-service email change (account detail page). Email is an identity/recovery field, so a
    // user changing their own email must re-verify with step-up MFA.
    public const string ChangeEmail = "change-email";

    // Backup & restore
    public const string CreateBackup = "create-backup";
    public const string RestoreBackup = "restore-backup";
    public const string SetBackupPassword = "set-backup-password";
    public const string ChangeBackupEncryptionMode = "change-backup-encryption-mode";

    // CA management
    public const string CreateCa = "create-ca";
    public const string UpdateCa = "update-ca";
    public const string RevokeCa = "revoke-ca";

    /// <summary>
    /// Reissuing a CA's delegated OCSP responder or TSA certificate. Gated because it mints a new
    /// signing identity for the CA and repoints the CA at it — get it wrong and the CA's OCSP
    /// answers unauthorized for every request, which is exactly how this operation came to exist.
    /// </summary>
    public const string ReissueInfrastructureCerts = "reissue-infrastructure-certs";

    // Profile management
    public const string UpdateSigningProfile = "update-signing-profile";
    public const string DeleteSigningProfile = "delete-signing-profile";
    public const string UpdateCertProfile = "update-cert-profile";
    public const string DeleteCertProfile = "delete-cert-profile";
    public const string UpdateRequestProfile = "update-request-profile";
    public const string DeleteRequestProfile = "delete-request-profile";

    // Whitelist management
    public const string CreateWhitelist = "create-whitelist";
    public const string UpdateWhitelist = "update-whitelist";
    public const string DeleteWhitelist = "delete-whitelist";

    // Policy sync
    public const string PolicySync = "policy-sync";
    public const string PolicyImport = "policy-import";

    // Protocol / system config
    public const string UpdateProtocolConfig = "update-protocol-config";
    public const string UpdateConfig = "update-config";
    public const string Restart = "restart";

    // SSH CA management
    public const string CreateSshCa = "create-ssh-ca";
    public const string DisableSshCa = "disable-ssh-ca";

    // Key ceremony workflow
    public const string InitiateCeremony = "initiate-ceremony";
    public const string ApproveCeremony = "approve-ceremony";
    public const string RejectCeremony = "reject-ceremony";
    public const string CancelCeremony = "cancel-ceremony";
    public const string ExecuteCeremony = "execute-ceremony";
    public const string DisableCeremonyRequirement = "disable-ceremony-requirement";

    // Scheduler admin operations
    public const string UpdateSchedulerJob = "update-scheduler-job";
    public const string RunSchedulerJob = "run-scheduler-job";
    public const string UpdateSchedulerSchedule = "update-scheduler-schedule";
    public const string DeleteSchedulerSchedule = "delete-scheduler-schedule";
    public const string RunSchedulerSchedule = "run-scheduler-schedule";
    public const string UpdateSchedulerConfig = "update-scheduler-config";

    // CRL schedule administration (per-CA CRL generation configurations).
    // Distinct from the scheduler aggregator constants above: these gate the
    // existing AdminCrlScheduleController which manipulates CrlConfigurationEntity rows directly.
    public const string CreateCrlSchedule = "create-crl-schedule";
    public const string UpdateCrlSchedule = "update-crl-schedule";
    public const string DeleteCrlSchedule = "delete-crl-schedule";
    public const string ToggleCrlSchedule = "toggle-crl-schedule";

    // OID catalog administration. The catalog is global and decides what usages every CA in the
    // deployment may issue, so widening it is a system-wide change, not a per-CA one.
    public const string ManageOidCatalog = "manage-oid-catalog";

    // LDAP publisher administration (per-CA LDAP publishing configurations).
    public const string CreateLdapPublisher = "create-ldap-publisher";
    public const string UpdateLdapPublisher = "update-ldap-publisher";
    public const string DeleteLdapPublisher = "delete-ldap-publisher";

    // Bulk distribution-config operations (Distribution page): a single token authorizes a
    // batch of enable/disable/delete actions across several CRL schedules or LDAP publishers,
    // so operating on a multi-row selection prompts for step-up exactly once instead of per row.
    // BulkCrlSchedule is batch-scoped (no target) because a selection can span CAs; BulkLdapPublisher
    // is bound to the owning CA id because LDAP publishers are addressed under a single CA route.
    public const string BulkCrlSchedule = "bulk-crl-schedule";
    public const string BulkLdapPublisher = "bulk-ldap-publisher";

    // Certificate Transparency log catalog. CT log URL + public key are system-wide
    // artifacts — corrupting them silently breaks SCT embedding for every tenant,
    // so mutations require step-up MFA on top of the SystemOperator policy.
    public const string CreateCtLog = "create-ct-log";
    public const string UpdateCtLog = "update-ct-log";
    public const string DeleteCtLog = "delete-ct-log";

    // Certificate template catalog (bundles CA + signing profile + cert profile).
    // Global artifacts that affect every tenant's enrollment flow; mutations require
    // step-up MFA on top of the SystemOperator policy.
    public const string CreateCertificateTemplate = "create-certificate-template";
    public const string UpdateCertificateTemplate = "update-certificate-template";
    public const string DeleteCertificateTemplate = "delete-certificate-template";

    // Per-CA service URL configuration (CDP / AIA / OCSP base URL). Mutating these
    // can silently redirect revocation lookups and issuer fetches — a classic
    // certificate-poisoning vector — so writes require step-up MFA.
    public const string UpdateCaServiceUrl = "update-ca-service-url";
    public const string DeleteCaServiceUrl = "delete-ca-service-url";

    // Feature flag catalog. Flipping a flag can disable Syslog/EventLog/metrics
    // emission or other security gates without code review, so writes require
    // step-up MFA on top of the SystemOperator policy.
    public const string UpdateFeatureFlag = "update-feature-flag";

    /// <summary>
    /// Deleting an ACME External Account Binding key. The admin UI has always requested step-up
    /// for this, but the operation was missing here and the endpoint carried no attribute — so
    /// MfaStepUpController rejected the request with 400 invalid_step_up_operation and the key
    /// could not be deleted at all. An EAB key authorizes ACME account binding, so it gets the
    /// same protection as every other destructive admin action.
    /// </summary>
    public const string DeleteEabKey = "delete-eab-key";

    // SSH profile catalog (signing / cert / request profiles all bind to the same
    // SSH CA key catalog). Reused across all three profile types because they
    // converge on the same signing material.
    public const string CreateSshProfile = "create-ssh-profile";
    public const string UpdateSshProfile = "update-ssh-profile";
    public const string DeleteSshProfile = "delete-ssh-profile";

    // MFA enrollment (also allowed via mTLS)
    public const string TotpSetup = "totp-setup";
    public const string TotpVerifySetup = "totp-verify-setup";
    public const string TotpRemove = "totp-remove";
    public const string WebAuthnRegister = "webauthn-register";
    public const string WebAuthnDelete = "webauthn-delete";
    public const string MtlsEnroll = "mtls-enroll";
    public const string MtlsDelete = "mtls-delete";

    // Tenants
    public const string EnableTenant = "enable-tenant";
    public const string DisableTenant = "disable-tenant";

    // Combined tenant-settings save (detail page): a single token authorizes one atomic update of
    // a tenant's ceilings, per-CA issuance quotas, and tenant/CA user-approval quorums — so editing
    // several sensitive fields at once prompts for step-up exactly once.
    public const string UpdateTenantSettings = "update-tenant-settings";

    /// <summary>
    /// The canonical allow-list consulted by <c>IssueStepUpTokenAsync</c>. Any operation
    /// string not present here is rejected at issuance time with
    /// <c>invalid_step_up_operation</c>.
    /// </summary>
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        SwitchBadge,
        ManageKerberosRealm, ManageTenantHostname,
        RevokeCert, HoldCert, UnholdCert,
        RevokeSelfCert,
        ReissueCert,
        ExportCert,
        UpdateCertAcl,
        CreateUser, UpdateUser, DeleteUser,
        AddGroupMember, RemoveGroupMember, UpdateUserGroups,
        CreateGroup, DeleteGroup, UpdateGroup,
        GrantUserCapability, RevokeUserCapability,
        CreateRole, UpdateRole, DeleteRole,
        AssignRole, UnassignRole,
        ResetPassword, ResetMfa, ChangePassword, ChangeEmail,
        CreateBackup, RestoreBackup, SetBackupPassword, ChangeBackupEncryptionMode,
        CreateCa, UpdateCa, RevokeCa, ReissueInfrastructureCerts, CreateSshCa, DisableSshCa,
        UpdateSigningProfile, DeleteSigningProfile,
        UpdateCertProfile, DeleteCertProfile,
        UpdateRequestProfile, DeleteRequestProfile,
        CreateWhitelist, UpdateWhitelist, DeleteWhitelist,
        PolicySync, PolicyImport,
        UpdateProtocolConfig, UpdateConfig, Restart,
        InitiateCeremony, ApproveCeremony, RejectCeremony, CancelCeremony, ExecuteCeremony, DisableCeremonyRequirement,
        UpdateSchedulerJob, RunSchedulerJob,
        UpdateSchedulerSchedule, DeleteSchedulerSchedule, RunSchedulerSchedule,
        UpdateSchedulerConfig,
        CreateCrlSchedule, UpdateCrlSchedule, DeleteCrlSchedule, ToggleCrlSchedule,
        CreateLdapPublisher, UpdateLdapPublisher, DeleteLdapPublisher,
        ManageOidCatalog,
        BulkCrlSchedule, BulkLdapPublisher,
        CreateCtLog, UpdateCtLog, DeleteCtLog,
        CreateCertificateTemplate, UpdateCertificateTemplate, DeleteCertificateTemplate,
        UpdateCaServiceUrl, DeleteCaServiceUrl,
        UpdateFeatureFlag,
        DeleteEabKey,
        CreateSshProfile, UpdateSshProfile, DeleteSshProfile,
        TotpSetup, TotpVerifySetup, TotpRemove,
        WebAuthnRegister, WebAuthnDelete,
        MtlsEnroll, MtlsDelete,
        EnableTenant, DisableTenant, UpdateTenantSettings,
    };

    /// <summary>
    /// Restricted mTLS step-up allow-list — only MFA enrollment operations may be
    /// authorized via a client certificate. Destructive operations require TOTP or
    /// WebAuthn. Mirrors <c>MfaStepUpController.AllowedMtlsStepUpOperations</c>.
    /// </summary>
    public static readonly IReadOnlySet<string> AllowedViaMtls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        TotpSetup, TotpVerifySetup, TotpRemove,
        WebAuthnRegister, WebAuthnDelete,
        MtlsEnroll, MtlsDelete,
    };
}
