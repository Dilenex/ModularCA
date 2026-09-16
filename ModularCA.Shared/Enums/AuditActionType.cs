namespace ModularCA.Shared.Enums;

public static class AuditActionType
{
    // Certificate lifecycle
    public const string CertificateIssued = "CertificateIssued";
    public const string CertificateRevoked = "CertificateRevoked";
    public const string CertificateHeld = "CertificateHeld";
    public const string CertificateUnheld = "CertificateUnheld";
    public const string CertificateReissued = "CertificateReissued";
    public const string CertificateExported = "CertificateExported";

    // Authentication
    public const string UserLogin = "UserLogin";
    public const string UserLoginFailed = "UserLoginFailed";
    public const string UserCertLogin = "UserCertLogin";
    public const string UserLogout = "UserLogout";

    // MFA
    public const string MfaTokenInvalid = "MfaTokenInvalid";
    public const string MfaTotpFailed = "MfaTotpFailed";
    public const string MfaTotpVerified = "MfaTotpVerified";
    public const string MfaWebAuthnFailed = "MfaWebAuthnFailed";
    public const string MfaWebAuthnVerified = "MfaWebAuthnVerified";
    public const string MfaMtlsVerified = "MfaMtlsVerified";
    public const string MfaTotpSetup = "MfaTotpSetup";
    public const string MfaTotpRemoved = "MfaTotpRemoved";
    // Dedicated removal action types mirroring MfaTotpRemoved for
    // WebAuthn and mTLS. Used by TotpController/WebAuthnController/MtlsController
    // removal endpoints so SIEM queries can filter on a stable enum string instead of
    // parsing DetailsJson.Action.
    public const string MfaWebAuthnRemoved = "MfaWebAuthnRemoved";
    public const string MfaMtlsRemoved = "MfaMtlsRemoved";
    // Emitted whenever a step-up MFA verification fails (TOTP code
    // wrong, WebAuthn assertion wrong, rate-limit lockout hit). Symmetric counterpart
    // of the MfaStepUpVerified success record so SIEM can alert on brute-force
    // attempts against high-value operations.
    public const string MfaStepUpFailed = "MfaStepUpFailed";
    public const string MfaStepUpVerified = "MfaStepUpVerified";

    // User management
    public const string UserCreated = "UserCreated";
    public const string UserDeleted = "UserDeleted";
    public const string UserUpdated = "UserUpdated";
    public const string UserRoleAdded = "UserRoleAdded";
    public const string UserRoleRemoved = "UserRoleRemoved";
    public const string UserPasswordChanged = "UserPasswordChanged";
    public const string UserPasswordReset = "UserPasswordReset";

    // CSR operations
    public const string CsrSubmitted = "CsrSubmitted";
    public const string CsrApproved = "CsrApproved";
    public const string CsrRejected = "CsrRejected";

    // CRL operations
    public const string CrlGenerated = "CrlGenerated";

    // ACME protocol
    public const string AcmeAccountCreated = "AcmeAccountCreated";
    public const string AcmeAccountDeactivated = "AcmeAccountDeactivated";
    public const string AcmeOrderFinalized = "AcmeOrderFinalized";

    // SSH CA
    public const string SshCertIssued = "SshCertIssued";
    public const string SshCertRevoked = "SshCertRevoked";
    public const string SshCaKeyDisabled = "SshCaKeyDisabled";

    // Scheduled jobs
    public const string TlsCertificateRenewed = "TlsCertificateRenewed";
    public const string CrlExported = "CrlExported";
    public const string AcmeCleanupCompleted = "AcmeCleanupCompleted";
    public const string ProtocolCleanupCompleted = "ProtocolCleanupCompleted";
    public const string ExpiredCertificatesRevoked = "ExpiredCertificatesRevoked";
    // Emitted by SchedulerService.RunJobAsync when a scheduled
    // job's outer catch fires. Distinct from the individual job's own audit event
    // (e.g. CrlExported) so SIEM can alert on "scheduler dispatch crashed" without
    // having to parse per-job reason strings.
    public const string SchedulerJobFailed = "SchedulerJobFailed";

    // Keystore operations
    /// <summary>Emitted when a keystore file is successfully loaded + signature-verified at startup or on demand.</summary>
    public const string KeystoreLoaded = "KeystoreLoaded";
    /// <summary>Emitted when entries are appended to an existing keystore (new CA, cross-sign, intermediate creation, etc.).</summary>
    public const string KeystoreAppended = "KeystoreAppended";
    /// <summary>Emitted when file-level or per-entry signature verification rejects a keystore — possible tamper, pin rewrite, or forged file.</summary>
    public const string KeystoreSignatureFailed = "KeystoreSignatureFailed";
    /// <summary>Emitted when the SPKI-pin MAC check fails — DB-side pin has been swapped or the secondary passphrase rotated without re-saving.</summary>
    public const string KeystorePinMacFailed = "KeystorePinMacFailed";

    // Configuration changes
    public const string ConfigUpdated = "ConfigUpdated";
    public const string ApplicationRestarted = "ApplicationRestarted";

    // Profile management
    public const string CertProfileCreated = "CertProfileCreated";
    public const string CertProfileUpdated = "CertProfileUpdated";
    public const string CertProfileDeleted = "CertProfileDeleted";
    public const string SigningProfileCreated = "SigningProfileCreated";
    public const string SigningProfileUpdated = "SigningProfileUpdated";
    public const string SigningProfileDeleted = "SigningProfileDeleted";

    // Feature flags
    public const string FeatureFlagUpdated = "FeatureFlagUpdated";

    // Security policy
    public const string PasswordPolicyUpdated = "PasswordPolicyUpdated";
    public const string SecurityPolicyUpdated = "SecurityPolicyUpdated";
    public const string LdapPublisherPolicyUpdated = "LdapPublisherPolicyUpdated";
    public const string RateLimitPolicyUpdated = "RateLimitPolicyUpdated";

    // CT logs
    public const string CtLogCreated = "CtLogCreated";
    public const string CtLogUpdated = "CtLogUpdated";
    public const string CtLogDeleted = "CtLogDeleted";

    // Enrollment tokens
    public const string EnrollmentTokenGenerated = "EnrollmentTokenGenerated";
    public const string EnrollmentTokenRevoked = "EnrollmentTokenRevoked";
    public const string QrEnrollmentCompleted = "QrEnrollmentCompleted";

    // Protocol configuration
    public const string ProtocolConfigUpdated = "ProtocolConfigUpdated";

    // CA management
    public const string CaUpdated = "CaUpdated";
    public const string CaCreated = "CaCreated";
    // Placeholder constants for the future CA decommissioning
    // workflow. Adding them now means any later [HttpDelete] handler that forgets
    // the audit call has a compile-time candidate to reach for. CA removal is a
    // critical security event — it implies private key destruction, CRL freezing,
    // and trust chain breakage and must never land silently.
    public const string CaDeleted = "CaDeleted";
    public const string CaDecommissioned = "CaDecommissioned";
    public const string CaArchived = "CaArchived";

    // Keystore lifecycle events. Any code path that mutates the
    // keystore file (initial creation, runtime append, backup export) must emit
    // one of these so forensic responders can attribute "who touched the CA
    // private key store, and when." System-actor events (ActorUserId=null) are
    // still valuable — the calling process identity and call-site context is
    // captured in DetailsJson.
    public const string KeystoreInitialized = "KeystoreInitialized";
    public const string KeystoreUnlocked = "KeystoreUnlocked";
    public const string KeystoreKeyAdded = "KeystoreKeyAdded";
    public const string KeystoreKeyRemoved = "KeystoreKeyRemoved";
    public const string KeystoreKeyReplaced = "KeystoreKeyReplaced";
    public const string KeystoreBackupCreated = "KeystoreBackupCreated";
    public const string KeystoreBackfillRun = "KeystoreBackfillRun";

    // Trust anchors (cross-certification)
    public const string TrustAnchorImported = "TrustAnchorImported";
    public const string TrustAnchorDeleted = "TrustAnchorDeleted";
    public const string TrustAnchorToggled = "TrustAnchorToggled";

    // Backup and restore
    public const string BackupCreated = "BackupCreated";
    public const string BackupRestored = "BackupRestored";
    public const string BackupListed = "BackupListed";

    // ACME EAB keys
    public const string AcmeEabKeyCreated = "AcmeEabKeyCreated";
    public const string AcmeEabKeyDeleted = "AcmeEabKeyDeleted";

    // Group management
    public const string GroupCreated = "GroupCreated";
    public const string GroupUpdated = "GroupUpdated";
    public const string GroupDeleted = "GroupDeleted";
    public const string GroupMemberAdded = "GroupMemberAdded";
    public const string GroupMemberRemoved = "GroupMemberRemoved";

    // cert-manager integration
    public const string CertManagerSignCompleted = "CertManagerSignCompleted";
    public const string CertManagerSignFailed = "CertManagerSignFailed";

    // Key ceremony workflow
    public const string KeyCeremonyInitiated = "KeyCeremonyInitiated";
    public const string KeyCeremonyApproved = "KeyCeremonyApproved";
    public const string KeyCeremonyRejected = "KeyCeremonyRejected";
    public const string KeyCeremonyExecuted = "KeyCeremonyExecuted";
    public const string KeyCeremonyCancelled = "KeyCeremonyCancelled";
    public const string KeyCeremonyExpired = "KeyCeremonyExpired";

    /// <summary>
    /// Emitted when a <c>TenantPolicyChange</c> ceremony executes successfully and actually
    /// mutates the tenant row — distinct from <c>KeyCeremonyExecuted</c> so the tenant-policy
    /// before/after diff has its own action name for easier audit filtering.
    /// </summary>
    public const string TenantPolicyChangeApplied = "TenantPolicyChangeApplied";

    /// <summary>
    /// Emitted when a <c>ControlledUserChange</c> ceremony executes and actually applies a
    /// controlled user's privilege change (promote/demote/delete). Distinct from
    /// <c>KeyCeremonyExecuted</c> so privilege-lifecycle changes have their own audit action.
    /// </summary>
    public const string ControlledUserChangeApplied = "ControlledUserChangeApplied";

    // Policy sync
    public const string PolicySyncExecuted = "PolicySyncExecuted";
    public const string PolicySyncImported = "PolicySyncImported";

    // Tenant management
    public const string TenantCreated = "TenantCreated";
    public const string TenantUpdated = "TenantUpdated";
    public const string TenantDisabled = "TenantDisabled";

    // IP Whitelist management
    public const string WhitelistCreated = "WhitelistCreated";
    public const string WhitelistUpdated = "WhitelistUpdated";
    public const string WhitelistDeleted = "WhitelistDeleted";

    // LDAP group sync
    public const string LdapMappingUpdated = "LdapMappingUpdated";
    public const string LdapSyncTriggered = "LdapSyncTriggered";

    // LDAP publisher management
    public const string LdapPublisherCreated = "LdapPublisherCreated";
    public const string LdapPublisherUpdated = "LdapPublisherUpdated";
    public const string LdapPublisherDeleted = "LdapPublisherDeleted";

    // OID catalog management
    public const string OidOptionCreated = "OidOptionCreated";
    public const string OidOptionDeleted = "OidOptionDeleted";

    // Certificate renewal
    public const string CertificateRenewalInitiated = "CertificateRenewalInitiated";

    // Quota management
    public const string QuotaUpdated = "QuotaUpdated";

    // Privileged access / system-admin bypass events. Emitted from the
    // authorization service when a system admin accesses a CA or tenant's rows without a
    // direct CA-scoped group membership.
    public const string SystemAdminElevatedAccess = "SystemAdminElevatedAccess";

    // Certificate permission management
    public const string CertPermissionViewGranted = "CertPermissionViewGranted";
    public const string CertPermissionManageGranted = "CertPermissionManageGranted";
    public const string CertPermissionDowngraded = "CertPermissionDowngraded";
    public const string CertPermissionRevoked = "CertPermissionRevoked";

    // SSH profile management
    public const string SshSigningProfileCreated = "SshSigningProfileCreated";
    public const string SshSigningProfileUpdated = "SshSigningProfileUpdated";
    public const string SshSigningProfileDeleted = "SshSigningProfileDeleted";
    public const string SshCertProfileCreated = "SshCertProfileCreated";
    public const string SshCertProfileUpdated = "SshCertProfileUpdated";
    public const string SshCertProfileDeleted = "SshCertProfileDeleted";
    public const string SshRequestProfileCreated = "SshRequestProfileCreated";
    public const string SshRequestProfileUpdated = "SshRequestProfileUpdated";
    public const string SshRequestProfileDeleted = "SshRequestProfileDeleted";

    // SSH template management
    public const string SshTemplateCreated = "SshTemplateCreated";
    public const string SshTemplateUpdated = "SshTemplateUpdated";
    public const string SshTemplateDeleted = "SshTemplateDeleted";

    // CRL schedule management
    public const string CrlScheduleCreated = "CrlScheduleCreated";
    public const string CrlScheduleUpdated = "CrlScheduleUpdated";
    public const string CrlScheduleDeleted = "CrlScheduleDeleted";
    public const string CrlScheduleStatusChanged = "CrlScheduleStatusChanged";

    // Scheduler admin operations
    public const string SchedulerJobUpdated = "SchedulerJobUpdated";
    public const string SchedulerJobManualRun = "SchedulerJobManualRun";
    public const string SchedulerScheduleUpdated = "SchedulerScheduleUpdated";
    public const string SchedulerScheduleDeleted = "SchedulerScheduleDeleted";
    public const string SchedulerScheduleManualRun = "SchedulerScheduleManualRun";
    public const string SchedulerConfigUpdated = "SchedulerConfigUpdated";

    // Compliance
    /// <summary>An operator cleared a compliance finding. Previously unrecorded entirely.</summary>
    public const string ComplianceFindingResolved = "ComplianceFindingResolved";

    // Access badges
    /// <summary>A session put a badge on, took one off, or switched badges. Details name both sides.</summary>
    public const string BadgeSwitched = "BadgeSwitched";
    public const string BadgeCreated = "BadgeCreated";
    public const string BadgeUpdated = "BadgeUpdated";
    public const string BadgeDeleted = "BadgeDeleted";

    // Kerberos realm bindings (Windows autoenrollment)
    /// <summary>A forest was bound to a tenant. Details name the realm, SPN and enrollment user; never a key.</summary>
    public const string KerberosRealmCreated = "KerberosRealmCreated";
    public const string KerberosRealmUpdated = "KerberosRealmUpdated";
    public const string KerberosRealmDisabled = "KerberosRealmDisabled";
    public const string KerberosRealmDeleted = "KerberosRealmDeleted";
    /// <summary>A key version was imported or derived. Details carry the version and types, never the key.</summary>
    public const string KerberosRealmKeyAdded = "KerberosRealmKeyAdded";
    public const string KerberosRealmKeyRetired = "KerberosRealmKeyRetired";
}
