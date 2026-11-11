namespace ModularCA.Shared.Authorization;

/// <summary>
/// String constants for all capability grant values used in the authorization system.
/// Each constant maps to a row in the CapabilityGrants table.
/// </summary>
public static class Capabilities
{
    // Certificate operations
    public const string CertRequest = "cert.request";
    public const string CertView = "cert.view";
    public const string CertRevoke = "cert.revoke";
    public const string CertReissue = "cert.reissue";
    public const string CertApprove = "cert.approve";

    // Profile operations
    public const string ProfileView = "profile.view";
    public const string ProfileUse = "profile.use";
    public const string ProfileManage = "profile.manage";
    public const string ProfileAssign = "profile.assign";

    // Token operations
    public const string TokenCreate = "token.create";
    public const string TokenManage = "token.manage";

    // CA management
    public const string CaView = "ca.view";
    public const string CaManage = "ca.manage";

    // Group & user management
    public const string GroupView = "group.view";
    public const string GroupManage = "group.manage";
    public const string UserManage = "user.manage";

    // Audit & system
    public const string AuditView = "audit.view";
    public const string BackupManage = "backup.manage";
    public const string SystemManage = "system.manage";

    /// <summary>All defined capabilities.</summary>
    public static readonly string[] All = new[]
    {
        CertRequest, CertView, CertRevoke, CertReissue, CertApprove,
        ProfileView, ProfileUse, ProfileManage, ProfileAssign,
        TokenCreate, TokenManage,
        CaView, CaManage,
        GroupView, GroupManage, UserManage,
        AuditView, BackupManage, SystemManage
    };

    /// <summary>Capabilities granted to the Administrator template.</summary>
    public static readonly string[] AdministratorTemplate = All;

    /// <summary>
    /// Capabilities granted to the Operator template. It carries <see cref="ProfileUse"/> since
    /// 0.4.4: approving and issuing ask for it on the signing and certificate profile, and
    /// without it the template's own <see cref="CertApprove"/> could approve nothing. The
    /// migration <c>OperatorRoleUsesProfiles</c> adds it to installs from before.
    /// </summary>
    public static readonly string[] OperatorTemplate = new[]
    {
        CertRequest, CertView, CertRevoke, CertReissue, CertApprove,
        ProfileView, ProfileUse, ProfileAssign,
        TokenCreate, TokenManage,
        CaView, CaManage,
        GroupView
    };

    /// <summary>Capabilities granted to the Auditor template.</summary>
    public static readonly string[] AuditorTemplate = new[]
    {
        CertView, ProfileView, CaView, GroupView, AuditView
    };

    /// <summary>Capabilities granted to the Requester template.</summary>
    public static readonly string[] RequesterTemplate = new[]
    {
        CertRequest, CertView
    };
}
