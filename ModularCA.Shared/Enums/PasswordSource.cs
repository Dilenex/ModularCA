namespace ModularCA.Shared.Enums;

/// <summary>
/// Where an account's sign-in password is checked: against the directory (LDAP), against the
/// local password hash, or by the instance-wide LDAP setting. Stored on
/// <see cref="Entities.UserEntity.PasswordSource"/> by member name.
/// </summary>
public enum PasswordSource
{
    /// <summary>
    /// Follows the instance setting. With LDAP sign-in off, the local hash decides. With it on, the
    /// directory is asked first: an accepted bind signs in (and turns the account into
    /// <see cref="Directory"/>), a refused bind is final, no directory entry lets the local hash
    /// decide, and an unreachable directory refuses without counting a failed attempt. The default
    /// for every account, and the value every account had before the column existed.
    /// </summary>
    Inherit = 0,

    /// <summary>
    /// The local hash only. The directory is never asked, even with LDAP sign-in on, so the account
    /// signs in through an LDAP outage and in direct-bind mode. The bootstrap administrator starts
    /// here, so break-glass sign-in never depends on the directory.
    /// </summary>
    Local = 1,

    /// <summary>
    /// The directory only. The local hash is never consulted: a refused bind or a missing directory
    /// entry refuses the sign-in and counts a failed attempt; an unreachable directory, or LDAP
    /// sign-in turned off, refuses it without counting one. ModularCA keeps no usable password for
    /// such an account, so it cannot set one by self-service or admin reset.
    /// </summary>
    Directory = 2,
}
