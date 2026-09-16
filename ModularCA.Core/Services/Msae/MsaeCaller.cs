using ModularCA.Core.Services.Msae.Kerberos;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Who is asking the policy or enrollment service, and as whom they act. A credential caller
/// (UsernameToken or Basic) is the ModularCA user they signed in as. A Kerberos caller is a
/// forest principal acting with the capabilities of the realm binding's enrollment user, and
/// carries the identity the subject is built from.
/// </summary>
/// <param name="ActingAsUsername">The ModularCA username every capability check is made for.</param>
/// <param name="AuditPrincipal">What the audit row records as the caller: <c>user:alice</c> or <c>krb:WS-042$@CORP.CUSTOMER-A.LOCAL</c>.</param>
/// <param name="AuthMethod">How the caller authenticated: <c>UsernameToken</c>, <c>Basic</c> or <c>Kerberos</c>.</param>
/// <param name="Kerberos">The accepted ticket's caller, for Kerberos callers only.</param>
public sealed record MsaeCaller(string ActingAsUsername, string AuditPrincipal, string AuthMethod, KerberosCaller? Kerberos)
{
    /// <summary>The realm a Kerberos caller came from, for the audit row. Null for credential callers.</summary>
    public string? Realm => Kerberos?.Realm;

    /// <summary>A caller that signed in with a username and password.</summary>
    public static MsaeCaller Credential(string username, string authMethod = "UsernameToken")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        return new(username, $"user:{username}", authMethod, null);
    }

    /// <summary>A caller that presented an accepted Kerberos ticket.</summary>
    public static MsaeCaller FromKerberos(KerberosCaller caller)
        => new(caller.Binding.EnrollmentUsername, $"krb:{caller.FullName}", "Kerberos", caller);
}
