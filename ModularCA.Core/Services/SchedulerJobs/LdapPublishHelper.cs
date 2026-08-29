using Microsoft.Extensions.Logging;
using ModularCA.Shared.Models.Scheduler;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Shared helper for publishing certificates and CRLs to an LDAP directory.
/// Used by both the scheduled <see cref="LdapPublisherJob"/> and the
/// post-issuance / post-CRL hooks in the core services.
/// </summary>
public static class LdapPublishHelper
{
    /// <summary>
    /// Creates and authenticates an <see cref="LdapConnection"/> using the host, port, TLS
    /// setting and credentials from the supplied <paramref name="options"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="LdapScheduleOptions.UseSsl"/> is honoured here. It previously was not — the
    /// setting existed on the entity, was persisted, was returned by the admin API and was
    /// rendered as a checkbox, but no code path ever applied it, so every publisher bind was a
    /// cleartext simple bind sending the directory password over the network. The admin "Test
    /// Connection" button shared this method and so reported success for a connection that was
    /// not the one the operator had configured.
    /// </para>
    /// <para>
    /// This is LDAPS (TLS from the first byte, conventionally port 636), matching what
    /// <c>LdapAuthService</c> does. StartTLS on port 389 is a different handshake and is not
    /// offered, so a publisher pointed at 389 with this enabled will fail to connect rather than
    /// quietly downgrade.
    /// </para>
    /// <para>
    /// The server certificate is validated against the host's trust store. On Linux that is
    /// OpenLDAP's configuration (<c>TLS_CACERT</c> in <c>ldap.conf</c>), not the .NET trust
    /// store — worth knowing when the directory presents a certificate from a private CA.
    /// </para>
    /// </remarks>
    /// <param name="options">LDAP connection options.</param>
    /// <param name="timeout">Caps blocking time on an unresponsive directory server.</param>
    /// <param name="logger">Optional logger, used to record an unencrypted bind.</param>
    /// <returns>A bound <see cref="LdapConnection"/> ready for requests.</returns>
    public static LdapConnection Connect(LdapScheduleOptions options, TimeSpan? timeout = null, ILogger? logger = null)
    {
        var connection = CreateConnection(options, timeout, logger);
        connection.Bind();
        return connection;
    }

    /// <summary>
    /// Builds and configures the connection without binding it. Split out from
    /// <see cref="Connect"/> so the transport settings — the part that was silently wrong — can be
    /// asserted in a test without a directory server to bind to.
    /// </summary>
    internal static LdapConnection CreateConnection(
        LdapScheduleOptions options, TimeSpan? timeout = null, ILogger? logger = null)
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(options.LdapHost, options.LdapPort));
        connection.AuthType = AuthType.Basic;
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = options.UseSsl;
        connection.Credential = new NetworkCredential(options.Username, options.Password);
        // Cap blocking time on an unresponsive directory server.
        if (timeout.HasValue && timeout.Value > TimeSpan.Zero)
            connection.Timeout = timeout.Value;

        if (!options.UseSsl)
        {
            // Not refused, because a publisher against a directory on a trusted segment is a
            // legitimate configuration and refusing would break running deployments on upgrade.
            // It is recorded every time, because a simple bind puts the credential on the wire in
            // the clear and most directories — Active Directory among them — reject it outright
            // once LDAP signing and channel binding are enforced.
            logger?.LogWarning(
                "LDAP publisher binding to {Host}:{Port} WITHOUT TLS — the bind password is sent in cleartext. " +
                "Enable 'Use SSL' on this publisher and point it at the directory's LDAPS port.",
                options.LdapHost, options.LdapPort);
        }

        return connection;
    }

    /// <summary>
    /// Publishes a single end-entity certificate to the LDAP
    /// <c>userCertificate;binary</c> attribute of the entry whose DN is
    /// derived from the certificate subject.
    /// </summary>
    /// <param name="connection">An already-bound LDAP connection.</param>
    /// <param name="options">LDAP schedule options containing the DN template and base DN.</param>
    /// <param name="certDer">DER-encoded certificate bytes.</param>
    /// <param name="subjectDn">The X.500 subject DN of the certificate.</param>
    /// <param name="logger">Logger for diagnostics.</param>
    public static void PublishUserCertificate(
        LdapConnection connection,
        LdapScheduleOptions options,
        byte[] certDer,
        string subjectDn,
        ILogger logger)
    {
        var targetDn = DeriveUserDn(options, subjectDn);
        if (string.IsNullOrWhiteSpace(targetDn))
        {
            logger.LogWarning("Could not derive LDAP target DN for subject {Subject}; skipping user cert publish", subjectDn);
            return;
        }

        var request = new ModifyRequest(targetDn, DirectoryAttributeOperation.Replace, "userCertificate;binary", certDer);
        connection.SendRequest(request);
        logger.LogInformation("Published user certificate to LDAP entry {TargetDn}", targetDn);
    }

    /// <summary>
    /// Publishes a CRL to the LDAP <c>certificateRevocationList</c> attribute
    /// at the configured base DN.
    /// </summary>
    /// <param name="connection">An already-bound LDAP connection.</param>
    /// <param name="options">LDAP schedule options.</param>
    /// <param name="crlDer">DER-encoded CRL bytes.</param>
    /// <param name="logger">Logger for diagnostics.</param>
    public static void PublishCrl(
        LdapConnection connection,
        LdapScheduleOptions options,
        byte[] crlDer,
        ILogger logger)
    {
        var request = new ModifyRequest(options.BaseDn, DirectoryAttributeOperation.Replace, "certificateRevocationList", crlDer);
        connection.SendRequest(request);
        logger.LogInformation("Published CRL to LDAP under {BaseDn}", options.BaseDn);
    }

    /// <summary>
    /// Derives the LDAP distinguished name for a user entry from the certificate
    /// subject DN, using the configured <see cref="LdapScheduleOptions.UserDnTemplate"/>
    /// or a default pattern of <c>cn={cn},{BaseDn}</c>.
    /// </summary>
    /// <param name="options">LDAP options containing the template and base DN.</param>
    /// <param name="subjectDn">The X.500 subject DN string (e.g. "CN=John, E=john@example.com").</param>
    /// <returns>The resolved LDAP DN, or <c>null</c> if no CN or email could be extracted.</returns>
    internal static string? DeriveUserDn(LdapScheduleOptions options, string subjectDn)
    {
        var cn = ExtractRdnValue(subjectDn, "CN");
        var email = ExtractRdnValue(subjectDn, "E")
                 ?? ExtractRdnValue(subjectDn, "EMAILADDRESS")
                 ?? ExtractRdnValue(subjectDn, "1.2.840.113549.1.9.1");

        // IV-05: Escape user-provided DN values per RFC 4514 to prevent LDAP injection.
        var escapedCn = cn != null ? EscapeLdapDnValue(cn) : null;
        var escapedEmail = email != null ? EscapeLdapDnValue(email) : null;

        if (!string.IsNullOrWhiteSpace(options.UserDnTemplate))
        {
            var dn = options.UserDnTemplate
                .Replace("{cn}", escapedCn ?? "", StringComparison.OrdinalIgnoreCase)
                .Replace("{email}", escapedEmail ?? "", StringComparison.OrdinalIgnoreCase);
            return dn;
        }

        // Fallback: cn={cn},{BaseDn}
        if (!string.IsNullOrWhiteSpace(escapedCn))
            return $"cn={escapedCn},{options.BaseDn}";

        if (!string.IsNullOrWhiteSpace(escapedEmail))
            return $"cn={escapedEmail},{options.BaseDn}";

        return null;
    }

    /// <summary>
    /// Escapes special characters in a DN attribute value per RFC 4514 §2.4 to
    /// prevent LDAP injection attacks. Handles: leading/trailing spaces, leading #,
    /// and the special characters <c>, + " \ &lt; &gt; ;</c> plus null characters.
    /// </summary>
    /// <param name="value">The raw attribute value to escape.</param>
    /// <returns>The escaped value safe for use in an LDAP distinguished name.</returns>
    internal static string EscapeLdapDnValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        var sb = new System.Text.StringBuilder(value.Length + 8);

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            // Null character — always escape
            if (c == '\0')
            {
                sb.Append("\\00");
                continue;
            }

            // Leading space or # must be escaped
            if (i == 0 && (c == ' ' || c == '#'))
            {
                sb.Append('\\');
                sb.Append(c);
                continue;
            }

            // Trailing space must be escaped
            if (i == value.Length - 1 && c == ' ')
            {
                sb.Append('\\');
                sb.Append(c);
                continue;
            }

            // RFC 4514 special characters that must always be escaped
            if (c is ',' or '+' or '"' or '\\' or '<' or '>' or ';')
            {
                sb.Append('\\');
                sb.Append(c);
                continue;
            }

            sb.Append(c);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Extracts the value of a specific RDN component from an X.500 distinguished name string.
    /// </summary>
    private static string? ExtractRdnValue(string dn, string rdnType)
    {
        if (string.IsNullOrWhiteSpace(dn))
            return null;

        // Split on comma but respect escaped commas
        var parts = dn.Split(',');
        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            var eqIdx = trimmed.IndexOf('=');
            if (eqIdx <= 0) continue;

            var key = trimmed[..eqIdx].Trim();
            if (key.Equals(rdnType, StringComparison.OrdinalIgnoreCase))
                return trimmed[(eqIdx + 1)..].Trim();
        }
        return null;
    }
}
