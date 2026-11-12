using Microsoft.Extensions.Logging;
using ModularCA.Shared.Models.Config;
using System.DirectoryServices.Protocols;
using System.Net;

namespace ModularCA.Auth.Services;

/// <summary>
/// What the directory said about a sign-in bind. Callers decide from this whether the local
/// password hash may be consulted: see <see cref="PasswordCredentialCheck"/>.
/// </summary>
public enum LdapBindOutcome
{
    /// <summary>The directory accepted the user's credentials.</summary>
    Succeeded,

    /// <summary>
    /// The directory answered and refused the bind: wrong password, or an account the directory has
    /// disabled, expired or locked. The directory is authoritative for this user.
    /// </summary>
    Refused,

    /// <summary>
    /// The service-account search answered that the directory has no entry for this user, so the
    /// account can only be a local one. Only reported when a service account is configured; a
    /// direct bind cannot tell an unknown user from a wrong password and reports
    /// <see cref="Refused"/>.
    /// </summary>
    UserNotFound,

    /// <summary>
    /// No answer about the user: the server could not be reached, the service-account bind or
    /// search failed, LDAP sign-in is turned off, or the directory returned an unexpected error.
    /// </summary>
    Unavailable,
}

/// <summary>
/// Authenticates users against an LDAP/Active Directory server and retrieves their group memberships
/// for synchronization with the CA-scoped group model.
/// </summary>
public interface ILdapAuthService
{
    /// <summary>
    /// Binds as the user against the configured LDAP server and reports what the directory said.
    /// </summary>
    /// <param name="username">The sign-in name, matched by the configured search filter.</param>
    /// <param name="password">The password to bind with.</param>
    /// <returns>The bind outcome; see <see cref="LdapBindOutcome"/>.</returns>
    Task<LdapBindOutcome> AuthenticateAsync(string username, string password);

    /// <summary>
    /// Retrieves the LDAP group DNs for the specified user: an empty list when the user belongs to
    /// no groups, <c>null</c> when the lookup could not be answered (disabled, failure, user not found).
    /// </summary>
    Task<List<string>?> GetUserGroupsAsync(string username);
}

/// <summary>
/// LDAP authentication and group query implementation using System.DirectoryServices.Protocols.
/// Supports service-account-based user search and direct-bind authentication.
/// </summary>
public class LdapAuthService : ILdapAuthService, ModularCA.Core.Services.ILdapGroupProvider
{
    private readonly SystemConfig _config;
    private readonly ILogger<LdapAuthService> _logger;

    public LdapAuthService(SystemConfig config, ILogger<LdapAuthService> logger)
    {
        _config = config;
        _logger = logger;
    }

    /// <summary>
    /// Binds as the user and classifies the result. With a service account configured, the user's
    /// DN is found first: no entry is <see cref="LdapBindOutcome.UserNotFound"/>, and a failure of
    /// the service-account bind or search is <see cref="LdapBindOutcome.Unavailable"/>, never
    /// <see cref="LdapBindOutcome.Refused"/>, because it says nothing about the user's password.
    /// Without a service account the username is bound directly, and invalid credentials are
    /// <see cref="LdapBindOutcome.Refused"/>.
    /// </summary>
    /// <param name="username">The sign-in name, matched by the configured search filter.</param>
    /// <param name="password">The password to bind with.</param>
    /// <returns>The bind outcome.</returns>
    /// <exception cref="InvalidOperationException">RequireTls is on but UseSsl is off.</exception>
    public Task<LdapBindOutcome> AuthenticateAsync(string username, string password)
    {
        var ldapConfig = _config.LdapAuth;
        if (!ldapConfig.Enabled)
            return Task.FromResult(LdapBindOutcome.Unavailable);

        // AUTH-019: hard-fail when RequireTls is on but SSL is not configured
        if (ldapConfig.RequireTls && !ldapConfig.UseSsl)
            throw new InvalidOperationException("LDAP RequireTls is enabled but UseSsl is false. Enable SSL or disable RequireTls.");

        LdapDirectoryIdentifier identifier;
        string userDn;
        try
        {
            identifier = new LdapDirectoryIdentifier(ldapConfig.Host, ldapConfig.Port);

            // Step 1: Bind with service account to search for the user DN
            if (!string.IsNullOrWhiteSpace(ldapConfig.BindDn))
            {
                using var searchConn = new LdapConnection(identifier);
                searchConn.AuthType = AuthType.Basic;
                searchConn.SessionOptions.ProtocolVersion = 3;
                if (ldapConfig.UseSsl) searchConn.SessionOptions.SecureSocketLayer = true;
                searchConn.Credential = new NetworkCredential(ldapConfig.BindDn, ldapConfig.BindPassword);
                searchConn.Bind();

                var filter = ldapConfig.SearchFilter.Replace("{0}", EscapeLdapFilter(username));
                var searchRequest = new SearchRequest(ldapConfig.SearchBaseDn, filter, SearchScope.Subtree, "distinguishedName");
                var searchResponse = (SearchResponse)searchConn.SendRequest(searchRequest);

                if (searchResponse.Entries.Count == 0)
                {
                    _logger.LogDebug("LDAP authentication: user {Username} has no directory entry", username);
                    return Task.FromResult(LdapBindOutcome.UserNotFound);
                }

                userDn = searchResponse.Entries[0].DistinguishedName;
            }
            else
            {
                // No service account — attempt direct bind with username
                userDn = username;
            }
        }
        catch (Exception ex)
        {
            // The service-account bind or the user search failed. An invalid-credentials error here
            // belongs to the service account, not the user, so it must not read as a refused bind.
            Serilog.Log.Error(ex, "LDAP user lookup failed for user {Username}", username);
            return Task.FromResult(LdapBindOutcome.Unavailable);
        }

        try
        {
            // Step 2: Bind with the user's credentials to verify password
            using var authConn = new LdapConnection(identifier);
            authConn.AuthType = AuthType.Basic;
            authConn.SessionOptions.ProtocolVersion = 3;
            if (ldapConfig.UseSsl) authConn.SessionOptions.SecureSocketLayer = true;
            authConn.Credential = new NetworkCredential(userDn, password);
            authConn.Bind();

            _logger.LogInformation("LDAP authentication succeeded for user {Username} (DN: {UserDn})", username, userDn);
            return Task.FromResult(LdapBindOutcome.Succeeded);
        }
        catch (LdapException ex) when (ex.ErrorCode == 49)
        {
            _logger.LogDebug("LDAP authentication failed for user {Username}: invalid credentials", username);
            return Task.FromResult(LdapBindOutcome.Refused);
        }
        catch (Exception ex)
        {
            // Do NOT surface ex.Message to callers — it can leak DNs, server paths,
            // and driver version info. Log the full exception server-side for operators.
            Serilog.Log.Error(ex, "LDAP bind failed for user {Username}", username);
            return Task.FromResult(LdapBindOutcome.Unavailable);
        }
    }

    /// <summary>
    /// Queries the directory for the user's group DNs. Returns <c>null</c> (not an empty list) when
    /// LDAP or group sync is disabled, the user is not found, or the query fails, so callers can tell
    /// "unknown" apart from "no groups" and leave memberships untouched.
    /// </summary>
    public Task<List<string>?> GetUserGroupsAsync(string username)
    {
        var ldapConfig = _config.LdapAuth;
        if (!ldapConfig.Enabled || !ldapConfig.GroupSyncEnabled)
            return Task.FromResult<List<string>?>(null);

        // AUTH-019: hard-fail when RequireTls is on but SSL is not configured
        if (ldapConfig.RequireTls && !ldapConfig.UseSsl)
            throw new InvalidOperationException("LDAP RequireTls is enabled but UseSsl is false. Enable SSL or disable RequireTls.");

        try
        {
            var identifier = new LdapDirectoryIdentifier(ldapConfig.Host, ldapConfig.Port);
            using var conn = new LdapConnection(identifier);
            conn.AuthType = AuthType.Basic;
            conn.SessionOptions.ProtocolVersion = 3;
            if (ldapConfig.UseSsl) conn.SessionOptions.SecureSocketLayer = true;

            if (!string.IsNullOrWhiteSpace(ldapConfig.BindDn))
                conn.Credential = new NetworkCredential(ldapConfig.BindDn, ldapConfig.BindPassword);
            conn.Bind();

            // First find the user DN
            var userFilter = ldapConfig.SearchFilter.Replace("{0}", EscapeLdapFilter(username));
            var userSearch = new SearchRequest(ldapConfig.SearchBaseDn, userFilter, SearchScope.Subtree, "distinguishedName");
            var userResponse = (SearchResponse)conn.SendRequest(userSearch);
            if (userResponse.Entries.Count == 0)
                return Task.FromResult<List<string>?>(null);

            var userDn = userResponse.Entries[0].DistinguishedName;

            // Query groups the user belongs to
            var groupBaseDn = string.IsNullOrWhiteSpace(ldapConfig.GroupSearchBaseDn)
                ? ldapConfig.SearchBaseDn
                : ldapConfig.GroupSearchBaseDn;

            var groupFilter = ldapConfig.GroupSearchFilter.Replace("{0}", EscapeLdapFilter(userDn));
            var groupSearch = new SearchRequest(groupBaseDn, groupFilter, SearchScope.Subtree, "distinguishedName");
            var groupResponse = (SearchResponse)conn.SendRequest(groupSearch);

            var groups = new List<string>();
            foreach (SearchResultEntry entry in groupResponse.Entries)
            {
                groups.Add(entry.DistinguishedName);
            }

            _logger.LogDebug("LDAP groups for {Username}: {Groups}", username, string.Join(", ", groups));
            return Task.FromResult<List<string>?>(groups);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LDAP group query failed for user {Username}", username);
            return Task.FromResult<List<string>?>(null);
        }
    }

    private static string EscapeLdapFilter(string input)
    {
        return input
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }
}
