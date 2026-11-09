namespace ModularCA.API.Models;

/// <summary>
/// Connection settings for the application and audit databases. Not referenced anywhere: the
/// configuration in use is <see cref="ModularCA.Shared.Models.Config.DbConfig"/>.
/// </summary>
public class DbConfig
{
    // Updated to reflect sql-app and sql-audit
    /// <summary>The application database.</summary>
    public SqlConfig App { get; set; } = new();
    /// <summary>The audit database.</summary>
    public SqlConfig Audit { get; set; } = new();
}

/// <summary>Connection settings for one PostgreSQL database. Not referenced anywhere outside <see cref="DbConfig"/>.</summary>
public class SqlConfig
{
    /// <summary>Server host name or address.</summary>
    public string Host { get; set; } = "localhost";
    /// <summary>Server port; 5432 by default.</summary>
    public int Port { get; set; } = 5432;
    /// <summary>Login role.</summary>
    public string Username { get; set; } = "postgres";
    /// <summary>Login password.</summary>
    public string Password { get; set; } = "password";
    /// <summary>Database name.</summary>
    public string Database { get; set; } = "modularca";
}

