namespace ModularCA.API.Models;

public class DbConfig
{
    // Updated to reflect sql-app and sql-audit
    public SqlConfig App { get; set; } = new();
    public SqlConfig Audit { get; set; } = new();
}

public class SqlConfig
{
    public string Host { get; set; } = "localhost";
    public int Port { get; set; } = 5432;
    public string Username { get; set; } = "root";
    public string Password { get; set; } = "password";
    public string Database { get; set; } = "modularca";
}

