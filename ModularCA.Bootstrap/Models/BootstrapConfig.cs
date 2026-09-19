namespace ModularCA.Bootstrap.Models;

public class BootstrapConfig
{
    public CaConfig Ca { get; set; } = new();
    public SigningProfileConfig SigningProfile { get; set; } = new();

    // Updated to reflect sql-app and sql-audit
    public SqlConfig SqlApp { get; set; } = new();
    public SqlConfig SqlAudit { get; set; } = new();
}

public class CaConfig
{
    public CaSubjectConfig Subject { get; set; } = new();
    public string Algorithm { get; set; } = "RSA";
    public int KeySize { get; set; } = 4096;
    public int ValidityYears { get; set; } = 10;
}

public class CaSubjectConfig
{
    public string? CN { get; set; }
    public string? O { get; set; }
    public string? OU { get; set; }
    public List<string>? DC { get; set; }
    public string? L { get; set; }
    public string? ST { get; set; }
    public string? C { get; set; }
}

public class SigningProfileConfig
{
    public string Name { get; set; } = "default";
    public bool IsCa { get; set; } = true;
    public List<string> KeyUsages { get; set; } = new();
    public List<string> ExtendedKeyUsages { get; set; } = new();
}

public class SqlConfig
{
    public string Host { get; set; } = "localhost";
    public int Port { get; set; } = 5432;
    public string Username { get; set; } = "root";
    public string Password { get; set; } = "password";
    public string Database { get; set; } = "modularca";
}

