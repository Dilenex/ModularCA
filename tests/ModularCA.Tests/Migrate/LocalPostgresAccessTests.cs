using ModularCA.Migrate;
using ModularCA.Tests.Database;
using Npgsql;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// Bug hunt 2026-11, X3: the migrate tool created its temporary administrative role with the
/// plaintext password in <c>psql -c</c>'s arguments, readable by any local user from
/// <c>/proc/&lt;pid&gt;/cmdline</c> while it ran, and logged by a server that logs DDL. The role
/// is a member of the application and audit roles for the run. The statement now goes to psql on
/// standard input, and carries a SCRAM verifier instead of the password.
/// </summary>
public sealed class LocalPostgresAccessTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    [Fact]
    public void Psql_is_given_no_statement_on_its_command_line()
    {
        Assert.DoesNotContain(LocalPostgresAccess.PsqlArguments, a => a.StartsWith("-c", StringComparison.Ordinal) || a.Contains("-tAc", StringComparison.Ordinal));
        Assert.DoesNotContain(LocalPostgresAccess.PsqlArguments, a => a.Contains(' '));
        Assert.Contains("ON_ERROR_STOP=1", LocalPostgresAccess.PsqlArguments);
    }

    [Fact]
    public void The_verifier_has_postgresqls_shape_and_no_plaintext()
    {
        var verifier = LocalPostgresAccess.ScramSha256Verifier("s3cret-Pa55", new byte[16]);

        Assert.Matches(@"^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}$", verifier);
        Assert.DoesNotContain("s3cret", verifier);
        Assert.DoesNotContain("'", verifier);
        Assert.NotEqual(verifier, LocalPostgresAccess.ScramSha256Verifier("s3cret-Pa55"));
    }

    /// <summary>A role created with the verifier signs in with the password, so the verifier is the one PostgreSQL computes.</summary>
    [RequiresEnvironmentFact(ServerVariable)]
    [Trait("Category", "PostgreSQL")]
    [Trait(TestTier.Name, TestTier.Slow)]
    public async Task A_role_created_with_the_verifier_signs_in_with_the_password()
    {
        var admin = Environment.GetEnvironmentVariable(ServerVariable)!;
        var role = $"mca_scram_{Guid.NewGuid():N}"[..30];
        const string password = "Xq7_verifier-test-password";

        await using (var conn = new NpgsqlConnection(admin))
        {
            await conn.OpenAsync();
            await using var create = new NpgsqlCommand(
                $"CREATE ROLE {role} WITH LOGIN PASSWORD '{LocalPostgresAccess.ScramSha256Verifier(password)}'", conn);
            await create.ExecuteNonQueryAsync();
        }
        try
        {
            var asRole = new NpgsqlConnectionStringBuilder(admin) { Username = role, Password = password, Database = "postgres", Pooling = false };
            await using var login = new NpgsqlConnection(asRole.ConnectionString);
            await login.OpenAsync();
            await using var who = new NpgsqlCommand("SELECT current_user", login);
            Assert.Equal(role, (string?)await who.ExecuteScalarAsync());
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await using var conn = new NpgsqlConnection(admin);
            await conn.OpenAsync();
            await using var drop = new NpgsqlCommand($"DROP ROLE IF EXISTS {role}", conn);
            await drop.ExecuteNonQueryAsync();
        }
    }
}
