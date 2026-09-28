using System.Net.Sockets;
using System.Security.Authentication;
using ModularCA.Database;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// How <see cref="SchemaFailure"/> sorts the errors a schema read or a migration raises, which
/// exit code each leads to, and how each is described to the operator.
/// </summary>
public class SchemaFailureClassificationTests
{
    private static PostgresException Pg(string sqlState, string message = "server said no") =>
        new(message, "ERROR", "ERROR", sqlState);

    public static TheoryData<Exception, SchemaFailureKind> Cases() => new()
    {
        { Pg("55P03"), SchemaFailureKind.MigrationInProgress },
        { Pg("57014"), SchemaFailureKind.MigrationInProgress },
        { Pg("40P01"), SchemaFailureKind.MigrationInProgress },
        { Pg("40001"), SchemaFailureKind.MigrationInProgress },
        { new NpgsqlException("Exception while reading from stream", new TimeoutException()), SchemaFailureKind.MigrationInProgress },
        { Pg("28P01"), SchemaFailureKind.Misconfigured },
        { Pg("28000"), SchemaFailureKind.Misconfigured },
        { Pg("42501"), SchemaFailureKind.Misconfigured },
        { new SchemaAccessException("modularca-app", "modularca_app", "\"public\".\"__EFMigrationsHistory\""), SchemaFailureKind.Misconfigured },
        { new NpgsqlException("TLS", new AuthenticationException("remote certificate rejected")), SchemaFailureKind.Misconfigured },
        { new InvalidOperationException("anything else"), SchemaFailureKind.Misconfigured },
        { Pg("42P01"), SchemaFailureKind.Misconfigured },
        { Pg("3D000"), SchemaFailureKind.Missing },
        { new SchemaConnectException(Pg("3D000")), SchemaFailureKind.Missing },
        { new NpgsqlException("connect", new SocketException((int)SocketError.ConnectionRefused)), SchemaFailureKind.Unreachable },
        { new SocketException((int)SocketError.HostNotFound), SchemaFailureKind.Unreachable },
        { new NpgsqlException("read", new IOException("connection reset")), SchemaFailureKind.Unreachable },
        { Pg("57P03"), SchemaFailureKind.Unreachable },
        { Pg("53300"), SchemaFailureKind.Unreachable },
        { Pg("57P01"), SchemaFailureKind.Unreachable },
        { Pg("08006"), SchemaFailureKind.Unreachable },
        { new SchemaConnectException(new NpgsqlException("connect", new TimeoutException())), SchemaFailureKind.Unreachable },
        { new SchemaConnectException(Pg("28P01")), SchemaFailureKind.Misconfigured },
        { new InvalidOperationException("outer", Pg("42501")), SchemaFailureKind.Misconfigured },
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public void Each_error_has_one_kind(Exception error, SchemaFailureKind expected)
    {
        Assert.Equal(expected, SchemaFailure.Classify(error));
    }

    [Theory]
    [InlineData("55P03", true)]
    [InlineData("40P01", true)]
    [InlineData("40001", true)]
    [InlineData("57P03", true)]
    [InlineData("57014", false)]
    [InlineData("42501", false)]
    [InlineData("42P07", false)]
    [InlineData("P0001", false)]
    public void A_failed_migration_exits_75_only_when_a_retry_can_pass(string sqlState, bool retried)
    {
        var exit = SchemaFailure.TransientForMigration(Pg(sqlState)) ? SchemaStartupApi.TempFailExitCode : SchemaStartupApi.ExitCode;
        Assert.Equal(retried ? 75 : 3, exit);
    }

    [Fact]
    public void A_statement_that_ran_past_its_client_timeout_is_not_retried()
    {
        var timeout = new NpgsqlException("Exception while reading from stream", new TimeoutException());
        Assert.True(SchemaFailure.IsStatementTimeout(timeout));
        Assert.False(SchemaFailure.TransientForMigration(timeout));
        Assert.True(SchemaFailure.TransientForMigration(new NpgsqlException("lost", new IOException("reset"))));
    }

    [Fact]
    public void A_connect_timeout_while_migrating_is_retried_and_never_taken_for_a_statement_timeout()
    {
        var connectTimeout = new SchemaConnectException(new NpgsqlException("Exception while connecting", new TimeoutException("The operation has timed out")));
        var wrapped = new InvalidOperationException("history re-read", connectTimeout);

        foreach (var error in new Exception[] { connectTimeout, wrapped })
        {
            Assert.Equal(SchemaFailureKind.Unreachable, SchemaFailure.Classify(error));
            Assert.False(SchemaFailure.IsStatementTimeout(error));
            Assert.True(SchemaFailure.TransientForMigration(error));
            var text = SchemaFailure.Describe(error, 3630);
            Assert.Contains("connect timeout", text);
            Assert.DoesNotContain("command timeout", text);
        }

        Assert.False(SchemaFailure.TransientForMigration(new SchemaConnectException(Pg("28P01"))));
        Assert.True(SchemaFailure.TransientForMigration(new SchemaConnectException(Pg("57P03"))));
        Assert.True(SchemaFailure.TransientForMigration(new SchemaConnectException(new NpgsqlException("connect", new SocketException((int)SocketError.ConnectionRefused)))));
    }

    [Fact]
    public void The_exit_codes_are_3_for_the_operator_and_75_for_a_retry()
    {
        Assert.Equal(3, SchemaStartupApi.ExitCode);
        Assert.Equal(75, SchemaStartupApi.TempFailExitCode);
    }

    [Theory]
    [InlineData("55P03", "lock timeout")]
    [InlineData("40P01", "deadlock")]
    [InlineData("42501", "insufficient privilege")]
    [InlineData("28P01", "password authentication failed")]
    [InlineData("3D000", "database does not exist")]
    public void A_server_error_is_described_by_its_sqlstate(string sqlState, string meaning)
    {
        var text = SchemaFailure.Describe(new InvalidOperationException("wrapped", Pg(sqlState, "the server message")));
        Assert.Contains(sqlState, text);
        Assert.Contains(meaning, text);
        Assert.Contains("the server message", text);
    }

    [Fact]
    public void A_statement_timeout_names_the_limit()
    {
        Assert.Contains("statement timeout (3600 s)", SchemaFailure.Describe(Pg("57014"), 3600));
    }

    [Fact]
    public void A_client_timeout_is_described_as_a_command_timeout_with_its_limit()
    {
        var error = new NpgsqlException("Exception while reading from stream", new TimeoutException("Timeout during reading attempt"));
        var text = SchemaFailure.Describe(error, 45);
        Assert.Contains("command timeout (45 s)", text);
        Assert.Contains("Timeout during reading attempt", text);
    }

    [Fact]
    public void A_tls_failure_is_recognised_anywhere_in_the_chain()
    {
        Assert.True(SchemaFailure.IsTlsFailure(new NpgsqlException("x", new IOException("y", new AuthenticationException("z")))));
        Assert.False(SchemaFailure.IsTlsFailure(Pg("28P01")));
    }
}
