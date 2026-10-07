using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// Tests for <see cref="PostgresErrorUtil.IsUniqueViolation"/>. The helper backs the
/// <c>catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))</c> filter
/// in <c>CertExpiryNotificationJob</c> and <c>CmpService.PersistOrCheckTransactionAsync</c>.
/// A bug here would either swallow non-uniqueness errors as "already exists" (data loss) or
/// fail to recognize legitimate uniqueness collisions (false-positive failures).
/// <para>
/// Replaces <c>MySqlErrorUtilTests</c>, which asserted on MySQL error number 1062. The
/// assertions are the same shape against SQLSTATE 23505, and the test helper that reflected
/// into <c>MySqlException</c> to set a private field is gone: Npgsql gives
/// <see cref="PostgresException"/> a public constructor that takes the SQLSTATE, so the
/// exception under test is now constructed the way the driver constructs it.
/// </para>
/// </summary>
public class PostgresErrorUtilTests
{
    /// <summary>Builds a <see cref="PostgresException"/> carrying the given SQLSTATE.</summary>
    private static PostgresException Pg(string sqlState) =>
        new("duplicate key value violates unique constraint", "ERROR", "ERROR", sqlState);

    [Fact]
    public void Probe_Factory_Produces_PostgresException_With_Correct_SqlState()
    {
        // Verifies the construction helper itself before we trust IsUniqueViolation downstream.
        var ex = Pg("23505");
        Assert.Equal("23505", ex.SqlState);
    }

    [Fact]
    public void Returns_True_When_Inner_Is_PostgresException_With_SqlState_23505()
    {
        var dbEx = new DbUpdateException("dup", Pg("23505"));

        Assert.True(PostgresErrorUtil.IsUniqueViolation(dbEx));
    }

    [Fact]
    public void Returns_False_When_Inner_Is_PostgresException_With_Different_SqlState()
    {
        // 40P01 = deadlock_detected; legitimate transient failure that should NOT be silently
        // swallowed as a uniqueness collision.
        var dbEx = new DbUpdateException("deadlock", Pg("40P01"));

        Assert.False(PostgresErrorUtil.IsUniqueViolation(dbEx));
    }

    [Fact]
    public void Returns_False_When_Inner_Is_Foreign_Key_Violation()
    {
        // 23503 = foreign_key_violation. Same SQLSTATE class as 23505 and therefore the most
        // plausible thing to match by accident if the check were ever loosened to a prefix.
        var dbEx = new DbUpdateException("fk", Pg("23503"));

        Assert.False(PostgresErrorUtil.IsUniqueViolation(dbEx));
    }

    [Fact]
    public void Returns_False_When_Chain_Has_No_PostgresException()
    {
        var inner = new InvalidOperationException("not a PostgreSQL error");
        var dbEx = new DbUpdateException("unrelated", inner);

        Assert.False(PostgresErrorUtil.IsUniqueViolation(dbEx));
    }

    [Fact]
    public void Walks_Inner_Chain_To_Find_PostgresException()
    {
        // Some EF code paths wrap the provider exception one or two levels deep. The helper
        // must traverse the chain rather than only checking the immediate InnerException.
        var middle = new InvalidOperationException("wrapper", Pg("23505"));
        var dbEx = new DbUpdateException("update failed", middle);

        Assert.True(PostgresErrorUtil.IsUniqueViolation(dbEx));
    }
}
