using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Shared;

/// <summary>
/// Pins the one place a PostgreSQL connection string is built.
/// <para>
/// Two things here are worth a test rather than a reading. The TLS mode clamps <em>upwards</em>
/// on anything it does not recognise, so a typo in <c>db.yaml</c> cannot quietly drop transport
/// encryption on a certificate authority's database — the opposite default would be silent and
/// invisible. And the MySQL spellings still parse, because every <c>db.yaml</c> in the field
/// contains one and a database migration should not also be a configuration migration.
/// </para>
/// </summary>
public class PostgresConnectionTests
{
    [Theory]
    [InlineData("Require", SslMode.Require)]
    [InlineData("require", SslMode.Require)]
    [InlineData("Required", SslMode.Require)]        // MySQL spelling, still honoured
    [InlineData("Prefer", SslMode.Prefer)]
    [InlineData("Preferred", SslMode.Prefer)]        // MySQL spelling
    [InlineData("Allow", SslMode.Allow)]
    [InlineData("Disable", SslMode.Disable)]
    [InlineData("None", SslMode.Disable)]            // MySQL spelling
    [InlineData("VerifyCA", SslMode.VerifyCA)]
    [InlineData("VerifyFull", SslMode.VerifyFull)]
    [InlineData("verify-full", SslMode.VerifyFull)]
    public void ParseSslMode_Accepts_Both_Vocabularies(string input, SslMode expected)
    {
        Assert.Equal(expected, PostgresConnection.ParseSslMode(input));
    }

    [Theory]
    [InlineData("Requried")]
    [InlineData("yes")]
    [InlineData("")]
    [InlineData(null)]
    public void ParseSslMode_Clamps_Anything_Unrecognised_Up_To_Require(string? input)
    {
        Assert.Equal(SslMode.Require, PostgresConnection.ParseSslMode(input));
    }

    [Fact]
    public void Build_Escapes_A_Password_Containing_A_Semicolon()
    {
        // The reason this goes through a builder rather than string concatenation: a semicolon
        // in a password truncates a hand-built connection string and produces an authentication
        // failure with no visible cause.
        var connStr = PostgresConnection.Build("localhost", 5432, "modularca-app", "modularca_app", "a;b=c'd");
        var parsed = new NpgsqlConnectionStringBuilder(connStr);
        Assert.Equal("a;b=c'd", parsed.Password);
        Assert.Equal("modularca-app", parsed.Database);
    }

    [Fact]
    public void Build_Falls_Back_To_The_Default_Port_When_Unset()
    {
        var parsed = new NpgsqlConnectionStringBuilder(
            PostgresConnection.Build("localhost", 0, "db", "u", "p"));
        Assert.Equal(PostgresConnection.DefaultPort, parsed.Port);
    }

    [Fact]
    public void BuildMaintenance_Targets_The_Maintenance_Database()
    {
        // CREATE DATABASE and DROP DATABASE cannot run from a session attached to the database
        // they name, so every administrative path has to land here rather than on the app DB.
        var parsed = new NpgsqlConnectionStringBuilder(
            PostgresConnection.BuildMaintenance("localhost", 5432, "postgres", "p"));
        Assert.Equal(PostgresConnection.MaintenanceDatabase, parsed.Database);
    }

    [Fact]
    public void Build_From_DbInstance_Carries_Every_Field()
    {
        var instance = new DbInstance
        {
            Host = "db.example.com",
            Port = 6432,
            Database = "modularca-audit",
            Username = "modularca_audit",
            Password = "s3cret",
            SslMode = "VerifyFull",
        };
        var parsed = new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance));
        Assert.Equal("db.example.com", parsed.Host);
        Assert.Equal(6432, parsed.Port);
        Assert.Equal("modularca-audit", parsed.Database);
        Assert.Equal("modularca_audit", parsed.Username);
        Assert.Equal("s3cret", parsed.Password);
        Assert.Equal(SslMode.VerifyFull, parsed.SslMode);
    }

    [Theory]
    [InlineData("modularca-app", "\"modularca-app\"")]
    [InlineData("we\"ird", "\"we\"\"ird\"")]
    public void QuoteIdentifier_Doubles_Embedded_Quotes(string input, string expected)
    {
        // The application database is called modularca-app and contains a hyphen, so it can
        // only ever appear in DDL quoted — PostgreSQL would otherwise read the hyphen as an
        // operator and fold the name to lower case besides.
        Assert.Equal(expected, PostgresConnection.QuoteIdentifier(input));
    }

    [Fact]
    public void QuoteLiteral_Doubles_Embedded_Apostrophes()
    {
        // CREATE ROLE ... PASSWORD will not take a bound parameter, so the generated password
        // is interpolated, and PasswordUtil.Generate can emit an apostrophe.
        Assert.Equal("'it''s'", PostgresConnection.QuoteLiteral("it's"));
    }
}
