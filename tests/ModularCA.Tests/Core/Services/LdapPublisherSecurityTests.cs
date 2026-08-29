using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Scheduler;
using System.DirectoryServices.Protocols;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers the LDAP publisher's transport security.
/// <para>
/// <c>LdapConfigurationEntity.UseSsl</c> existed, was persisted, was returned by the admin API and
/// was rendered as a checkbox — and no code path ever applied it. <c>LdapScheduleOptions</c> had no
/// such field, so the value stopped at the entity, and every publisher bind was a cleartext simple
/// bind carrying the directory password. The admin "Test Connection" button called the same helper
/// and so reported success for a connection that was not the one the operator had configured,
/// which made the setting look verified rather than merely ignored.
/// </para>
/// </summary>
public class LdapPublisherTlsTests
{
    private static LdapScheduleOptions Options(bool useSsl) => new()
    {
        LdapHost = "ldap.example.com",
        LdapPort = useSsl ? 636 : 389,
        UseSsl = useSsl,
        Username = "cn=publisher,ou=svc,dc=example,dc=com",
        Password = "bind-secret",
        BaseDn = "dc=example,dc=com",
    };

    // SessionOptions.SecureSocketLayer cannot be asserted by reading it back: on Windows,
    // wldap32 does not reflect LDAP_OPT_SSL until the connection is established, so the getter
    // returns false however the setter was called (ProtocolVersion, below, does reflect). The
    // setting is verified structurally instead — see LdapPublisherOptionWiringTests.

    [Fact]
    public void The_bind_is_ldap_v3()
    {
        // Matches LdapAuthService. Left implicit before, which risks a v2 negotiation against a
        // directory that still offers it — and LDAPv2 has no StartTLS and weaker controls.
        using var connection = LdapPublishHelper.CreateConnection(Options(useSsl: true));
        Assert.Equal(3, connection.SessionOptions.ProtocolVersion);
    }

    [Fact]
    public void An_unencrypted_bind_is_recorded()
    {
        var logger = new CapturingLogger();
        using var connection = LdapPublishHelper.CreateConnection(Options(useSsl: false), logger: logger);

        Assert.Contains(logger.Warnings, w => w.Contains("WITHOUT TLS", StringComparison.Ordinal));
    }

    [Fact]
    public void An_encrypted_bind_is_not_warned_about()
    {
        var logger = new CapturingLogger();
        using var connection = LdapPublishHelper.CreateConnection(Options(useSsl: true), logger: logger);

        Assert.Empty(logger.Warnings);
    }

    [Fact]
    public void The_connect_timeout_is_applied_when_supplied()
    {
        using var connection = LdapPublishHelper.CreateConnection(
            Options(useSsl: true), TimeSpan.FromSeconds(17));
        Assert.Equal(TimeSpan.FromSeconds(17), connection.Timeout);
    }

    private sealed class CapturingLogger : Microsoft.Extensions.Logging.ILogger
    {
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            Microsoft.Extensions.Logging.EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= Microsoft.Extensions.Logging.LogLevel.Warning)
                Warnings.Add(formatter(state, exception));
        }
    }
}

/// <summary>
/// Covers the storage format for the LDAP publisher bind password.
/// <para>
/// The column held it in plaintext. Everything around it was careful — reads return <c>"***"</c>,
/// the audit payload omits it, an update echoing the mask back is treated as "unchanged" — so the
/// credential was guarded everywhere except where it lived. An LDAP publisher bind account is not
/// low-value: publishing into a directory's PKI containers needs write access worth stealing.
/// </para>
/// <para>
/// These tests pin the format contract, which is what every reader and writer agrees on. The
/// Data Protection implementation itself lives in the API project, which this test project
/// deliberately does not reference.
/// </para>
/// </summary>
public class LdapSecretProtectionTests
{
    [Fact]
    public void A_tagged_value_is_recognised_as_protected()
    {
        Assert.True(LdapSecretProtection.IsProtected("dp1:CfDJ8Hq..."));
    }

    [Theory]
    [InlineData("plain-password")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("dp1")]          // the tag needs its colon
    [InlineData("DP1:xyz")]      // ordinal, not case-insensitive
    public void Anything_else_is_not(string? stored)
    {
        Assert.False(LdapSecretProtection.IsProtected(stored));
    }

    [Fact]
    public void A_legacy_plaintext_password_is_flagged_for_upgrade()
    {
        // This is what drives the self-heal in LdapPublisherJob: rows written before protection
        // existed get re-written on the next scheduled publish, without waiting for an operator
        // to open and re-save each publisher by hand.
        Assert.True(LdapSecretProtection.NeedsUpgrade("plain-password"));
    }

    [Fact]
    public void An_already_protected_password_needs_no_upgrade()
    {
        Assert.False(LdapSecretProtection.NeedsUpgrade("dp1:CfDJ8Hq..."));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void An_unset_password_needs_no_upgrade(string? stored)
    {
        // An anonymous-bind publisher has no password. Encrypting the empty string would turn
        // "unset" into a value that decrypts to nothing, and would rewrite the row on every run.
        Assert.False(LdapSecretProtection.NeedsUpgrade(stored));
    }

    /// <summary>
    /// The semantics every <see cref="ILdapSecretProtector"/> must satisfy, exercised against a
    /// stand-in so the contract is pinned independently of the Data Protection implementation.
    /// </summary>
    private sealed class ReversingProtector : ILdapSecretProtector
    {
        public string Protect(string? plaintext)
        {
            if (string.IsNullOrWhiteSpace(plaintext)) return string.Empty;
            if (LdapSecretProtection.IsProtected(plaintext)) return plaintext;
            return LdapSecretProtection.Tag + new string(plaintext.Reverse().ToArray());
        }

        public string Unprotect(string? stored)
        {
            if (string.IsNullOrWhiteSpace(stored)) return string.Empty;
            if (!LdapSecretProtection.IsProtected(stored)) return stored;
            return new string(stored[LdapSecretProtection.Tag.Length..].Reverse().ToArray());
        }
    }

    [Fact]
    public void A_password_survives_a_round_trip()
    {
        var protector = new ReversingProtector();
        Assert.Equal("bind-secret", protector.Unprotect(protector.Protect("bind-secret")));
    }

    [Fact]
    public void A_legacy_plaintext_value_reads_back_unchanged()
    {
        // The upgrade path: a row written before protection existed must keep working rather than
        // failing the publish, so an untagged value is returned as-is.
        Assert.Equal("legacy-password", new ReversingProtector().Unprotect("legacy-password"));
    }

    [Fact]
    public void Protecting_twice_does_not_nest()
    {
        // Update sends the real password only when it differs from the "***" mask, but a caller
        // that hands back an already-stored value must not produce a payload needing two passes.
        var protector = new ReversingProtector();
        var once = protector.Protect("bind-secret");
        Assert.Equal(once, protector.Protect(once));
        Assert.Equal("bind-secret", protector.Unprotect(protector.Protect(once)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void An_unset_password_stays_unset(string? plaintext)
    {
        var protector = new ReversingProtector();
        Assert.Equal(string.Empty, protector.Protect(plaintext));
        Assert.Equal(string.Empty, protector.Unprotect(plaintext));
    }
}

/// <summary>
/// Guards the wiring the original defect lived in: an <see cref="LdapScheduleOptions"/> built
/// without carrying <c>UseSsl</c>.
/// <para>
/// The bug was not a wrong value, it was a missing assignment, repeated at every site that built
/// the options object — the scheduled job's hydration block, the CRL publish hook, and the admin
/// "Test Connection" endpoint. Nothing failed, nothing warned, and the checkbox in the UI kept
/// reporting whatever the operator had chosen. A behavioural test cannot catch that on Windows,
/// because <c>SessionOptions.SecureSocketLayer</c> does not read back before the connection is
/// established, so the assignments are checked structurally instead.
/// </para>
/// <para>
/// This mirrors <c>BootstrapSigningProfileEkuTests</c>, which pins a different
/// wired-through-or-silently-wrong value the same way. It is deliberately narrow: it asserts that
/// a password-carrying options literal also carries the transport setting, which is exactly the
/// invariant that was violated, and it will fail on a fourth call site that forgets it.
/// </para>
/// </summary>
public class LdapPublisherOptionWiringTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string Read(string relativePath)
    {
        var path = Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));
        Assert.True(File.Exists(path), $"expected {path}");
        return File.ReadAllText(path);
    }

    /// <summary>Every production file that builds or hydrates a publisher connection.</summary>
    public static TheoryData<string> OptionBuildingSources() => new()
    {
        "ModularCA.Core/Services/CrlService.cs",
        "ModularCA.API/Controllers/v1/Admin/AdminLdapPublishersController.cs",
    };

    [Theory]
    [MemberData(nameof(OptionBuildingSources))]
    public void An_options_literal_that_carries_a_password_also_carries_the_transport(string relativePath)
    {
        var source = Read(relativePath);

        var literals = System.Text.RegularExpressions.Regex.Matches(
            source,
            @"new\s+LdapScheduleOptions\s*\{(?<body>[^}]*)\}",
            System.Text.RegularExpressions.RegexOptions.Singleline);

        Assert.NotEmpty(literals);

        foreach (System.Text.RegularExpressions.Match literal in literals)
        {
            var body = literal.Groups["body"].Value;

            // A literal with no credential is a sparse one — LdapPublisherJob builds
            // `new LdapScheduleOptions { TaskId = row.Id }` and hydrates it from the row
            // afterwards — so there is nothing to carry yet.
            if (!body.Contains("Password", StringComparison.Ordinal))
                continue;

            Assert.True(
                body.Contains("UseSsl", StringComparison.Ordinal),
                $"An LdapScheduleOptions literal in {relativePath} sets Password but not UseSsl. " +
                "A connection built from it binds in cleartext whatever the publisher is configured for.");
        }
    }

    [Fact]
    public void The_hydration_block_carries_the_transport_alongside_the_password()
    {
        // LdapPublisherJob fills a sparse options object field by field rather than through an
        // initializer, so it needs its own check. This is the site the bug was introduced at.
        var source = Read("ModularCA.Core/Services/SchedulerJobs/LdapPublisherJob.cs");

        Assert.Contains("options.Password =", source, StringComparison.Ordinal);
        Assert.Contains("options.UseSsl =", source, StringComparison.Ordinal);
    }

    [Fact]
    public void The_connection_helper_applies_the_transport_setting()
    {
        // The end of the chain. Everything above only matters if this assignment exists.
        var source = Read("ModularCA.Core/Services/SchedulerJobs/LdapPublishHelper.cs");

        Assert.Matches(
            @"SessionOptions\.SecureSocketLayer\s*=\s*options\.UseSsl\s*;",
            source);
    }

    [Fact]
    public void The_stored_password_is_never_handed_to_a_connection_undecrypted()
    {
        // Each site must pass the bind password through the protector. A direct
        // `Password = cfg.Password` would bind with ciphertext once rows are protected —
        // failing at the directory rather than in review.
        foreach (var relativePath in new[]
                 {
                     "ModularCA.Core/Services/CrlService.cs",
                     "ModularCA.Core/Services/SchedulerJobs/LdapPublisherJob.cs",
                     "ModularCA.API/Controllers/v1/Admin/AdminLdapPublishersController.cs",
                 })
        {
            var source = Read(relativePath);
            Assert.DoesNotMatch(@"Password\s*=\s*(cfg|ldapConfig)\.Password\s*[,;]", source);
            Assert.Contains("Unprotect(", source, StringComparison.Ordinal);
        }
    }
}
