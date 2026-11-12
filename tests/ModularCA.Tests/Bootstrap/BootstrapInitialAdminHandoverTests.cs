using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// xUnit collection for tests that redirect <see cref="Console.Out"/>, a process-wide static. Not
/// run in parallel with anything, so no other test's output lands in the capture, and the capture
/// never swallows another test's.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class ConsoleCaptureCollection
{
    /// <summary>The collection's name.</summary>
    public const string Name = "ConsoleCapture";
}

/// <summary>
/// The headless bootstrap hands over its first administrator without a secret reaching standard
/// output, which under systemd and Podman is the journal. With a claim token hash in bootstrap.yaml
/// the account has no password and waits to be claimed; without one the generated password is left
/// in an owner-only file and only the file's path is printed.
/// </summary>
[Collection(ConsoleCaptureCollection.Name)]
public sealed class BootstrapInitialAdminHandoverTests : IDisposable
{
    private readonly string _configDir = Directory.CreateTempSubdirectory("mca-handover-").FullName;
    private static readonly DateTime Now = new(2026, 11, 9, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>A database holding the two system groups the first administrator joins.</summary>
    private static ModularCADbContext Seeded()
    {
        var db = InMemoryDbContextFactory.Create();
        db.CaGroups.AddRange(
            new CaGroupEntity { Name = "system-super", DisplayName = "system-super", IsSystemGroup = true, IsSystemTierSuper = true },
            new CaGroupEntity { Name = "system-admin", DisplayName = "system-admin", IsSystemGroup = true });
        db.SaveChanges();
        return db;
    }

    /// <summary>Runs <see cref="BootstrapProfileSeeder.CreateInitialUser"/> writing to the real console, and returns what it printed.</summary>
    private static (InitialAdminHandover Handover, string Printed) CreateCapturingConsole(
        ModularCADbContext db, string configDir, YamlBootstrapLoader.AdministrationConfig? administration)
    {
        var capture = new StringWriter();
        var console = Console.Out;
        Console.SetOut(capture);
        try
        {
            var handover = BootstrapProfileSeeder.CreateInitialUser(db, configDir, administration, now: Now);
            return (handover, capture.ToString());
        }
        finally
        {
            Console.SetOut(console);
        }
    }

    public void Dispose()
    {
        try { Directory.Delete(_configDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void Without_a_claim_the_generated_password_goes_to_an_owner_only_file_and_is_not_printed()
    {
        using var db = Seeded();

        var (handover, printed) = CreateCapturingConsole(db, _configDir, administration: null);

        var path = InitialAdminPasswordFile.PathIn(_configDir);
        Assert.Equal(path, handover.PasswordFile);
        Assert.Null(handover.ClaimExpiresAt);
        var password = InitialAdminPasswordFile.Read(_configDir);
        Assert.False(string.IsNullOrEmpty(password));
        Assert.True(password!.Length >= 16);

        // The file holds the account's password, which must be changed at first sign-in.
        var admin = Assert.Single(db.Users);
        Assert.Equal(BootstrapProfileSeeder.InitialUsername, admin.Username);
        Assert.True(PasswordUtil.VerifyPassword(password, admin.PasswordHash));
        Assert.True(admin.PasswordChangeOnNextLogon);
        Assert.Empty(db.UserClaimTokens);

        // Readable by this account only.
        if (OperatingSystem.IsWindows())
            Assert.True(new FileInfo(path).GetAccessControl().AreAccessRulesProtected,
                "the password file must not inherit its folder's permissions");
        else
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));

        // Standard output names the file and never carries the password, nor does the closing banner.
        Assert.DoesNotContain(password, printed);
        Assert.Contains(path, printed);
        var banner = string.Join("\n", handover.BannerLines());
        Assert.DoesNotContain(password, banner);
        Assert.Contains(path, banner);
        Assert.DoesNotContain("GENERATED ABOVE", banner);
    }

    [Fact]
    public void With_a_claim_hash_the_account_has_no_usable_password_and_waits_to_be_claimed()
    {
        using var db = Seeded();
        var token = AccountClaims.NewToken();
        var administration = new YamlBootstrapLoader.AdministrationConfig { ClaimTokenSha256 = AccountClaims.HashHex(token) };

        var (handover, printed) = CreateCapturingConsole(db, _configDir, administration);

        var admin = Assert.Single(db.Users);
        Assert.Equal(string.Empty, admin.PasswordHash);
        Assert.False(PasswordUtil.VerifyPassword(token, admin.PasswordHash));
        Assert.False(PasswordUtil.VerifyPassword(string.Empty, admin.PasswordHash));
        Assert.False(admin.PasswordChangeOnNextLogon);
        Assert.Equal(ModularCA.Shared.Enums.PasswordSource.Local, admin.PasswordSource);

        var claim = Assert.Single(db.UserClaimTokens);
        Assert.Equal(admin.Id, claim.UserId);
        Assert.Equal(AccountClaims.Hash(token), claim.TokenHash);
        Assert.Equal(Now + AccountClaims.DefaultLifetime, claim.ExpiresAt);
        Assert.Equal(AccountClaims.IssuedByBootstrap, claim.IssuedBy);

        // Nothing written, and nothing secret printed: only that it waits, and until when.
        Assert.False(File.Exists(InitialAdminPasswordFile.PathIn(_configDir)));
        Assert.Null(handover.PasswordFile);
        Assert.Equal(claim.ExpiresAt, handover.ClaimExpiresAt);
        Assert.DoesNotContain(token, printed);
        Assert.Contains("waiting to be claimed", printed);
        Assert.Contains("2026-11-16 12:00 UTC", printed);
        Assert.Contains("2026-11-16 12:00 UTC", string.Join("\n", handover.BannerLines()));
    }

    [Fact]
    public void A_claim_lifetime_from_bootstrap_yaml_sets_the_expiry_and_a_leftover_password_file_is_removed()
    {
        using var db = Seeded();
        InitialAdminPasswordFile.Write(_configDir, "an-earlier-install's-password");
        var administration = new YamlBootstrapLoader.AdministrationConfig
        {
            ClaimTokenSha256 = AccountClaims.HashHex(AccountClaims.NewToken()).ToUpperInvariant(),
            ClaimTokenLifetimeHours = 24,
        };

        BootstrapProfileSeeder.CreateInitialUser(db, _configDir, administration, TextWriter.Null, Now);

        Assert.Equal(Now.AddHours(24), Assert.Single(db.UserClaimTokens).ExpiresAt);
        Assert.False(File.Exists(InitialAdminPasswordFile.PathIn(_configDir)));
    }

    [Theory]
    [InlineData("not-a-hash", null)]
    [InlineData("abc123", null)]
    [InlineData("zz00000000000000000000000000000000000000000000000000000000000000", null)]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0)]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 8761)]
    public void A_claim_hash_or_lifetime_that_cannot_work_is_refused_before_anything_changes(string hash, int? hours)
    {
        var administration = new YamlBootstrapLoader.AdministrationConfig { ClaimTokenSha256 = hash, ClaimTokenLifetimeHours = hours };

        var ex = Assert.Throws<InvalidRequestException>(() => BootstrapInputSections.EnsureClaimTokenUsable(administration));
        Assert.Contains(hours == null ? "ClaimTokenSha256" : "ClaimTokenLifetimeHours", ex.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void No_claim_hash_is_not_a_claim(string? hash)
    {
        BootstrapInputSections.EnsureClaimTokenUsable(null);
        BootstrapInputSections.EnsureClaimTokenUsable(new YamlBootstrapLoader.AdministrationConfig { ClaimTokenSha256 = hash, ClaimTokenLifetimeHours = 0 });
    }

    [Fact]
    public void The_lifetime_has_a_week_default_and_a_year_ceiling()
    {
        BootstrapInputSections.EnsureClaimTokenUsable(new YamlBootstrapLoader.AdministrationConfig
        {
            ClaimTokenSha256 = AccountClaims.HashHex("t"),
            ClaimTokenLifetimeHours = 8760,
        });
        Assert.Equal(TimeSpan.FromDays(7), AccountClaims.DefaultLifetime);
    }

    [Theory]
    [InlineData("config/bootstrap.yaml.example")]
    [InlineData("ModularCA.Bootstrap/bootstrap.yaml.example")]
    public void The_examples_describe_the_claim_keys_without_setting_them(string relative)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any()) dir = dir.Parent;
        var text = File.ReadAllText(Path.Combine(dir!.FullName, relative));

        // Present, commented out: an example that set a hash would leave every copy of it with an
        // administrator nobody can claim.
        Assert.Contains("# ClaimTokenSha256:", text);
        Assert.Contains("# ClaimTokenLifetimeHours:", text);
        Assert.Contains("initial-admin-password", text);
        Assert.Null(YamlBootstrapLoader.Load(Path.Combine(dir.FullName, relative)).Administration.ClaimTokenSha256);
    }
}
