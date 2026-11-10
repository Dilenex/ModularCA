using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Settings;

/// <summary>
/// A node that starts before its signer listens, as a pod or two units started together do:
/// the secrets the signer wraps are neither moved nor read at start, and once the signer
/// answers the background retry moves and reads them, without a restart. The JWT secret the
/// node made up meanwhile is never stored, and the stored one replaces it in the running
/// configuration. While it waits, the node's health says it is not ready.
/// </summary>
public sealed class SignerSecretsRetryTests : IDisposable
{
    private const string JwtSecret = "the-jwt-secret-from-the-file-which-is-long-enough-for-the-node-to-accept-it-at-start";
    private const string BindPassword = "the-directory-bind-password";
    private const string MailPassword = "the-mail-password";
    private const string TemporaryJwt = "a-temporary-jwt-secret-made-up-for-this-start-and-long-enough-to-be-accepted-by-it";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-signer-secrets-{Guid.NewGuid():N}");
    private readonly string _databaseName = $"signer-secrets-{Guid.NewGuid():N}";
    private readonly RecordingAuditService _audit = new();

    /// <summary>Creates the directory the configuration file lives in.</summary>
    public SignerSecretsRetryTests() => Directory.CreateDirectory(_dir);

    /// <summary>Removes it.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private ModularCADbContext Db() => InMemoryDbContextFactory.Create(_databaseName);
    private SettingsStore Store(ModularCA.Shared.Signing.ISigningService signer) => new(Db(), _audit, signer, NullLogger<SettingsStore>.Instance);

    private static SystemConfig FromFileWithSecrets(bool withJwt = true)
    {
        var config = new SystemConfig();
        config.Acme.Http01.MaxAddresses = 8;
        config.Https.Port = 9443;
        if (withJwt)
            config.JWT.Secret = JwtSecret;
        config.LdapAuth.BindPassword = BindPassword;
        config.Email.Password = MailPassword;
        return config;
    }

    private string WriteFile(SystemConfig config)
    {
        var path = Path.Combine(_dir, "config.yaml");
        ConfigYamlWriter.Write(path, config);
        return path;
    }

    private async Task<(SystemConfig Config, SettingsPersistence Persistence, SettingsStartReport Report)> Start(string path, SettingsTestSigner signer)
    {
        var config = YamlConfigLoader.Load(path, _ => { });
        var overlay = new EnvVarConfigOverlay();
        var persistence = new SettingsPersistence(config, overlay, path);
        var report = await SettingsRuntime.StartAsync(Store(signer), config, persistence, overlay.EnvSourcedPaths, mayMove: true, withSecrets: true);
        return (config, persistence, report);
    }

    private SignerSecretsRetry Retry(SettingsTestSigner signer, SignerSecretsState state, SystemConfig config, SettingsPersistence persistence, bool mayMove = true)
        => new(signer, state,
            ct => SettingsRuntime.CompleteSecretsAsync(Store(signer), config, persistence, new HashSet<string>(), mayMove, state.MadeUp, ct),
            NullLogger.Instance, TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(40));

    /// <summary>Brings the signer up a little after the retry has found it down a few times.</summary>
    private static async Task<SettingsSecretsReport?> RunWhileTheSignerComesUp(SignerSecretsRetry retry, SettingsTestSigner signer)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var running = retry.RunAsync(timeout.Token);
        await Task.Delay(150);
        Assert.False(running.IsCompleted, "the retry must keep waiting while the signer is down");
        signer.Unreachable = false;
        return await running;
    }

    [Fact]
    public async Task A_first_start_with_the_signer_down_moves_the_secrets_once_it_answers_without_a_restart()
    {
        var signer = new SettingsTestSigner { Unreachable = true };
        var path = WriteFile(FromFileWithSecrets());
        var started = await Start(path, signer);
        Assert.Empty(started.Report.SecretsMoved!);
        Assert.Contains(JwtSecret, File.ReadAllText(path));

        var state = new SignerSecretsState();
        state.MarkPending("waiting");
        var report = await RunWhileTheSignerComesUp(Retry(signer, state, started.Config, started.Persistence), signer);

        Assert.NotNull(report);
        Assert.Equal(["Email_Password", "JWT_Secret", "LdapAuth_BindPassword"], report!.SecretsMoved.Order());
        Assert.Empty(report.SecretProblems);
        Assert.False(state.Pending);
        // Wrapped in the store, gone from the file and from the copy of it, in force as before.
        Assert.Equal(3, (await Store(signer).LoadAsync()).Secrets.Count);
        Assert.DoesNotContain(JwtSecret, File.ReadAllText(path));
        Assert.DoesNotContain(BindPassword, File.ReadAllText(path));
        Assert.DoesNotContain(JwtSecret, File.ReadAllText(report.FileBackup!));
        Assert.Equal(JwtSecret, started.Config.JWT.Secret);
        Assert.Equal(BindPassword, started.Config.LdapAuth.BindPassword);

        // The next start reads them back as any start would.
        var next = await Start(path, signer);
        Assert.Equal(JwtSecret, next.Config.JWT.Secret);
        Assert.Equal(MailPassword, next.Config.Email.Password);
    }

    [Fact]
    public async Task A_later_start_with_the_signer_down_reads_the_stored_secrets_once_it_answers_and_drops_its_temporary_jwt()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFile(FromFileWithSecrets());
        await Start(path, signer);

        signer.Unreachable = true;
        var later = await Start(path, signer);
        Assert.Equal(string.Empty, later.Config.JWT.Secret);
        Assert.Null(later.Config.LdapAuth.BindPassword);
        // What the startup does with a JWT secret it could not read.
        later.Config.JWT.Secret = TemporaryJwt;
        later.Persistence.KeepSecretsAsHeld();
        later.Persistence.LeaveOutOfFile(SettingsPersistence.JwtSecretKey);
        var state = new SignerSecretsState();
        state.MarkMadeUp(SettingsPersistence.JwtSecretKey);
        state.MarkPending("waiting");

        var report = await RunWhileTheSignerComesUp(Retry(signer, state, later.Config, later.Persistence), signer);

        Assert.NotNull(report);
        Assert.Empty(report!.SecretsMoved);
        Assert.Empty(report.SecretProblems);
        Assert.Equal(JwtSecret, later.Config.JWT.Secret);
        Assert.Equal(BindPassword, later.Config.LdapAuth.BindPassword);
        Assert.Equal(MailPassword, later.Config.Email.Password);
        Assert.False(state.Pending);
        Assert.Empty(state.MadeUp);
        // The temporary secret was never stored, and a later save does not store anything for it.
        var stored = await Store(signer).LoadAsync();
        Assert.Equal(1, stored.Secrets["JWT_Secret"].Version);
        later.Config.Acme.Http01.MaxAddresses = 5;
        await later.Persistence.SaveAsync(Store(signer), new SettingsActor(Guid.NewGuid(), "alice"));
        Assert.Equal(1, (await Store(signer).LoadAsync()).Secrets["JWT_Secret"].Version);
        Assert.Equal(JwtSecret, (await Start(path, signer)).Config.JWT.Secret);
    }

    [Fact]
    public async Task A_made_up_jwt_secret_with_none_stored_is_kept_and_never_stored()
    {
        var signer = new SettingsTestSigner { Unreachable = true };
        var path = WriteFile(FromFileWithSecrets(withJwt: false));
        var started = await Start(path, signer);
        started.Config.JWT.Secret = TemporaryJwt;
        started.Persistence.KeepSecretsAsHeld();
        started.Persistence.LeaveOutOfFile(SettingsPersistence.JwtSecretKey);
        var state = new SignerSecretsState();
        state.MarkMadeUp(SettingsPersistence.JwtSecretKey);
        state.MarkPending("waiting");

        var report = await RunWhileTheSignerComesUp(Retry(signer, state, started.Config, started.Persistence), signer);

        Assert.Equal(["Email_Password", "LdapAuth_BindPassword"], report!.SecretsMoved.Order());
        Assert.DoesNotContain("JWT_Secret", (await Store(signer).LoadAsync()).Secrets.Keys);
        Assert.Equal(TemporaryJwt, started.Config.JWT.Secret);
        Assert.DoesNotContain(TemporaryJwt, File.ReadAllText(path));
    }

    [Fact]
    public async Task Another_role_reads_the_stored_secrets_once_the_signer_answers_and_moves_none()
    {
        var signer = new SettingsTestSigner();
        var path = WriteFile(FromFileWithSecrets());
        await Start(path, signer);

        var otherPath = Path.Combine(_dir, "other.yaml");
        ConfigYamlWriter.Write(otherPath, new SystemConfig { Https = { Port = 9443 } });
        var before = File.ReadAllText(otherPath);
        var other = YamlConfigLoader.Load(otherPath, _ => { });
        var persistence = new SettingsPersistence(other, new EnvVarConfigOverlay(), otherPath);
        signer.Unreachable = true;
        await SettingsRuntime.StartAsync(Store(signer), other, persistence, new HashSet<string>(), mayMove: false, withSecrets: true);
        Assert.Null(other.LdapAuth.BindPassword);

        var state = new SignerSecretsState();
        state.MarkPending("waiting");
        var report = await RunWhileTheSignerComesUp(Retry(signer, state, other, persistence, mayMove: false), signer);

        Assert.Empty(report!.SecretsMoved);
        Assert.Equal(BindPassword, other.LdapAuth.BindPassword);
        Assert.Equal(JwtSecret, other.JWT.Secret);
        Assert.Equal(before, File.ReadAllText(otherPath));
    }

    [Fact]
    public async Task While_the_signer_stays_down_nothing_is_attempted_and_stopping_ends_the_wait()
    {
        var signer = new SettingsTestSigner { Unreachable = true };
        var state = new SignerSecretsState();
        state.MarkPending("waiting");
        var calls = 0;
        var retry = new SignerSecretsRetry(signer, state, _ =>
        {
            calls++;
            throw new InvalidOperationException("not to be called");
        }, NullLogger.Instance, TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(20));

        using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var report = await retry.RunAsync(stop.Token);

        Assert.Null(report);
        Assert.Equal(0, calls);
        Assert.True(state.Pending);
    }

    [Fact]
    public async Task A_step_that_fails_once_the_signer_answers_is_tried_again()
    {
        var signer = new SettingsTestSigner();
        var state = new SignerSecretsState();
        state.MarkPending("waiting");
        var calls = 0;
        var done = new SettingsSecretsReport(new SettingsSnapshot(0, new Dictionary<string, StoredSetting>(), new Dictionary<string, StoredSecret>()), [], [], null, null);
        var retry = new SignerSecretsRetry(signer, state, _ =>
        {
            if (++calls == 1)
                throw new InvalidOperationException("the database blinked");
            return Task.FromResult(done);
        }, NullLogger.Instance, TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(20));

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        Assert.Same(done, await retry.RunAsync(timeout.Token));
        Assert.Equal(2, calls);
        Assert.False(state.Pending);
    }

    [Fact]
    public async Task The_nodes_health_is_unhealthy_while_the_secrets_wait_and_healthy_after()
    {
        var state = new SignerSecretsState();
        var type = ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.SignerSecretsHealthCheck");
        var check = (IHealthCheck)Activator.CreateInstance(type, state)!;

        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(new HealthCheckContext())).Status);
        state.MarkPending("The secrets the signer wraps have not been read.");
        var pending = await check.CheckHealthAsync(new HealthCheckContext());
        Assert.Equal(HealthStatus.Unhealthy, pending.Status);
        Assert.Contains("signerSecrets", pending.Data.Keys);
        state.MarkDone();
        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(new HealthCheckContext())).Status);
    }

    [Fact]
    public void Tokens_are_checked_against_the_jwt_secret_in_force_when_they_arrive()
    {
        var config = new SystemConfig { JWT = { Secret = TemporaryJwt, Issuer = "mca", Audience = "mca" } };
        var type = ApiAssembly.TypeNamed("ModularCA.API.Startup.JwtSigningKey");
        var keys = Activator.CreateInstance(type, config)!;
        var current = type.GetMethod("Current")!;
        Microsoft.IdentityModel.Tokens.SecurityKey Current() => (Microsoft.IdentityModel.Tokens.SecurityKey)current.Invoke(keys, null)!;
        var parameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidIssuer = "mca", ValidAudience = "mca", ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (_, _, _, _) => [Current()],
        };
        string Sign(string secret)
        {
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(secret)),
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
            return handler.WriteToken(new System.IdentityModel.Tokens.Jwt.JwtSecurityToken("mca", "mca", null, null, DateTime.UtcNow.AddMinutes(5), credentials));
        }
        bool Accepted(string token)
        {
            try
            {
                new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().ValidateToken(token, parameters, out _);
                return true;
            }
            catch (Microsoft.IdentityModel.Tokens.SecurityTokenException)
            {
                return false;
            }
        }

        var underTemporary = Sign(TemporaryJwt);
        Assert.True(Accepted(underTemporary));
        Assert.Same(Current(), Current());

        // The stored secret is read onto the running configuration.
        config.JWT.Secret = JwtSecret;
        Assert.False(Accepted(underTemporary));
        Assert.True(Accepted(Sign(JwtSecret)));
    }

    [Fact]
    public void The_startup_marks_the_wait_runs_the_retry_and_checks_tokens_against_the_secret_in_force()
    {
        var startup = Source("ModularCA.API", "StartModularCA.cs");
        Assert.Contains("settingsOutcome.SignerUnreachable", startup);
        Assert.Contains("signerSecretsState.MarkMadeUp(ModularCA.Core.Services.Settings.SettingsPersistence.JwtSecretKey)", startup);
        Assert.Contains("new ModularCA.API.Services.SignerSecretsRetryService(", startup);
        Assert.Contains("IssuerSigningKeyResolver = (_, _, _, _) => jwtSigningKey.Keys()", startup);
        Assert.DoesNotContain("IssuerSigningKey = new SymmetricSecurityKey", startup);
    }

    private static string Source(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(new[] { dir!.FullName }.Concat(parts).ToArray()));
    }
}
