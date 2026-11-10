using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Tests for <see cref="EnvVarConfigOverlay.WithSecretsProtected"/>. This helper backs four
/// PersistConfig sites — a regression here means env-sourced secrets get materialized to disk,
/// which is a credential disclosure on every config save.
/// </summary>
[Collection(EnvVarsCollection.Name)]
public class EnvVarConfigOverlayTests
{
    private const string JwtSecretEnvVar = "MODULARCA__JWT__SECRET";

    /// <summary>
    /// Sets MODULARCA__JWT__SECRET, runs the body, and unsets it on cleanup. Process-wide
    /// env-var manipulation is why this test class is in the EnvVars collection (serial).
    /// </summary>
    private static void WithJwtSecretEnvVar(string value, Action body)
    {
        var original = Environment.GetEnvironmentVariable(JwtSecretEnvVar);
        Environment.SetEnvironmentVariable(JwtSecretEnvVar, value);
        try { body(); }
        finally { Environment.SetEnvironmentVariable(JwtSecretEnvVar, original); }
    }

    [Fact]
    public void WithSecretsProtected_Nulls_EnvSourced_Secret_Before_Body_And_Restores_After()
    {
        WithJwtSecretEnvVar("from-env", () =>
        {
            var config = new SystemConfig();
            var overlay = new EnvVarConfigOverlay();
            overlay.Apply(config);
            Assert.Contains("JWT.Secret", overlay.EnvSourcedPaths);
            Assert.Equal("from-env", config.JWT.Secret);

            string? sawDuringBody = "<not-set>";
            overlay.WithSecretsProtected(config, () => { sawDuringBody = config.JWT.Secret; });

            Assert.Null(sawDuringBody);
            Assert.Equal("from-env", config.JWT.Secret); // restored
        });
    }

    [Fact]
    public void WithSecretsProtected_Restores_Even_When_Body_Throws()
    {
        WithJwtSecretEnvVar("from-env", () =>
        {
            var config = new SystemConfig();
            var overlay = new EnvVarConfigOverlay();
            overlay.Apply(config);

            Assert.Throws<InvalidOperationException>(() =>
                overlay.WithSecretsProtected(config, () => throw new InvalidOperationException("boom")));

            // Restore must run even if body threw — the JWT secret is back in memory and the
            // running process can keep using it for token signing on subsequent requests.
            Assert.Equal("from-env", config.JWT.Secret);
        });
    }

    [Fact]
    public void WithSecretsProtected_Skips_Non_EnvSourced_Fields()
    {
        // No env var is set this round, so EnvSourcedPaths is empty and JWT.Secret is whatever
        // the operator typed. WithSecretsProtected must not null it.
        var original = Environment.GetEnvironmentVariable(JwtSecretEnvVar);
        Environment.SetEnvironmentVariable(JwtSecretEnvVar, null);
        try
        {
            var config = new SystemConfig { JWT = { Secret = "from-yaml" } };
            var overlay = new EnvVarConfigOverlay();
            overlay.Apply(config);
            Assert.DoesNotContain("JWT.Secret", overlay.EnvSourcedPaths);

            string? sawDuringBody = "<not-set>";
            overlay.WithSecretsProtected(config, () => { sawDuringBody = config.JWT.Secret; });

            // Body still saw the operator-typed value (not nulled) and the value is unchanged
            // afterward — non-env-sourced fields flow through to the YAML write as-is.
            Assert.Equal("from-yaml", sawDuringBody);
            Assert.Equal("from-yaml", config.JWT.Secret);
        }
        finally { Environment.SetEnvironmentVariable(JwtSecretEnvVar, original); }
    }

    [Fact]
    public void EnvSourcedPaths_Is_ReadOnlySet_Cannot_Be_Mutated_By_Caller()
    {
        var overlay = new EnvVarConfigOverlay();
        // The exposed type is IReadOnlySet<string> so the compiler refuses .Add(...). This test
        // is a compile-time guard captured as a runtime check on the declared type — if someone
        // changes the property to expose HashSet<string> in the future, this test breaks first.
        Assert.IsAssignableFrom<IReadOnlySet<string>>(overlay.EnvSourcedPaths);
    }

    [Fact]
    public void Apply_Marks_EnvSourced_Path_When_Variable_Set()
    {
        WithJwtSecretEnvVar("present", () =>
        {
            var config = new SystemConfig();
            var overlay = new EnvVarConfigOverlay();
            overlay.Apply(config);

            Assert.Contains("JWT.Secret", overlay.EnvSourcedPaths);
        });
    }

    [Fact]
    public void Apply_Does_Not_Mark_EnvSourced_Path_When_Variable_Empty()
    {
        // Empty string is treated as "not set" by Apply (matches IsNullOrEmpty check).
        var original = Environment.GetEnvironmentVariable(JwtSecretEnvVar);
        Environment.SetEnvironmentVariable(JwtSecretEnvVar, "");
        try
        {
            var config = new SystemConfig();
            var overlay = new EnvVarConfigOverlay();
            overlay.Apply(config);

            Assert.DoesNotContain("JWT.Secret", overlay.EnvSourcedPaths);
        }
        finally { Environment.SetEnvironmentVariable(JwtSecretEnvVar, original); }
    }

    /// <summary>
    /// The HSM PIN is cleared from the running configuration once the session has logged in, so
    /// the process no longer holds it as a string. A config.yaml rewrite must still keep the PIN
    /// the file holds, or the next start could not log in to the HSM.
    /// </summary>
    [Fact]
    public void Release_clears_a_file_secret_and_writes_put_the_file_value_back()
    {
        var config = new SystemConfig();
        config.Hsm.Pin = "pin-1234";
        var overlay = new EnvVarConfigOverlay();

        overlay.Release(config, "Hsm.Pin", () => "pin-1234");
        Assert.Equal(string.Empty, config.Hsm.Pin);

        string? written = null;
        overlay.WithSecretsProtected(config, () => written = ConfigYamlWriter.Serialize(config));

        Assert.Contains("pin-1234", written);
        Assert.Equal(string.Empty, config.Hsm.Pin);
    }

    [Fact]
    public void Release_of_an_unreadable_file_stops_the_write_and_keeps_the_secret_cleared()
    {
        var config = new SystemConfig();
        config.Hsm.Pin = "1234";
        var overlay = new EnvVarConfigOverlay();
        overlay.Release(config, "Hsm.Pin", () => throw new IOException("unreadable"));

        var ran = false;
        Assert.Throws<IOException>(() => overlay.WithSecretsProtected(config, () => ran = true));

        Assert.False(ran);
        Assert.Equal(string.Empty, config.Hsm.Pin);
    }

    [Fact]
    public void Release_of_an_environment_secret_keeps_it_out_of_the_file()
    {
        const string pinVar = "MODULARCA__HSM__PIN";
        var original = Environment.GetEnvironmentVariable(pinVar);
        Environment.SetEnvironmentVariable(pinVar, "from-env");
        try
        {
            var config = new SystemConfig();
            var overlay = new EnvVarConfigOverlay();
            overlay.Apply(config);
            overlay.Release(config, "Hsm.Pin", () => "from-file");

            string? sawDuringBody = "<not-set>";
            overlay.WithSecretsProtected(config, () => sawDuringBody = config.Hsm.Pin);

            Assert.Null(sawDuringBody);
            Assert.Equal(string.Empty, config.Hsm.Pin);
        }
        finally { Environment.SetEnvironmentVariable(pinVar, original); }
    }

    [Fact]
    public void Release_refuses_a_path_that_is_not_a_secret()
        => Assert.Throws<ArgumentException>(() => new EnvVarConfigOverlay().Release(new SystemConfig(), "Http.Port", () => null));

    /// <summary>Sets <see cref="EnvVarConfigOverlay.HealthLoopbackPortVariable"/> for the length of <paramref name="body"/>.</summary>
    private static void WithHealthPortEnvVar(string? value, Action body)
    {
        var original = Environment.GetEnvironmentVariable(EnvVarConfigOverlay.HealthLoopbackPortVariable);
        Environment.SetEnvironmentVariable(EnvVarConfigOverlay.HealthLoopbackPortVariable, value);
        try { body(); }
        finally { Environment.SetEnvironmentVariable(EnvVarConfigOverlay.HealthLoopbackPortVariable, original); }
    }

    [Fact]
    public void The_health_port_from_the_environment_applies_and_is_never_written_to_the_file()
    {
        WithHealthPortEnvVar("8081", () =>
        {
            var config = new SystemConfig { Health = { LoopbackPort = 9090 } };
            var overlay = new EnvVarConfigOverlay();
            using var log = new StringWriter();
            overlay.Apply(config, log);

            Assert.Equal(8081, config.Health.LoopbackPort);
            Assert.Contains("Health.LoopbackPort", overlay.EnvSourcedPaths);
            Assert.Contains("Health.LoopbackPort", log.ToString());
            Assert.DoesNotContain("8081", log.ToString());

            // A config.yaml write sees the file's own value, and the running value comes back.
            var sawDuringBody = -2;
            overlay.WithSecretsProtected(config, () => sawDuringBody = config.Health.LoopbackPort);
            Assert.Equal(9090, sawDuringBody);
            Assert.Equal(8081, config.Health.LoopbackPort);
        });
    }

    [Fact]
    public void A_health_port_from_the_environment_that_is_not_a_number_is_refused_at_the_start()
    {
        WithHealthPortEnvVar("eighty-eighty-one", () =>
        {
            var config = new SystemConfig();
            new EnvVarConfigOverlay().Apply(config, TextWriter.Null);

            Assert.Equal(-1, config.Health.LoopbackPort);
            Assert.Contains("is not a port", ConfigInputRules.HealthLoopbackPortError(config));
        });
    }

    [Fact]
    public void Without_the_variable_the_health_port_is_the_files()
    {
        WithHealthPortEnvVar(null, () =>
        {
            var config = new SystemConfig { Health = { LoopbackPort = 9090 } };
            var overlay = new EnvVarConfigOverlay();
            overlay.Apply(config, TextWriter.Null);

            Assert.Equal(9090, config.Health.LoopbackPort);
            Assert.DoesNotContain("Health.LoopbackPort", overlay.EnvSourcedPaths);
            var sawDuringBody = -2;
            overlay.WithSecretsProtected(config, () => sawDuringBody = config.Health.LoopbackPort);
            Assert.Equal(9090, sawDuringBody);
        });
    }
}
