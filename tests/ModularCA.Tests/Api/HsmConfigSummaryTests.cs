using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// <c>GET /api/v1/admin/config</c> and its <c>hsm</c> section. The Settings page's HSM card read
/// <c>config.hsm</c>, which the response never carried, so the card always said Disabled. The
/// response now carries a read-only <see cref="HsmSettingsSummary"/>: what is in force when the
/// signer runs in process, and only where the settings are kept when the signer is remote. The PIN
/// and the mappings' key ids are never in it.
/// </summary>
public sealed class HsmConfigSummaryTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";
    private const string Pin = "pin-that-must-never-leave-7731";
    private const string KeyId = "c0ffee0ddba11";

    private sealed class CurrentUserStub : ICurrentUserService
    {
        public Guid? UserId { get; } = Guid.NewGuid();
        public UserEntity? User => null;
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class SecurityPolicyStub : ISecurityPolicyService
    {
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(new SecurityPolicyEntity());
        public void InvalidateCache() { }
    }

    private sealed class LdapPublisherPolicyStub : ILdapPublisherPolicyService
    {
        public Task<LdapPublisherPolicyEntity> GetAsync() => Task.FromResult(new LdapPublisherPolicyEntity());
        public void InvalidateCache() { }
    }

    /// <summary>A configuration with the HSM on, a PIN and a key mapping with a key id.</summary>
    private static SystemConfig WithHsm(bool remoteSigner)
    {
        var config = new SystemConfig();
        config.Hsm.Enabled = true;
        config.Hsm.ModulePath = "/usr/lib/softhsm/libsofthsm2.so";
        config.Hsm.SlotId = 1_234_567_890_123UL;
        config.Hsm.Pin = Pin;
        config.Hsm.KeyMappings.Add(new HsmKeyMapping { CaLabel = "root-ca", KeyLabel = "root-key", KeyId = KeyId });
        if (remoteSigner)
        {
            config.Signer.Mode = SignerConfig.RemoteMode;
            config.Signer.Endpoint = "https://signer.internal:8446";
        }
        return config;
    }

    /// <summary>Calls GetConfig and returns the response body as the browser would read it.</summary>
    private static async Task<(string Json, JsonElement Hsm)> GetConfig(SystemConfig config)
    {
        var controller = (ControllerBase)Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "AdminConfigController"),
            config, null, new RecordingAuditService(), new CurrentUserStub(),
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            new RecordingAlertService(), null, new EnvVarConfigOverlay(), new SecurityPolicyStub(), new LdapPublisherPolicyStub())!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        var result = await (Task<IActionResult>)controller.GetType().GetMethod("GetConfig")!.Invoke(controller, [])!;
        var ok = Assert.IsType<OkObjectResult>(result);
        var json = JsonSerializer.Serialize(ok.Value, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            ReferenceHandler = ReferenceHandler.IgnoreCycles,
            Converters = { new JsonStringEnumConverter() },
        });
        var hsm = JsonDocument.Parse(json).RootElement.GetProperty("hsm").Clone();
        return (json, hsm);
    }

    [Fact]
    public async Task In_process_the_response_says_what_is_in_force()
    {
        var (_, hsm) = await GetConfig(WithHsm(remoteSigner: false));

        Assert.Equal("node", hsm.GetProperty("heldBy").GetString());
        Assert.True(hsm.GetProperty("enabled").GetBoolean());
        Assert.Equal("/usr/lib/softhsm/libsofthsm2.so", hsm.GetProperty("modulePath").GetString());
        // As text: a slot id above 2^53 would lose digits as a JavaScript number.
        Assert.Equal("1234567890123", hsm.GetProperty("slotId").GetString());
        var mapping = Assert.Single(hsm.GetProperty("keyMappings").EnumerateArray());
        Assert.Equal("root-ca", mapping.GetProperty("caLabel").GetString());
        Assert.Equal("root-key", mapping.GetProperty("keyLabel").GetString());
        Assert.Equal(JsonValueKind.Null, hsm.GetProperty("signerEndpoint").ValueKind);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task The_pin_and_key_ids_are_never_returned(bool remoteSigner)
    {
        var (json, hsm) = await GetConfig(WithHsm(remoteSigner));

        Assert.DoesNotContain(Pin, json, StringComparison.Ordinal);
        Assert.DoesNotContain(KeyId, json, StringComparison.OrdinalIgnoreCase);
        Assert.False(hsm.TryGetProperty("pin", out _));
    }

    [Fact]
    public async Task With_a_remote_signer_only_where_the_settings_are_kept_is_returned()
    {
        // The node's file still has an Hsm section, as one does until the pod removes it; it is
        // not what the signer uses, so none of it is reported.
        var (json, hsm) = await GetConfig(WithHsm(remoteSigner: true));

        Assert.Equal("signer", hsm.GetProperty("heldBy").GetString());
        Assert.Equal("https://signer.internal:8446", hsm.GetProperty("signerEndpoint").GetString());
        foreach (var field in new[] { "enabled", "modulePath", "slotId", "keyMappings" })
            Assert.Equal(JsonValueKind.Null, hsm.GetProperty(field).ValueKind);
        Assert.DoesNotContain("libsofthsm2", json, StringComparison.Ordinal);
    }

    [Fact]
    public void The_summary_types_have_no_field_that_could_carry_a_secret()
    {
        var names = typeof(HsmSettingsSummary).GetProperties().Select(p => p.Name)
            .Concat(typeof(HsmKeyMappingSummary).GetProperties().Select(p => p.Name))
            .ToList();

        Assert.DoesNotContain(nameof(HsmConfig.Pin), names);
        Assert.DoesNotContain(nameof(HsmKeyMapping.KeyId), names);
    }

    [Fact]
    public void An_hsm_that_is_off_is_reported_off_with_nothing_set()
    {
        var summary = HsmSettingsSummary.From(new SystemConfig());

        Assert.Equal(HsmSettingsSummary.HeldByNode, summary.HeldBy);
        Assert.False(summary.Enabled);
        Assert.Equal(string.Empty, summary.ModulePath);
        Assert.Equal("0", summary.SlotId);
        Assert.Empty(summary.KeyMappings!);
    }
}
