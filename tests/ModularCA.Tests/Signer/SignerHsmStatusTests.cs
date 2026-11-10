using System.Diagnostics;
using System.Text.Json;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Api;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// With a remote signer the Settings page's HSM card could only say "held by the signer". The
/// signer's health answer now carries what it loaded at start (whether its HSM is on, the module
/// path, the slot, the key labels), and <c>GET /api/v1/admin/config</c> shows that. These run the
/// real signer host behind mutual TLS and the node's client: the fields arrive, the PIN and the
/// key ids are in no message and no response, the node's own stale <c>Hsm:</c> section is never
/// what is shown, and a signer that says nothing or does not answer leaves the card as it was.
/// </summary>
[Collection(RemoteSignerCollection.Name)]
public sealed class SignerHsmStatusTests
{
    /// <summary>The signer's own HSM settings, which differ from whatever the node's file still says.</summary>
    private static HsmConfig SignerHsm() => new()
    {
        Enabled = true,
        ModulePath = "/opt/hsm/lib/libcs_pkcs11_R3.so",
        SlotId = 18_446_744_073_709_551_000UL,
        Pin = HsmConfigSummaryTests.Pin,
        KeyMappings =
        {
            new HsmKeyMapping { CaLabel = "root-ca", KeyLabel = "root-key-2026", KeyId = HsmConfigSummaryTests.KeyId },
            new HsmKeyMapping { CaLabel = "issuing-ca", KeyLabel = "issuing-key-2026" },
        },
    };

    [Fact]
    public async Task The_signers_health_answer_carries_its_hsm_settings_and_the_config_response_shows_them()
    {
        await using var host = await HostedSigner.StartAsync(new SettingsTestSigner(), hsm: SignerHsmStatus.From(SignerHsm()));
        using var node = host.Connect();

        var health = await node.HealthAsync();

        Assert.True(health.Unlocked);
        var hsm = Assert.IsType<SignerHsmStatus>(health.Hsm);
        Assert.True(hsm.Enabled);
        Assert.Equal("/opt/hsm/lib/libcs_pkcs11_R3.so", hsm.ModulePath);
        Assert.Equal(18_446_744_073_709_551_000UL, hsm.SlotId);
        Assert.Equal([("root-ca", "root-key-2026"), ("issuing-ca", "issuing-key-2026")], hsm.KeyLabels.Select(l => (l.CaLabel, l.KeyLabel)));

        // The node's file still has an Hsm section of its own (another module, another slot): not shown.
        var (json, card) = await HsmConfigSummaryTests.GetConfig(HsmConfigSummaryTests.WithHsm(remoteSigner: true), node);

        Assert.Equal("signer", card.GetProperty("heldBy").GetString());
        Assert.Equal("https://signer.internal:8446", card.GetProperty("signerEndpoint").GetString());
        Assert.True(card.GetProperty("enabled").GetBoolean());
        Assert.Equal("/opt/hsm/lib/libcs_pkcs11_R3.so", card.GetProperty("modulePath").GetString());
        // As text: this slot id is above 2^53.
        Assert.Equal("18446744073709551000", card.GetProperty("slotId").GetString());
        Assert.Equal(
            [("root-ca", "root-key-2026"), ("issuing-ca", "issuing-key-2026")],
            card.GetProperty("keyMappings").EnumerateArray().Select(m => (m.GetProperty("caLabel").GetString()!, m.GetProperty("keyLabel").GetString()!)));
        Assert.DoesNotContain("libsofthsm2", json, StringComparison.Ordinal);
        Assert.DoesNotContain("1234567890123", json, StringComparison.Ordinal);
        Assert.DoesNotContain(HsmConfigSummaryTests.Pin, json, StringComparison.Ordinal);
        Assert.DoesNotContain(HsmConfigSummaryTests.KeyId, json, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Nothing the signer puts on the wire for its HSM can hold the PIN or a key id: the types have no such field.</summary>
    [Fact]
    public void Neither_the_status_nor_its_wire_message_has_a_field_for_the_pin_or_a_key_id()
    {
        var status = SignerHsmStatus.From(SignerHsm());
        var wire = ModularCA.Signer.Wire.WireMapping.ToWire(new SignerHealth(true, 2, SignerHealth.Pkcs11Backend) { Hsm = status });
        var bytes = Google.Protobuf.MessageExtensions.ToByteArray(wire);

        foreach (var text in new[] { JsonSerializer.Serialize(status), wire.ToString(), System.Text.Encoding.UTF8.GetString(bytes) })
        {
            Assert.DoesNotContain(HsmConfigSummaryTests.Pin, text, StringComparison.Ordinal);
            Assert.DoesNotContain(HsmConfigSummaryTests.KeyId, text, StringComparison.OrdinalIgnoreCase);
        }

        string[] fields = [.. ModularCA.Signer.Wire.HsmStatus.Descriptor.Fields.InDeclarationOrder().Select(f => f.Name),
            .. ModularCA.Signer.Wire.HsmKeyLabel.Descriptor.Fields.InDeclarationOrder().Select(f => f.Name)];
        Assert.Equal(["enabled", "module_path", "slot_id", "key_labels", "ca_label", "key_label"], fields);
        string[] properties = [.. typeof(SignerHsmStatus).GetProperties().Select(p => p.Name), .. typeof(SignerHsmKeyLabel).GetProperties().Select(p => p.Name)];
        Assert.DoesNotContain(nameof(HsmConfig.Pin), properties);
        Assert.DoesNotContain(nameof(HsmKeyMapping.KeyId), properties);
    }

    /// <summary>A signer with its HSM off says so, which is not the same as saying nothing.</summary>
    [Fact]
    public async Task A_signer_with_no_hsm_reports_it_off()
    {
        await using var host = await HostedSigner.StartAsync(new SettingsTestSigner(), hsm: SignerHsmStatus.From(null));
        using var node = host.Connect();

        var (_, card) = await HsmConfigSummaryTests.GetConfig(HsmConfigSummaryTests.WithHsm(remoteSigner: true), node);

        Assert.Equal("signer", card.GetProperty("heldBy").GetString());
        Assert.False(card.GetProperty("enabled").GetBoolean());
        Assert.Equal(string.Empty, card.GetProperty("modulePath").GetString());
        Assert.Empty(card.GetProperty("keyMappings").EnumerateArray());
    }

    /// <summary>
    /// A signer that predates the field, and one that does not answer: the card says only where
    /// the settings are kept, as before, and the page is not held up for long.
    /// </summary>
    [Fact]
    public async Task A_signer_that_says_nothing_or_does_not_answer_leaves_only_where_the_settings_are_kept()
    {
        await using var older = await HostedSigner.StartAsync(new SettingsTestSigner());
        using (var node = older.Connect())
        {
            Assert.Null((await node.HealthAsync()).Hsm);
            var (_, card) = await HsmConfigSummaryTests.GetConfig(HsmConfigSummaryTests.WithHsm(remoteSigner: true), node);
            Assert.Equal("signer", card.GetProperty("heldBy").GetString());
            foreach (var field in new[] { "enabled", "modulePath", "slotId", "keyMappings" })
                Assert.Equal(JsonValueKind.Null, card.GetProperty(field).ValueKind);
        }

        await using var relay = new LoopbackRelay();
        using var away = HostedSigner.ConnectTo(relay.Endpoint);
        var watch = Stopwatch.StartNew();
        var (json, unreachable) = await HsmConfigSummaryTests.GetConfig(HsmConfigSummaryTests.WithHsm(remoteSigner: true), away);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), $"the config response waited {watch.Elapsed} for the signer");
        Assert.Equal("signer", unreachable.GetProperty("heldBy").GetString());
        Assert.Equal(JsonValueKind.Null, unreachable.GetProperty("enabled").ValueKind);
        Assert.DoesNotContain("libsofthsm2", json, StringComparison.Ordinal);
    }

    /// <summary>In process the node reads its own file, whatever state the signer is in.</summary>
    [Fact]
    public async Task In_process_the_node_reports_its_own_settings()
    {
        var (_, card) = await HsmConfigSummaryTests.GetConfig(HsmConfigSummaryTests.WithHsm(remoteSigner: false), UnreachableSigner());

        Assert.Equal("node", card.GetProperty("heldBy").GetString());
        Assert.Equal("/usr/lib/softhsm/libsofthsm2.so", card.GetProperty("modulePath").GetString());
    }

    [Fact]
    public void The_signer_role_registers_the_status_from_its_own_hsm_settings()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        var role = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.API", "Startup", "SignerRole.cs"));
        Assert.Contains("builder.Services.AddSingleton(SignerHsmStatus.From(config.Hsm));", role);
    }

    /// <summary>A signer that answers nothing.</summary>
    private static ISigningService UnreachableSigner() => new SettingsTestSigner { Unreachable = true };
}
