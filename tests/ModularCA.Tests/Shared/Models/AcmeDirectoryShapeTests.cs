using System.Text.Json;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Shared.Models;

/// <summary>
/// Pins the JSON shape of the ACME directory, which is the first thing every ACME client parses
/// and therefore the cheapest place to break all of them at once.
/// <para>
/// The directory used to emit <c>"meta": null</c> when external account binding was not required.
/// RFC 8555 §7.1.1 makes <c>meta</c> optional, and clients read optional as "may be absent", not
/// "may be null". certbot does <c>jobj.pop('meta', {})</c> — which returns the <c>{}</c> default
/// only when the KEY is missing. A present-but-null value hands back <c>None</c>, and the next
/// line raises <c>TypeError: argument of type 'NoneType' is not iterable</c>. Every certbot run
/// against this server died there, before it could even register an account.
/// </para>
/// <para>
/// These assert on ABSENCE of the key, not on the deserialized value. A round-trip test would
/// have passed against the broken code, because System.Text.Json reads <c>null</c> back into a
/// null property perfectly happily. The bug only exists in the wire form.
/// </para>
/// </summary>
public class AcmeDirectoryShapeTests
{
    // Matches the API's configured casing policy.
    private static readonly JsonSerializerOptions Wire = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private static JsonElement Serialize(object value) =>
        JsonDocument.Parse(JsonSerializer.Serialize(value, Wire)).RootElement;

    private static AcmeDirectoryResponse Directory(AcmeDirectoryMeta? meta = null) => new()
    {
        NewNonce = "https://ca.example.test/acme/x/new-nonce",
        NewAccount = "https://ca.example.test/acme/x/new-account",
        NewOrder = "https://ca.example.test/acme/x/new-order",
        RevokeCert = "https://ca.example.test/acme/x/revoke-cert",
        KeyChange = "https://ca.example.test/acme/x/key-change",
        Meta = meta,
    };

    [Fact]
    public void Meta_is_absent_not_null_when_there_is_nothing_to_advertise()
    {
        var json = Serialize(Directory(meta: null));

        Assert.False(json.TryGetProperty("meta", out _),
            "the directory must OMIT meta, not emit \"meta\": null — certbot cannot parse the latter");
    }

    [Fact]
    public void The_required_endpoints_are_always_present()
    {
        var json = Serialize(Directory(meta: null));

        foreach (var field in new[] { "newNonce", "newAccount", "newOrder", "revokeCert", "keyChange" })
        {
            Assert.True(json.TryGetProperty(field, out var value), $"{field} must be present");
            Assert.Equal(JsonValueKind.String, value.ValueKind);
        }
    }

    [Fact]
    public void Meta_is_emitted_when_external_account_binding_is_required()
    {
        var json = Serialize(Directory(new AcmeDirectoryMeta { ExternalAccountRequired = true }));

        Assert.True(json.TryGetProperty("meta", out var meta));
        Assert.Equal(JsonValueKind.Object, meta.ValueKind);
        Assert.True(meta.GetProperty("externalAccountRequired").GetBoolean());
    }

    [Fact]
    public void An_empty_meta_carries_no_null_members()
    {
        // Once a meta object IS emitted, a null member inside it is the same hazard one level
        // down — so the object must come out empty rather than full of nulls.
        var json = Serialize(Directory(new AcmeDirectoryMeta()));

        Assert.True(json.TryGetProperty("meta", out var meta));
        Assert.Equal(JsonValueKind.Object, meta.ValueKind);
        foreach (var member in meta.EnumerateObject())
        {
            Assert.False(member.Value.ValueKind == JsonValueKind.Null,
                $"meta.{member.Name} was emitted as null");
        }
    }

    [Fact]
    public void Problem_documents_omit_their_optional_members()
    {
        // RFC 8555 §6.7 problem documents reach the client on every error path, so the same
        // null-versus-absent rule applies to them.
        var json = Serialize(new AcmeErrorResponse
        {
            Type = "urn:ietf:params:acme:error:malformed",
            Detail = "example",
            Status = 400,
        });

        Assert.False(json.TryGetProperty("subproblems", out _));
        Assert.False(json.TryGetProperty("identifier", out _));
    }

    // ---- terms of service: advertisement and enforcement must move together ----
    //
    // The server used to reject every new-account whose termsOfServiceAgreed was not true,
    // while advertising no terms at all. RFC 8555 §7.3.3 couples the two: clients set that
    // flag only when the directory hands them a URL, so demanding agreement without
    // publishing one is unsatisfiable — registration failed with "Must agree to terms of
    // service." and there was no request the client could have sent instead.

    [Fact]
    public void No_configured_terms_advertises_nothing_and_requires_nothing()
    {
        var acme = new AcmeConfig();

        Assert.Null(acme.PublishedTermsOfServiceUrl);
        Assert.Null(AcmeDirectoryMeta.For(acme));
    }

    [Fact]
    public void Configured_terms_are_advertised_in_meta()
    {
        var acme = new AcmeConfig { TermsOfServiceUrl = "https://ca.example.test/terms" };

        var json = Serialize(Directory(AcmeDirectoryMeta.For(acme)));

        Assert.True(json.TryGetProperty("meta", out var meta));
        Assert.Equal("https://ca.example.test/terms", meta.GetProperty("termsOfService").GetString());
    }

    [Fact]
    public void Whitespace_only_terms_count_as_no_terms()
    {
        // Otherwise an operator who clears the field to a stray space re-arms enforcement
        // while advertising an empty string — the original deadlock, wearing a disguise.
        var acme = new AcmeConfig { TermsOfServiceUrl = "   " };

        Assert.Null(acme.PublishedTermsOfServiceUrl);
        Assert.Null(AcmeDirectoryMeta.For(acme));
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("https://ca.example.test/terms", true)]
    public void Enforcement_holds_exactly_when_the_directory_advertises_terms(string? configured, bool expected)
    {
        // The invariant, stated once: whatever new-account enforces, the directory advertises.
        // Both sides read PublishedTermsOfServiceUrl, and this pins them to each other.
        var acme = new AcmeConfig { TermsOfServiceUrl = configured! };

        var enforced = acme.PublishedTermsOfServiceUrl != null;
        var advertised = AcmeDirectoryMeta.For(acme)?.TermsOfService != null;

        Assert.Equal(expected, enforced);
        Assert.Equal(enforced, advertised);
    }

    [Fact]
    public void Eab_only_meta_carries_no_terms_of_service_key()
    {
        var acme = new AcmeConfig { ExternalAccountRequired = true };

        var json = Serialize(Directory(AcmeDirectoryMeta.For(acme)));

        Assert.True(json.TryGetProperty("meta", out var meta));
        Assert.True(meta.GetProperty("externalAccountRequired").GetBoolean());
        Assert.False(meta.TryGetProperty("termsOfService", out _));
    }
}
