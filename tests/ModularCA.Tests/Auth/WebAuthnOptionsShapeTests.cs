using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Pins the JSON shape the browser is handed for WebAuthn registration.
/// </summary>
/// <remarks>
/// <para>
/// <c>WebAuthnController</c> returns the Fido2 library's own serialization rather than
/// <c>Ok(options)</c>, because the application's global <c>JsonStringEnumConverter</c> would
/// otherwise stringify the WebAuthn enums and the browser would reject the options. That makes
/// the library's output an external contract with the browser that nothing in this codebase was
/// checking.
/// </para>
/// <para>
/// The admin UI does <c>options.challenge = base64urlToBuffer(options.challenge)</c> immediately
/// on receipt. If the serialization does not carry a top-level <c>challenge</c> — because a Fido2
/// upgrade nested it, renamed it, or changed its encoding — that line throws
/// "can't access property replace, e is undefined" from inside the registration handler, with
/// nothing on the server to indicate anything went wrong.
/// </para>
/// </remarks>
public class WebAuthnOptionsShapeTests
{
    private static CredentialCreateOptions BuildOptions()
    {
        var fido2 = new Fido2(new Fido2Configuration
        {
            ServerDomain = "ca.example.test",
            ServerName = "ModularCA",
            Origins = new HashSet<string> { "https://ca.example.test" },
        });

        return fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Id = "user-1"u8.ToArray(),
                Name = "operator",
                DisplayName = "Operator",
            },
            ExcludeCredentials = new List<PublicKeyCredentialDescriptor>(),
            AuthenticatorSelection = new AuthenticatorSelection
            {
                UserVerification = UserVerificationRequirement.Preferred,
                ResidentKey = ResidentKeyRequirement.Preferred,
            },
        });
    }

    [Fact]
    public void The_serialized_options_carry_a_top_level_challenge()
    {
        using var doc = JsonDocument.Parse(BuildOptions().ToJson());
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("challenge", out var challenge),
            "The browser-facing options must expose `challenge` at the top level; the UI reads it "
            + "directly. Actual keys: " + string.Join(", ", root.EnumerateObject().Select(p => p.Name)));

        // base64urlToBuffer calls .replace on it, so it has to be a string — a byte array would
        // throw "e.replace is not a function" instead of "e is undefined", but both are crashes.
        Assert.Equal(JsonValueKind.String, challenge.ValueKind);
        Assert.False(string.IsNullOrWhiteSpace(challenge.GetString()));
    }

    [Fact]
    public void The_serialized_options_carry_the_fields_the_browser_requires()
    {
        using var doc = JsonDocument.Parse(BuildOptions().ToJson());
        var root = doc.RootElement;
        var keys = root.EnumerateObject().Select(p => p.Name).ToList();

        foreach (var required in new[] { "rp", "user", "challenge", "pubKeyCredParams" })
            Assert.True(root.TryGetProperty(required, out _),
                $"missing `{required}`. Actual keys: {string.Join(", ", keys)}");
    }

    [Fact]
    public void The_options_are_not_wrapped_in_a_publicKey_envelope()
    {
        // navigator.credentials.create({ publicKey: options }) — the UI supplies that envelope
        // itself, so a server that also wrapped would produce options.publicKey.challenge and the
        // top-level read would be undefined.
        using var doc = JsonDocument.Parse(BuildOptions().ToJson());

        Assert.False(doc.RootElement.TryGetProperty("publicKey", out _),
            "options are double-wrapped; the UI adds the publicKey envelope itself.");
    }
}
