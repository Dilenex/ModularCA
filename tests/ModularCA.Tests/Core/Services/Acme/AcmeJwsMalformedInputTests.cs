using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Acme;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Acme;

/// <summary>
/// RFC 8555 §6.5 and §6.7 for the JWS filter. A missing, unknown or replayed nonce was answered
/// <c>malformed</c>, and with no Replay-Nonce header, so a client could not tell it to retry with
/// a fresh nonce and had none to retry with; it is <c>badNonce</c> now, with a fresh nonce. A body
/// that is not a well-formed JWS escaped the filter as a JSON, base64 or key-lookup exception and
/// became a 500; it is 400 <c>malformed</c> now, as is a payload the action cannot read.
/// </summary>
public class AcmeJwsMalformedInputTests
{
    private const string Domain = "ca.example";
    private const string Path = "/api/v1/acme/new-order";
    private const string Url = "https://ca.example/api/v1/acme/new-order";

    /// <summary>Hands out <c>fresh-nonce</c> and accepts only <c>good-nonce</c>, once.</summary>
    private sealed class Nonces : IAcmeNonceService
    {
        private bool _spent;
        public Task<string> GenerateAsync() => Task.FromResult("fresh-nonce");
        public Task<bool> ConsumeAsync(string nonce)
        {
            var ok = nonce == "good-nonce" && !_spent;
            _spent |= ok;
            return Task.FromResult(ok);
        }
        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> HasExpiredNoncesAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);
    }

    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string B64(string text) => B64(Encoding.UTF8.GetBytes(text));

    /// <summary>A JWS signed with an inline P-256 jwk, with <paramref name="nonce"/> in its header (none when null).</summary>
    private static string Signed(string? nonce, string payload = "{}")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = key.ExportParameters(false);
        var header = new Dictionary<string, object>
        {
            ["alg"] = "ES256",
            ["url"] = Url,
            ["jwk"] = new { kty = "EC", crv = "P-256", x = B64(p.Q.X!), y = B64(p.Q.Y!) },
        };
        if (nonce != null)
            header["nonce"] = nonce;
        var protectedB64 = B64(JsonSerializer.Serialize(header));
        var payloadB64 = B64(payload);
        var signature = key.SignData(Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}"), HashAlgorithmName.SHA256);
        return JsonSerializer.Serialize(new { @protected = protectedB64, payload = payloadB64, signature = B64(signature) });
    }

    /// <summary>An unsigned JWS whose protected header is <paramref name="header"/>, for the cases refused before verification.</summary>
    private static string WithHeader(string header, string payloadB64 = "", string signatureB64 = "AA")
        => JsonSerializer.Serialize(new { @protected = B64(header), payload = payloadB64, signature = signatureB64 });

    /// <summary>
    /// Runs the real filter and JWS service over <paramref name="body"/> posted to new-order (jwk
    /// allowed, so the JWS checks are what decide), with <paramref name="nonces"/> as the nonce
    /// store and <paramref name="action"/> as the action's outcome. Returns the refusal, or the
    /// action's result when it ran, and the response's Replay-Nonce.
    /// </summary>
    private static async Task<(ObjectResult? Result, string? ReplayNonce)> RunAsync(string body, Nonces? nonces = null,
        Func<ActionContext, ActionExecutedContext>? action = null)
    {
        using var db = InMemoryDbContextFactory.Create();
        var config = new SystemConfig();
        config.Https.PublicDomain = Domain;
        config.Https.PublicPort = 443;
        nonces ??= new Nonces();
        var accounts = new AcmeAccountService(db);
        var type = ApiAssembly.TypeNamed("ModularCA.API.Filters.AcmeJwsActionFilter");
        var filter = (IAsyncActionFilter)Activator.CreateInstance(type,
            new AcmeJwsService(accounts, nonces), nonces, accounts, new CaResolverService(db), config, true, true)!;

        var http = new DefaultHttpContext();
        http.Request.Method = "POST";
        http.Request.Path = Path;
        http.Request.ContentType = "application/jose+json";
        http.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        var context = new ActionContext(http, new RouteData(), new ActionDescriptor());
        var executing = new ActionExecutingContext(context, new List<IFilterMetadata>(), new Dictionary<string, object?>(), controller: new object());
        ActionExecutedContext? executed = null;
        await filter.OnActionExecutionAsync(executing, () =>
        {
            executed = action?.Invoke(context) ?? new ActionExecutedContext(context, new List<IFilterMetadata>(), new object());
            return Task.FromResult(executed);
        });

        var nonce = http.Response.Headers.TryGetValue("Replay-Nonce", out var value) ? value.ToString() : null;
        if (executed == null)
            return (Assert.IsType<ObjectResult>(executing.Result), nonce);
        return (executed.Result as ObjectResult, nonce);
    }

    private static string TypeOf(ObjectResult result) => Assert.IsType<AcmeErrorResponse>(result.Value).Type;

    private static void AssertRefused(ObjectResult? refusal, string type)
    {
        Assert.NotNull(refusal);
        Assert.Equal(400, refusal!.StatusCode);
        Assert.Equal(type, TypeOf(refusal));
    }

    private const string BadNonce = "urn:ietf:params:acme:error:badNonce";
    private const string Malformed = "urn:ietf:params:acme:error:malformed";

    /// <summary>An unknown or missing nonce is <c>badNonce</c> with a fresh nonce to retry with.</summary>
    [Theory]
    [InlineData("stale-nonce")]
    [InlineData(null)]
    [InlineData("")]
    public async Task A_bad_nonce_is_badNonce_with_a_fresh_replay_nonce(string? nonce)
    {
        var (refusal, fresh) = await RunAsync(Signed(nonce));

        AssertRefused(refusal, BadNonce);
        Assert.Equal("fresh-nonce", fresh);
    }

    /// <summary>A nonce that is not a string is <c>badNonce</c> too.</summary>
    [Fact]
    public async Task A_nonce_that_is_not_a_string_is_badNonce()
    {
        var (refusal, fresh) = await RunAsync(WithHeader($$"""{"alg":"ES256","url":"{{Url}}","nonce":5}"""));

        AssertRefused(refusal, BadNonce);
        Assert.Equal("fresh-nonce", fresh);
    }

    /// <summary>The same request posted twice: the second presents a spent nonce and is <c>badNonce</c>.</summary>
    [Fact]
    public async Task A_replayed_request_is_badNonce_with_a_fresh_replay_nonce()
    {
        var nonces = new Nonces();
        var body = Signed("good-nonce");

        var (first, _) = await RunAsync(body, nonces);
        var (replayed, fresh) = await RunAsync(body, nonces);

        Assert.Null(first);
        AssertRefused(replayed, BadNonce);
        Assert.Equal("fresh-nonce", fresh);
    }

    /// <summary>A body that is not a well-formed JWS is 400 <c>malformed</c>, never an exception.</summary>
    [Theory]
    [InlineData("not json")]
    [InlineData("")]
    [InlineData("[]")]
    [InlineData("\"text\"")]
    [InlineData("{}")]
    [InlineData("{\"protected\":5,\"payload\":\"\",\"signature\":\"\"}")]
    [InlineData("{\"payload\":\"\",\"signature\":\"\"}")]
    [InlineData("{\"protected\":\"!!!\",\"payload\":\"\",\"signature\":\"AA\"}")]
    [InlineData("{\"protected\":\"bm90IGpzb24\",\"payload\":\"\",\"signature\":\"AA\"}")]
    [InlineData("{\"protected\":\"WzFd\",\"payload\":\"\",\"signature\":\"AA\"}")]
    [InlineData("{\"protected\":\"e30\",\"payload\":\"\",\"signature\":\"AA\"}")]
    public async Task A_body_that_is_not_a_jws_is_malformed(string body)
    {
        var (refusal, nonce) = await RunAsync(body);

        AssertRefused(refusal, Malformed);
        Assert.Equal("fresh-nonce", nonce);
    }

    /// <summary>Header fields of the wrong shape, and a signature that is not base64url, are malformed too.</summary>
    [Theory]
    [InlineData("kid-not-a-uri")]
    [InlineData("kid-number")]
    [InlineData("alg-number")]
    [InlineData("url-number")]
    [InlineData("signature-not-base64")]
    public async Task A_jws_with_unreadable_fields_is_malformed(string shape)
    {
        var body = shape switch
        {
            "kid-not-a-uri" => WithHeader($$"""{"alg":"ES256","url":"{{Url}}","nonce":"good-nonce","kid":"not a uri"}"""),
            "kid-number" => WithHeader($$"""{"alg":"ES256","url":"{{Url}}","nonce":"good-nonce","kid":5}"""),
            "alg-number" => WithHeader($$"""{"alg":5,"url":"{{Url}}","nonce":"good-nonce"}"""),
            "url-number" => WithHeader("""{"alg":"ES256","url":5,"nonce":"good-nonce"}"""),
            _ => WithHeader($$$"""{"alg":"ES256","url":"{{{Url}}}","nonce":"good-nonce","jwk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}""", "", "!!!"),
        };

        var (refusal, _) = await RunAsync(body);

        AssertRefused(refusal, Malformed);
    }

    /// <summary>A signed payload that is not JSON, or is JSON but not an object, is malformed.</summary>
    [Theory]
    [InlineData("not json")]
    [InlineData("[1]")]
    [InlineData("5")]
    public async Task A_payload_that_is_not_a_json_object_is_malformed(string payload)
    {
        var (refusal, _) = await RunAsync(Signed("good-nonce", payload));

        AssertRefused(refusal, Malformed);
    }

    /// <summary>A payload the action cannot bind (a field of the wrong type) is 400 <c>malformed</c>, not a 500.</summary>
    [Fact]
    public async Task A_payload_the_action_cannot_read_is_malformed()
    {
        var (result, _) = await RunAsync(Signed("good-nonce", "{\"identifiers\":5}"), action: context =>
            new ActionExecutedContext(context, new List<IFilterMetadata>(), new object())
            {
                Exception = new JsonException("The JSON value could not be converted."),
            });

        AssertRefused(result, Malformed);
    }

    /// <summary>A well-formed JWS with a good nonce, and an empty POST-as-GET payload, still reach the action.</summary>
    [Theory]
    [InlineData("{}")]
    [InlineData("")]
    public async Task A_well_formed_jws_reaches_the_action(string payload)
    {
        var (result, nonce) = await RunAsync(Signed("good-nonce", payload));

        Assert.Null(result);
        Assert.Equal("fresh-nonce", nonce);
    }
}
