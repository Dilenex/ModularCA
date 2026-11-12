using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// A SCEP client at a CA SCEP cannot run on is answered 409 with the reason in words, on GetCACaps,
/// on GetCACert and on PKIOperation by GET and by POST, instead of the generic "SCEP operation failed".
/// </summary>
public class ScepControllerRefusalTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Scep.ScepController";

    private static readonly ProtocolAdvisory Advisory =
        ProtocolCompatibility.Advisories("SCEP", "ECDSA").Single();

    /// <summary>A SCEP service that refuses every CA-bound operation as an EC CA does.</summary>
    private sealed class RefusingScep : IScepService
    {
        public Task<(byte[] data, bool isPkcs7)> GetCaCertAsync(string? caLabel = null, string? sourceIp = null)
            => throw new ProtocolIncompatibleException(Advisory);
        public Task<string> GetCaCapsAsync(string? caLabel = null, string? sourceIp = null)
            => throw new ProtocolIncompatibleException(Advisory);
        public Task<byte[]> PkiOperationAsync(byte[] cmsRequest, string? caLabel = null, string? sourceIp = null)
            => throw new ProtocolIncompatibleException(Advisory);
    }

    private static object NewController(byte[]? body = null)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(ControllerName), new RefusingScep())!;
        var http = new DefaultHttpContext();
        if (body != null)
        {
            http.Request.Body = new MemoryStream(body);
            http.Request.ContentType = "application/x-pki-message";
        }
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    private static void AssertRefusal(IActionResult result)
    {
        var conflict = Assert.IsType<ConflictObjectResult>(result);
        var json = JsonDocument.Parse(JsonSerializer.Serialize(conflict.Value,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase })).RootElement;
        Assert.Equal(Advisory.Message, json.GetProperty("error").GetString());
        Assert.Equal(ProtocolCompatibility.ScepRequiresRsaKey, json.GetProperty("reason").GetString());
    }

    [Theory]
    [InlineData("GetCACaps", null)]
    [InlineData("GetCACert", null)]
    [InlineData("PKIOperation", "AAAA")]
    public async Task A_get_is_answered_409_with_the_reason(string operation, string? message)
    {
        var controller = NewController();
        var result = await (Task<IActionResult>)controller.GetType().GetMethod("Get")!
            .Invoke(controller, new object?[] { operation, message, "ec-ca" })!;

        AssertRefusal(result);
    }

    [Fact]
    public async Task A_post_is_answered_409_with_the_reason()
    {
        var controller = NewController([0x30, 0x00]);
        var result = await (Task<IActionResult>)controller.GetType().GetMethod("Post")!
            .Invoke(controller, new object?[] { "ec-ca" })!;

        AssertRefusal(result);
    }
}
