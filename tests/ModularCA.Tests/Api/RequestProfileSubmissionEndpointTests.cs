using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The console's request routes take a request profile with every request: without one the
/// request is refused, with one it is held to the profile and the stored request records it.
/// </summary>
public sealed class RequestProfileSubmissionEndpointTests
{
    private sealed record World(ModularCADbContext Db, UserEntity User, CertProfileEntity Cert, SigningProfileEntity Signing, RequestProfileEntity Profile);

    private static World Seed()
    {
        var db = InMemoryDbContextFactory.Create();
        var user = new UserEntity { Id = Guid.NewGuid(), Username = "requester", Email = "r@x" };
        var cert = new CertProfileEntity { Name = "TLS Server", AllowedKeySizes = "[]", AllowedSignatureAlgorithms = "[]", ExtendedKeyUsages = "[]" };
        var signing = new SigningProfileEntity { Name = "signing", AllowedAlgorithms = "[]" };
        var profile = new RequestProfileEntity
        {
            Name = "Servers",
            DefaultCertProfileId = cert.Id,
            SubjectDnRules = JsonSerializer.Serialize(new[]
            {
                new SubjectDnFieldRule { Field = "CN", Requirement = "Required" },
                new SubjectDnFieldRule { Field = "O", Requirement = "Optional", FixedValue = "Acme" },
            }),
            SanRules = "{\"allowedTypes\":[\"DNS\"],\"required\":false,\"rules\":{}}",
        };
        db.AddRange(user, cert, signing, profile);
        db.SaveChanges();
        return new World(db, user, cert, signing, profile);
    }

    private static string CsrPem(string subject)
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var csr = new Pkcs10CertificationRequest(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()),
            new X509Name(subject), keys.Public, null);
        using var sw = new StringWriter();
        new PemWriter(sw).WriteObject(csr);
        return sw.ToString();
    }

    public static TheoryData<string> UploadControllers() => new()
    {
        "ModularCA.API.Controllers.v1.User.UserCertSignRequestController",
        "ModularCA.API.Controllers.v1.Admin.AdminCertSignRequestController",
    };

    [Theory]
    [MemberData(nameof(UploadControllers))]
    public async Task An_upload_names_its_request_profile_and_the_request_records_it(string controller)
    {
        var w = Seed();
        UploadCsrRequest Body(Guid? requestProfileId, string subject = "CN=host.example,O=Evil") => new()
        {
            Pem = CsrPem(subject),
            CertificateProfileId = w.Cert.Id,
            SigningProfileId = w.Signing.Id,
            RequestProfileId = requestProfileId,
        };

        var missing = Assert.IsType<BadRequestObjectResult>(await InvokeAsync(w, controller, "UploadCsrRequest", Body(null)));
        Assert.Contains("request profile is required", JsonSerializer.Serialize(missing.Value));
        Assert.Empty(w.Db.CertificateRequests);

        Assert.IsType<OkResult>(await InvokeAsync(w, controller, "UploadCsrRequest", Body(w.Profile.Id)));
        var stored = Assert.Single(w.Db.CertificateRequests);
        Assert.Equal(w.Profile.Id, stored.RequestProfileId);
        Assert.Equal("{\"O\":\"Acme\"}", stored.SubjectOverrides);

        var body = Body(w.Profile.Id);
        body.SanOverrides = [new SanOverride { Type = "Email", Value = "a@x.test" }];
        var refused = await Assert.ThrowsAsync<ConfigurationValidationException>(() => InvokeAsync(w, controller, "UploadCsrRequest", body));
        Assert.Equal(ErrorCodes.RequestProfileRefused, refused.Code);
        Assert.Contains("SAN type 'EMAIL' is not allowed", refused.Message);
        Assert.Single(w.Db.CertificateRequests);
    }

    /// <summary>Invokes <paramref name="action"/> of the real controller as the seeded user.</summary>
    private static async Task<IActionResult> InvokeAsync(World w, string controller, string action, object body)
    {
        var services = new SpaceIsolationMatrixTests.Resolver(w.Db);
        services.Add(typeof(ModularCA.Auth.Interfaces.ICurrentUserService), new CurrentUser(w.User));
        var type = ApiAssembly.TypeNamed(controller);
        var instance = ActivatorUtilities.CreateInstance(services, type);
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", w.User.Id.ToString())], "test")), RequestServices = services };
        type.GetProperty("ControllerContext")!.SetValue(instance, new ControllerContext { HttpContext = http });
        try
        {
            return await (Task<IActionResult>)type.GetMethod(action)!.Invoke(instance, [body])!;
        }
        catch (System.Reflection.TargetInvocationException e) when (e.InnerException != null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException).Throw();
            throw;
        }
    }

    private sealed class CurrentUser(UserEntity user) : ModularCA.Auth.Interfaces.ICurrentUserService
    {
        public Guid? UserId => user.Id;
        public UserEntity? User => user;
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }
}
