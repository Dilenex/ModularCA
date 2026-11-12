using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The infrastructure API's renew checks the key's space scope before it says anything about the
/// certificate. It refused a revoked certificate with 400 and a retired one with 409 before the
/// scope check, so a key scoped to one space could learn the state of a certificate in another.
/// A certificate outside the scope is now answered as one that does not exist: 404.
/// </summary>
public class InfraRenewScopeTests
{
    private const string Serial = "0A:1B";
    private static readonly Guid Space = Guid.Parse("5c4b3a29-1807-4f6e-9d5c-4b3a29180706");
    private static readonly Guid OtherSpace = Guid.Parse("6d5c4b3a-2918-4f6e-9d5c-4b3a29180707");

    /// <summary>A store that holds one certificate in the given state.</summary>
    private sealed class OneCertificate(CertificateInfoModel info) : ICertificateStore
    {
        public Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber)
            => Task.FromResult<CertificateInfoModel?>(serialNumber == Serial ? info : null);
        public Task SaveCertificateAsync(byte[] certificateBytes, CertificateInfoModel info, byte[]? encryptedPrivateKey = null) => throw new NotSupportedException();
        public Task<IEnumerable<CertificateInfoModel>> ListAsync() => throw new NotSupportedException();
        public Task<List<CertificateInfoModel>> GetAllCertificatesAsync() => throw new NotSupportedException();
        public Task<CertificateInfoModel?> GetCertificateByIdAsync(Guid id) => throw new NotSupportedException();
        public Task<CertificateInfoModel?> GetCertificateBySerialNumberAsync(string serialNumber) => throw new NotSupportedException();
        public Task<byte[]?> GetRawCertificateAsync(string serialNumber) => throw new NotSupportedException();
    }

    /// <summary>
    /// Renews <see cref="Serial"/> with a key scoped to <see cref="Space"/> (or unrestricted), the
    /// certificate issued by a CA of <paramref name="caSpace"/> (null: the instance) in the given
    /// state. <paramref name="withSigningProfile"/> false leaves the certificate with no signing
    /// profile, so its space cannot be established.
    /// </summary>
    private static async Task<IActionResult> RenewAsync(
        Guid? caSpace, bool revoked = false, bool retired = false, bool restricted = true, bool withSigningProfile = true)
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity { Name = "CA", Label = "ca", CertificateId = Guid.NewGuid(), SpaceId = caSpace };
        db.CertificateAuthorities.Add(ca);
        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "signing", IssuerId = ca.CertificateId };
        var certProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "device" };
        db.SigningProfiles.Add(signing);
        db.CertProfiles.Add(certProfile);
        var certificateId = Guid.NewGuid();
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = certificateId,
            SerialNumber = Serial,
            SubjectDN = "CN=device",
            Issuer = "CN=CA",
            Pem = string.Empty,
            RawCertificate = [],
            SigningProfileId = withSigningProfile ? signing.Id : null,
            CertProfileId = withSigningProfile ? certProfile.Id : null,
        });
        await db.SaveChangesAsync();

        var info = new CertificateInfoModel
        {
            CertificateId = certificateId,
            SerialNumber = Serial,
            Revoked = revoked,
            RetiredAt = retired ? DateTime.UtcNow.AddDays(-1) : null,
        };
        var config = new SystemConfig();
        config.IntegrationApi.SpaceId = restricted ? Space.ToString() : null;

        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.InfraController");
        var controller = Activator.CreateInstance(type, null, null, new OneCertificate(info), null, null, null, null, db, config)!;
        return await (Task<IActionResult>)type.GetMethod("RenewCertificate")!.Invoke(controller, [Serial])!;
    }

    private static void AssertNotFound(IActionResult result)
    {
        var notFound = Assert.IsType<NotFoundObjectResult>(result);
        Assert.Equal("{\"error\":\"Certificate not found.\"}", System.Text.Json.JsonSerializer.Serialize(notFound.Value));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task A_certificate_in_another_space_is_not_found_whatever_its_state(bool revoked, bool retired)
        => AssertNotFound(await RenewAsync(OtherSpace, revoked, retired));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task An_instance_certificate_is_not_found_by_a_space_scoped_key(bool revoked)
        => AssertNotFound(await RenewAsync(caSpace: null, revoked));

    [Fact]
    public async Task A_certificate_whose_space_cannot_be_established_is_not_found_by_a_scoped_key()
        => AssertNotFound(await RenewAsync(Space, revoked: true, withSigningProfile: false));

    [Fact]
    public async Task A_revoked_certificate_inside_the_scope_is_still_refused_as_revoked()
        => Assert.IsType<BadRequestObjectResult>(await RenewAsync(Space, revoked: true));

    [Fact]
    public async Task A_retired_certificate_inside_the_scope_is_still_refused_as_retired()
        => Assert.IsType<ConflictObjectResult>(await RenewAsync(Space, retired: true));

    [Fact]
    public async Task An_unrestricted_key_is_told_a_certificate_is_revoked_wherever_it_is()
        => Assert.IsType<BadRequestObjectResult>(await RenewAsync(OtherSpace, revoked: true, restricted: false));
}
