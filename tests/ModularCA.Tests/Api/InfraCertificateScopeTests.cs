using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The infrastructure API's certificate read and revoke answer a certificate outside the key's
/// space scope exactly as one that does not exist: 404 with the same body. They answered 403 for
/// one outside the scope and 404 for one that was missing, so a key scoped to one space could
/// learn which serials exist in every other.
/// </summary>
public class InfraCertificateScopeTests
{
    private const string Serial = "0A:2C";
    private static readonly Guid Space = Guid.Parse("7e6d5c4b-3a29-4f6e-9d5c-4b3a29180708");
    private static readonly Guid OtherSpace = Guid.Parse("8f7e6d5c-4b3a-4f6e-9d5c-4b3a29180709");

    /// <summary>A store that holds one certificate, or none.</summary>
    private sealed class Store(CertificateInfoModel? info) : ICertificateStore
    {
        public Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber)
            => Task.FromResult(serialNumber == Serial ? info : null);
        public Task SaveCertificateAsync(byte[] certificateBytes, CertificateInfoModel info, byte[]? encryptedPrivateKey = null) => throw new NotSupportedException();
        public Task<IEnumerable<CertificateInfoModel>> ListAsync() => throw new NotSupportedException();
        public Task<List<CertificateInfoModel>> GetAllCertificatesAsync() => throw new NotSupportedException();
        public Task<CertificateInfoModel?> GetCertificateByIdAsync(Guid id) => throw new NotSupportedException();
        public Task<CertificateInfoModel?> GetCertificateBySerialNumberAsync(string serialNumber) => throw new NotSupportedException();
        public Task<byte[]?> GetRawCertificateAsync(string serialNumber) => throw new NotSupportedException();
    }

    /// <summary>
    /// Records every revoke it is asked for, by certificate ID and serial. With
    /// <see cref="Vanished"/> set it refuses each as the revocation service refuses a certificate
    /// deleted after the controller looked it up.
    /// </summary>
    private sealed class Recorder : ICertificateRevocationService
    {
        public List<(Guid? Id, string? Serial)> Revoked { get; } = [];

        public bool Vanished { get; init; }

        public Task<RevocationResult> RevokeCertificateAsync(Guid? certificateId, string? certificateSerialNumber, RevocationReason reason, DateTime? invalidityDate = null)
        {
            Revoked.Add((certificateId, certificateSerialNumber));
            if (Vanished)
                throw new ResourceNotFoundException("Certificate", "Certificate not found.", certificateId?.ToString());
            return Task.FromResult(new RevocationResult(Guid.Empty, Serial, "Revoked", reason, DateTime.UtcNow, null));
        }

        [Obsolete("Not used by these tests.")]
        public Task ReissueCertificateAsync(Guid certificateId, DateTime notBefore, DateTime notAfter) => throw new NotSupportedException();
        public Task<RevocationResult> HoldCertificateAsync(Guid? certificateId, string? certificateSerialNumber) => throw new NotSupportedException();
        public Task<RevocationResult> UnholdCertificateAsync(Guid? certificateId, string? certificateSerialNumber) => throw new NotSupportedException();
    }

    /// <summary>Where the certificate is, as the key sees it.</summary>
    public enum Placement
    {
        /// <summary>Issued by a CA of the key's space.</summary>
        InScope,
        /// <summary>Issued by a CA of another space.</summary>
        OtherSpace,
        /// <summary>Issued by an instance CA, outside a space-scoped key.</summary>
        Instance,
        /// <summary>No signing profile, so its space cannot be established.</summary>
        NoSigningProfile,
        /// <summary>No such certificate.</summary>
        Missing,
    }

    /// <summary>
    /// Calls <paramref name="action"/> (<c>GetCertificate</c> or <c>RevokeCertificate</c>) on
    /// <see cref="Serial"/> with a key scoped to <see cref="Space"/>, the certificate placed as
    /// <paramref name="placement"/> and revoked or not.
    /// </summary>
    private static async Task<(IActionResult Result, Recorder Revocations, Guid CertificateId)> CallAsync(
        string action, Placement placement, bool revoked = false, bool vanished = false)
    {
        using var db = InMemoryDbContextFactory.Create();
        var caSpace = placement switch { Placement.OtherSpace => OtherSpace, Placement.Instance => (Guid?)null, _ => Space };
        var ca = new CertificateAuthorityEntity { Name = "CA", Label = "ca", CertificateId = Guid.NewGuid(), SpaceId = caSpace };
        db.CertificateAuthorities.Add(ca);
        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "signing", IssuerId = ca.CertificateId };
        db.SigningProfiles.Add(signing);
        var certificateId = Guid.NewGuid();
        if (placement != Placement.Missing)
        {
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = certificateId,
                SerialNumber = Serial,
                SubjectDN = "CN=device",
                Issuer = "CN=CA",
                Pem = string.Empty,
                RawCertificate = [],
                SigningProfileId = placement == Placement.NoSigningProfile ? null : signing.Id,
                Revoked = revoked,
                RevocationReason = revoked ? nameof(RevocationReason.Superseded) : null,
            });
        }
        await db.SaveChangesAsync();

        var info = placement == Placement.Missing ? null : new CertificateInfoModel
        {
            CertificateId = certificateId,
            SerialNumber = Serial,
            Revoked = revoked,
            RevocationReason = revoked ? nameof(RevocationReason.Superseded) : string.Empty,
        };
        var config = new SystemConfig();
        config.IntegrationApi.SpaceId = Space.ToString();
        var revocations = new Recorder { Vanished = vanished };

        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.InfraController");
        var controller = Activator.CreateInstance(type, null, null, new Store(info), revocations, null, null, null, db, config)!;
        object?[] args = action == "RevokeCertificate" ? [Serial, null] : [Serial];
        var result = await (Task<IActionResult>)type.GetMethod(action)!.Invoke(controller, args)!;
        return (result, revocations, certificateId);
    }

    private static void AssertNotFound(IActionResult result)
    {
        var notFound = Assert.IsType<NotFoundObjectResult>(result);
        Assert.Equal("{\"error\":\"Certificate not found.\"}", System.Text.Json.JsonSerializer.Serialize(notFound.Value));
    }

    [Theory]
    [InlineData(Placement.Missing)]
    [InlineData(Placement.OtherSpace)]
    [InlineData(Placement.Instance)]
    [InlineData(Placement.NoSigningProfile)]
    public async Task Get_answers_a_missing_or_out_of_scope_certificate_with_the_same_404(Placement placement)
        => AssertNotFound((await CallAsync("GetCertificate", placement)).Result);

    [Fact]
    public async Task Get_returns_a_certificate_inside_the_scope()
        => Assert.IsType<OkObjectResult>((await CallAsync("GetCertificate", Placement.InScope)).Result);

    [Theory]
    [InlineData(Placement.Missing, false)]
    [InlineData(Placement.OtherSpace, false)]
    [InlineData(Placement.OtherSpace, true)]
    [InlineData(Placement.Instance, false)]
    [InlineData(Placement.NoSigningProfile, true)]
    public async Task Delete_answers_a_missing_or_out_of_scope_certificate_with_the_same_404_and_revokes_nothing(Placement placement, bool revoked)
    {
        var (result, revocations, _) = await CallAsync("RevokeCertificate", placement, revoked);

        AssertNotFound(result);
        Assert.Empty(revocations.Revoked);
    }

    /// <summary>
    /// The revoke acts on the ID of the certificate the lookup and the scope check found, not on
    /// the serial resolved again.
    /// </summary>
    [Fact]
    public async Task Delete_revokes_a_certificate_inside_the_scope()
    {
        var (result, revocations, certificateId) = await CallAsync("RevokeCertificate", Placement.InScope);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(((Guid?)certificateId, (string?)null), Assert.Single(revocations.Revoked));
    }

    /// <summary>
    /// A certificate deleted between the lookup and the revoke is answered with the same 404 and
    /// body as a missing or out-of-scope one. The revocation service's not-found refusal used to
    /// reach the endpoint's catch-all as a 500.
    /// </summary>
    [Fact]
    public async Task Delete_answers_a_certificate_gone_before_the_revoke_with_the_same_404()
    {
        var (result, revocations, _) = await CallAsync("RevokeCertificate", Placement.InScope, vanished: true);

        AssertNotFound(result);
        Assert.Single(revocations.Revoked);
    }
}
