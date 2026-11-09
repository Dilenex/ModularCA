using Microsoft.AspNetCore.Mvc;
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
/// The infrastructure API's revoke takes a reason by its RFC 5280 name only. It parsed the reason
/// with <c>Enum.TryParse</c>, which also accepts a number ("1", "8", "99") and a comma list
/// ("KeyCompromise,CACompromise", whose values it ORs together), so a client could store a code
/// RFC 5280 does not define, or a different reason from the one it named.
/// </summary>
public class InfraRevokeReasonTests
{
    private const string Serial = "0A:1B";

    /// <summary>A store that holds one live certificate.</summary>
    private sealed class OneCertificate : ICertificateStore
    {
        private readonly CertificateInfoModel _info = new() { CertificateId = Guid.NewGuid(), SerialNumber = Serial };
        public Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber)
            => Task.FromResult<CertificateInfoModel?>(serialNumber == Serial ? _info : null);
        public Task SaveCertificateAsync(byte[] certificateBytes, CertificateInfoModel info, byte[]? encryptedPrivateKey = null) => throw new NotSupportedException();
        public Task<IEnumerable<CertificateInfoModel>> ListAsync() => throw new NotSupportedException();
        public Task<List<CertificateInfoModel>> GetAllCertificatesAsync() => throw new NotSupportedException();
        public Task<CertificateInfoModel?> GetCertificateByIdAsync(Guid id) => throw new NotSupportedException();
        public Task<CertificateInfoModel?> GetCertificateBySerialNumberAsync(string serialNumber) => throw new NotSupportedException();
        public Task<byte[]?> GetRawCertificateAsync(string serialNumber) => throw new NotSupportedException();
    }

    /// <summary>Records the reasons it is asked to revoke with.</summary>
    private sealed class Recorder : ICertificateRevocationService
    {
        public List<RevocationReason> Revoked { get; } = [];

        public Task<RevocationResult> RevokeCertificateAsync(Guid? certificateId, string? certificateSerialNumber, RevocationReason reason, DateTime? invalidityDate = null)
        {
            Revoked.Add(reason);
            return Task.FromResult(new RevocationResult(Guid.Empty, Serial, "Revoked", reason, DateTime.UtcNow, null));
        }

        [Obsolete("Not used by these tests.")]
        public Task ReissueCertificateAsync(Guid certificateId, DateTime notBefore, DateTime notAfter) => throw new NotSupportedException();
        public Task<RevocationResult> HoldCertificateAsync(Guid? certificateId, string? certificateSerialNumber) => throw new NotSupportedException();
        public Task<RevocationResult> UnholdCertificateAsync(Guid? certificateId, string? certificateSerialNumber) => throw new NotSupportedException();
    }

    private static async Task<(IActionResult Result, Recorder Revocations)> RevokeAsync(string? reason)
    {
        using var db = InMemoryDbContextFactory.Create();
        var revocations = new Recorder();
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.InfraController");
        var requestType = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.InfraRevokeCertificateRequest");
        var request = Activator.CreateInstance(requestType)!;
        requestType.GetProperty("Reason")!.SetValue(request, reason);
        var controller = Activator.CreateInstance(type, null, null, new OneCertificate(), revocations, null, null, null, db, new SystemConfig())!;
        var result = await (Task<IActionResult>)type.GetMethod("RevokeCertificate")!.Invoke(controller, [Serial, request])!;
        return (result, revocations);
    }

    /// <summary>Numbers, undefined codes, comma lists and unknown names are refused with 400 and nothing is revoked.</summary>
    [Theory]
    [InlineData("1")]
    [InlineData("0")]
    [InlineData("7")]
    [InlineData("8")]
    [InlineData("99")]
    [InlineData("-1")]
    [InlineData("KeyCompromise,CACompromise")]
    [InlineData("KeyCompromise, Superseded")]
    [InlineData("removeFromCRL")]
    [InlineData("compromised")]
    public async Task A_reason_that_is_not_a_defined_name_is_refused(string reason)
    {
        var (result, revocations) = await RevokeAsync(reason);

        var refused = Assert.IsType<BadRequestObjectResult>(result);
        using var json = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(refused.Value));
        Assert.Equal(ErrorCodes.RequestInvalid, json.RootElement.GetProperty("code").GetString());
        Assert.Contains("keyCompromise", json.RootElement.GetProperty("error").GetString());
        Assert.Empty(revocations.Revoked);
    }

    /// <summary>Each defined name is accepted, in RFC 5280 camelCase or in any case, and an omitted reason is unspecified.</summary>
    [Theory]
    [InlineData("keyCompromise", RevocationReason.KeyCompromise)]
    [InlineData("KEYCOMPROMISE", RevocationReason.KeyCompromise)]
    [InlineData("cACompromise", RevocationReason.CACompromise)]
    [InlineData("affiliationChanged", RevocationReason.AffiliationChanged)]
    [InlineData("superseded", RevocationReason.Superseded)]
    [InlineData("cessationOfOperation", RevocationReason.CessationOfOperation)]
    [InlineData("certificateHold", RevocationReason.CertificateHold)]
    [InlineData("privilegeWithdrawn", RevocationReason.PrivilegeWithdrawn)]
    [InlineData("aACompromise", RevocationReason.AaCompromise)]
    [InlineData(" unspecified ", RevocationReason.Unspecified)]
    [InlineData(null, RevocationReason.Unspecified)]
    [InlineData("", RevocationReason.Unspecified)]
    public async Task A_defined_reason_name_is_accepted(string? reason, RevocationReason expected)
    {
        var (result, revocations) = await RevokeAsync(reason);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal([expected], revocations.Revoked);
    }
}
