using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Shared.Entities;

/// <summary>
/// Pins the single definition of "PFX export will work".
/// <para>
/// The user portal gated its Export PFX button on <c>encryptedPrivateKey</c> appearing in the
/// list response. No read mapping populates that field — correctly, since wrapped key material
/// must not be shipped to a browser — so the button rendered for nobody and PFX export was
/// unreachable through the UI even for certificates whose key the CA holds.
/// </para>
/// <para>
/// The fix is a boolean computed from this predicate, which
/// <c>CertificateExportService.ExportPfxAsync</c> also consults. They must agree: a button that
/// offers an export the service refuses is as bad as a button that never appears.
/// </para>
/// </summary>
public class ExportablePrivateKeyTests
{
    private static CertificateEntity Cert(byte[]? key, byte[]? iv, byte[]? wrappedAes) => new()
    {
        EncryptedPrivateKey = key,
        AesKeyEncryptionIv = iv,
        EncryptedAesForPrivateKey = wrappedAes,
    };

    private static readonly byte[] Some = [1, 2, 3];

    [Fact]
    public void All_three_wrapping_components_present_means_exportable()
    {
        Assert.True(Cert(Some, Some, Some).HasExportablePrivateKey());
    }

    [Fact]
    public void A_certificate_with_no_stored_key_is_not_exportable()
    {
        // The CSR-upload flow: the requester kept the key, the CA never had it.
        Assert.False(Cert(null, null, null).HasExportablePrivateKey());
    }

    [Theory]
    [InlineData(false, true, true)]   // key missing
    [InlineData(true, false, true)]   // iv missing
    [InlineData(true, true, false)]   // wrapped AES key missing
    public void A_partial_wrapping_set_is_not_exportable(bool hasKey, bool hasIv, bool hasWrappedAes)
    {
        // Unwrapping needs all three. Reporting "exportable" on a partial set would show the
        // button and then fail at download time with a 404.
        var entity = Cert(hasKey ? Some : null, hasIv ? Some : null, hasWrappedAes ? Some : null);

        Assert.False(entity.HasExportablePrivateKey());
    }
}
