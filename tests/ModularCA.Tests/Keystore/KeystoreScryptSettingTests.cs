using Microsoft.EntityFrameworkCore;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Signer;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Keystore;

/// <summary>
/// The scrypt cost a keystore write uses comes from the security policy. scrypt needs N to be a
/// power of two; a value that is not one used to be accepted on save, and every keystore write
/// after it failed inside scrypt with a message that named neither the setting nor the fix.
/// </summary>
public sealed class KeystoreScryptSettingTests
{
    [Theory]
    [InlineData(30000)]
    [InlineData(65535)]
    [InlineData(100000)]
    public void A_target_n_that_is_not_a_power_of_two_is_refused_when_it_is_set(int n)
    {
        using var service = new KeystoreService(Path.Combine(Path.GetTempPath(), $"unused-{Guid.NewGuid():N}.keystore"), "main", "secondary", null!);

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => service.SetTargetScryptParams(n, 8, 1));

        Assert.Contains("power of two", ex.Message);
    }

    [Fact]
    public void A_stored_n_that_is_not_a_power_of_two_fails_the_write_saying_which_setting_and_nothing_is_written()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var files = world.Files!;
        var path = files.Path(KeyRef.TrustKeystore);
        var before = File.ReadAllBytes(path);
        using var db = world.OpenDb();
        db.SecurityPolicies.Single().KeystoreScryptN = 30000;
        db.SaveChanges();
        var signer = PrivateKeyFactory.CreateKey(world["ca-rsa"].PrivateKeyPkcs8);

        var ex = Assert.Throws<InvalidOperationException>(() => KeystoreService.AppendEntries(
            path, files.YamlPath, KeyRef.TrustKeystore, new[] { world["ca-ec"].Certificate.GetEncoded() }, signer, db));

        Assert.Contains("KeystoreScryptN", ex.Message);
        Assert.Contains("30000", ex.Message);
        Assert.Equal(before, File.ReadAllBytes(path));
    }

    [Fact]
    public void A_stored_power_of_two_n_is_written_into_the_file()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var files = world.Files!;
        var path = files.Path(KeyRef.TrustKeystore);
        using var db = world.OpenDb();
        db.SecurityPolicies.Single().KeystoreScryptN = 1 << 15;
        db.SaveChanges();
        var signer = PrivateKeyFactory.CreateKey(world["ca-rsa"].PrivateKeyPkcs8);

        KeystoreService.AppendEntries(path, files.YamlPath, KeyRef.TrustKeystore, new[] { world["ca-ec"].Certificate.GetEncoded() }, signer, db);

        Assert.Equal(1 << 15, KeystoreFileParser.Parse(path).ScryptN);
        Assert.Equal(1 << 15, db.SecurityPolicies.AsNoTracking().Single().KeystoreScryptN);
    }

    /// <summary>
    /// The 1 GiB ceiling is on setting a cost, not on reading one. A file written under a larger
    /// setting from before the ceiling, here N = 2^20 with r = 32 (4 GiB), still parses, so its
    /// keys still open on a host that can afford the derivation. The header is patched rather
    /// than written for real, which would take a 4 GiB derivation.
    /// </summary>
    [Fact]
    public void A_file_written_above_the_ceiling_still_parses()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mca-scrypt-ceiling-{Guid.NewGuid():N}.keystore");
        try
        {
            var signer = TestUtils.TestCaMaterial.CreateCa("CN=Scrypt Ceiling Test, O=ModularCA");
            using (var service = new KeystoreService(path, "main", "secondary", signer.KeyPair.Private))
            {
                service.SetTargetScryptParams(1 << 14, 8, 1);
                service.AddEntry(new byte[] { 1, 2, 3 }, "secondary");
                service.Save();
            }
            // Magic (8) + salt length (2) + salt (16), then N, r and p as little-endian int32.
            var bytes = File.ReadAllBytes(path);
            Assert.Equal(16, BitConverter.ToUInt16(bytes, 8));
            BitConverter.GetBytes(1 << 20).CopyTo(bytes, 26);
            BitConverter.GetBytes(32).CopyTo(bytes, 30);
            File.WriteAllBytes(path, bytes);

            var parsed = KeystoreFileParser.Parse(path);

            Assert.Equal((1 << 20, 32, 1), (parsed.ScryptN, parsed.ScryptR, parsed.ScryptP));
            Assert.True(ModularCA.Shared.Utils.KeystoreScryptPolicy.ExceedsMemoryCeiling(parsed.ScryptN, parsed.ScryptR));
        }
        finally
        {
            foreach (var f in new[] { path, path + ".bak", path + ".tmp" })
                try { File.Delete(f); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// A stored setting above the ceiling, saved before it existed, is still the cost a write
    /// uses: an install keeps the cost it chose rather than having it lowered behind its back.
    /// </summary>
    [Fact]
    public void A_stored_cost_above_the_ceiling_is_still_accepted_for_a_write()
    {
        using var service = new KeystoreService(Path.Combine(Path.GetTempPath(), $"unused-{Guid.NewGuid():N}.keystore"), "main", "secondary", null!);

        service.SetTargetScryptParams(1 << 20, 32, 1);
    }
}
