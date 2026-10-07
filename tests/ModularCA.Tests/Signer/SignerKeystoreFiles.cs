using Microsoft.EntityFrameworkCore;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using Org.BouncyCastle.Security;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The keystore files of a signer test world, real ones: written the way the bootstrap writes
/// them, with their <c>Keystores</c> rows in the world's database and their secondary
/// passphrases in a <c>keystore.yaml</c> beside them, then unlocked through
/// <see cref="SignerBootstrap"/>. The tests that have to see a file appear, survive a restart
/// or fail to verify run over these.
/// </summary>
internal sealed class SignerKeystoreFiles
{
    /// <summary>The secondary passphrase of <c>ca-certs.keystore</c>, which <c>ssh-ca.keystore</c> shares.</summary>
    public const string CertsSecondary = "secondary-of-the-ca-certs-keystore";

    /// <summary>The secondary passphrase of <c>ca-trust.keystore</c>: a different one, so sharing the wrong one fails.</summary>
    public const string TrustSecondary = "secondary-of-the-ca-trust-keystore";

    private SignerKeystoreFiles(string directory, SignerBootstrap bootstrap)
    {
        Directory = directory;
        Bootstrap = bootstrap;
    }

    /// <summary>The directory holding the keystore files.</summary>
    public string Directory { get; }

    /// <summary>The keystore configuration file, with one line for each of the two bootstrap keystores.</summary>
    public string YamlPath => System.IO.Path.Combine(Directory, "keystore.yaml");

    /// <summary>The unlocked keystores.</summary>
    public SignerBootstrap Bootstrap { get; }

    /// <summary>The path of a keystore file by name.</summary>
    public string Path(string keystore) => System.IO.Path.Combine(Directory, keystore);

    /// <summary>Writes the two bootstrap keystores for the world's held keys, signed by <c>ca-rsa</c>, and unlocks them.</summary>
    public static SignerKeystoreFiles Write(SignerTestWorld world)
    {
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"mca-signer-keystores-{Guid.NewGuid():N}");
        System.IO.Directory.CreateDirectory(directory);
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { System.IO.Directory.Delete(directory, recursive: true); } catch { }
        };
        File.WriteAllLines(System.IO.Path.Combine(directory, "keystore.yaml"),
        [
            $"{KeyRef.DefaultKeystore}: {CertsSecondary}",
            $"{KeyRef.TrustKeystore}: {TrustSecondary}",
        ]);

        var systemSigner = world["ca-rsa"];
        var signerKey = PrivateKeyFactory.CreateKey(systemSigner.PrivateKeyPkcs8);
        var pin = KeystoreService.ComputeSpkiSha256Hex(systemSigner.Certificate);
        var held = world.HeldKeys.ToList();
        using var db = world.OpenDb();
        // The instance waives key ceremonies, and keystores are written at the lowest scrypt
        // cost the policy allows: these tests are about the files, not the cost of deriving a key.
        db.SecurityPolicies.Add(new ModularCA.Shared.Entities.SecurityPolicyEntity { RequireKeyCeremony = false, KeystoreScryptN = 1 << 14 });
        db.SaveChanges();
        WriteKeystore(KeyRef.DefaultKeystore, CertsSecondary, held.Select(k => k.PrivateKeyPkcs8));
        WriteKeystore(KeyRef.TrustKeystore, TrustSecondary, held.Select(k => k.Certificate.GetEncoded()));
        return new SignerKeystoreFiles(directory, Unlock(world, directory));

        void WriteKeystore(string name, string secondary, IEnumerable<byte[]> entries)
        {
            var main = $"main-passphrase-of-{name}-{Guid.NewGuid():N}";
            using var service = new KeystoreService(System.IO.Path.Combine(directory, name), main, secondary, signerKey);
            service.SetTargetScryptParams(1 << 14, 8, 1);
            foreach (var entry in entries)
                service.AddEntry((byte[])entry.Clone(), secondary);
            BootstrapKeystoreWriter.WriteKeystoreFile(service, name, main, secondary, db, pin);
        }
    }

    /// <summary>Unlocks the same files again, as a restarted signer would.</summary>
    public SignerKeystoreFiles Reopen(SignerTestWorld world) => new(Directory, Unlock(world, Directory));

    private static SignerBootstrap Unlock(SignerTestWorld world, string directory)
        => SignerBootstrap.Unlock(System.IO.Path.Combine(directory, "keystore.yaml"), directory, Options(world));

    /// <summary>The options of a context over the world's in-memory database.</summary>
    private static DbContextOptions<ModularCADbContext> Options(SignerTestWorld world) => new DbContextOptionsBuilder<ModularCADbContext>()
        .UseInMemoryDatabase(world.DatabaseName)
        .ConfigureWarnings(w => w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning))
        .Options;
}
