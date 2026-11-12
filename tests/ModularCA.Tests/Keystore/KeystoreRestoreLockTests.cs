using ModularCA.Keystore.Services;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Signer;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Keystore;

/// <summary>
/// Restoring a keystore file (<see cref="FileKeystorePersistence.ImportKeystoreFile"/>, which
/// backup restore reaches through the signer) is a write like any other: it takes the same
/// per-path lock as <see cref="KeystoreService.AppendEntries"/>, and the file under its own name
/// is replaced in one step, with the previous one kept beside it. Before, a restore took no lock,
/// so it could interleave with a live append, and it moved the live file aside before moving the
/// new one in, leaving a moment with no keystore file at all.
/// </summary>
public sealed class KeystoreRestoreLockTests
{
    /// <summary>
    /// How long a restore that should be waiting is given to finish anyway. On the code before
    /// the fix the restore finishes well inside it; on the fixed code it cannot finish at all
    /// while the lock is held, so the wait cannot pass by luck.
    /// </summary>
    private static readonly TimeSpan GiveItTime = TimeSpan.FromSeconds(2);

    private sealed record Setup(SignerTestWorld World, string LivePath, byte[] Earlier, byte[] Current, FileKeystorePersistence Persistence);

    /// <summary>
    /// A world with real keystore files, whose <c>ca-trust.keystore</c> has been appended to
    /// once: <c>Earlier</c> is the file before the append, as a backup would hold it, and
    /// <c>Current</c> the live file after it. Both verify against the pinned signer.
    /// </summary>
    private static Setup Create()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var files = world.Files!;
        var livePath = files.Path(KeyRef.TrustKeystore);
        var earlier = File.ReadAllBytes(livePath);
        using (var db = world.OpenDb())
        {
            KeystoreService.AppendEntries(livePath, files.YamlPath, KeyRef.TrustKeystore,
                new[] { world["ca-ec"].Certificate.GetEncoded() }, PrivateKeyFactory.CreateKey(world["ca-rsa"].PrivateKeyPkcs8), db);
        }
        var current = File.ReadAllBytes(livePath);
        Assert.NotEqual(earlier, current);
        // The append's own pre-image is not what these tests look for.
        File.Delete(livePath + ".bak");
        return new Setup(world, livePath, earlier, current, new FileKeystorePersistence(files.Directory, files.YamlPath, world.Scopes, world.Keystore));
    }

    private static string[] KeptBeside(string livePath)
        => Directory.GetFiles(Path.GetDirectoryName(livePath)!, Path.GetFileName(livePath) + ".bak.*");

    [Fact]
    public async Task A_restore_waits_for_a_write_holding_the_file_lock()
    {
        var s = Create();
        var fileLock = KeystoreService.GetFileLock(s.LivePath);
        Task restore;
        fileLock.Wait();
        try
        {
            restore = Task.Run(() => s.Persistence.ImportKeystoreFile(KeyRef.TrustKeystore, s.Earlier));

            var finished = await Task.WhenAny(restore, Task.Delay(GiveItTime)) == restore;

            Assert.False(finished, "The restore did not wait for the keystore file lock.");
            Assert.Equal(s.Current, File.ReadAllBytes(s.LivePath));
            Assert.Empty(KeptBeside(s.LivePath));
        }
        finally
        {
            fileLock.Release();
        }

        await restore;
        Assert.Equal(s.Earlier, File.ReadAllBytes(s.LivePath));
        var kept = Assert.Single(KeptBeside(s.LivePath));
        Assert.Equal(s.Current, File.ReadAllBytes(kept));
        Assert.False(File.Exists(s.LivePath + ".restoring"));
    }

    [Fact]
    public async Task Moving_a_file_aside_waits_for_a_write_holding_the_file_lock()
    {
        var s = Create();
        var fileLock = KeystoreService.GetFileLock(s.LivePath);
        Task<string?> move;
        fileLock.Wait();
        try
        {
            move = Task.Run(() => s.Persistence.MoveKeystoreFileAside(KeyRef.TrustKeystore));

            var finished = await Task.WhenAny(move, Task.Delay(GiveItTime)) == move;

            Assert.False(finished, "Moving the keystore file aside did not wait for the keystore file lock.");
            Assert.Equal(s.Current, File.ReadAllBytes(s.LivePath));
        }
        finally
        {
            fileLock.Release();
        }

        var aside = await move;
        Assert.NotNull(aside);
        Assert.False(File.Exists(s.LivePath));
        Assert.Equal(s.Current, File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(s.LivePath)!, aside!)));
    }

    /// <summary>
    /// The lock is the same one an append takes: a path spelled differently but naming the same
    /// file gets the same lock, so a restore and an append cannot both be inside it.
    /// </summary>
    [Fact]
    public void The_lock_is_per_file_whatever_the_spelling()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"mca-lock-{Guid.NewGuid():N}");
        var path = Path.Combine(dir, "ca-trust.keystore");

        Assert.Same(KeystoreService.GetFileLock(path), KeystoreService.GetFileLock(Path.Combine(dir, ".", "ca-trust.keystore")));
        Assert.NotSame(KeystoreService.GetFileLock(path), KeystoreService.GetFileLock(Path.Combine(dir, "ca-certs.keystore")));
    }

    [Fact]
    public void A_restore_over_a_live_file_replaces_it_and_keeps_the_previous_one_beside_it()
    {
        var s = Create();

        s.Persistence.ImportKeystoreFile(KeyRef.TrustKeystore, s.Earlier);

        Assert.Equal(s.Earlier, File.ReadAllBytes(s.LivePath));
        var kept = Assert.Single(KeptBeside(s.LivePath));
        Assert.Equal(s.Current, File.ReadAllBytes(kept));
        Assert.False(File.Exists(s.LivePath + ".restoring"));
    }

    [Fact]
    public void A_restore_that_does_not_verify_leaves_the_live_file_alone()
    {
        var s = Create();
        var tampered = (byte[])s.Earlier.Clone();
        tampered[^1] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() => s.Persistence.ImportKeystoreFile(KeyRef.TrustKeystore, tampered));

        Assert.Equal(s.Current, File.ReadAllBytes(s.LivePath));
        Assert.Empty(KeptBeside(s.LivePath));
        Assert.False(File.Exists(s.LivePath + ".restoring"));
    }
}
