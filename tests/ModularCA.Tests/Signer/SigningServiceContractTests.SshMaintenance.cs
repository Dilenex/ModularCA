using ModularCA.Keystore;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// What stage 4 of <c>docs/architecture/ssh-keystore.md</c> adds around the SSH keystore file:
/// a restore of a state that has none moves a live one aside, a restore never puts one back
/// without its <c>Keystores</c> row, a creation that stops half way never leaves the file
/// without its row, and the break-glass tool opens it. Over real keystore files, on both bindings.
/// </summary>
public abstract partial class SigningServiceContractTests
{
    private static readonly SigningContext RestoreContext = new(Caller, SigningPurpose.Restore, null, null);

    /// <summary>What a restore offers when its archive carries no SSH keystore.</summary>
    private static KeyMaterial SshKeystoreAbsent(string keystore = KeyRef.SshKeystore, byte[]? bytes = null, Guid? certificateId = null)
        => new(bytes ?? [], KeyMaterial.KeystoreFileAbsent, certificateId ?? Guid.Empty, keystore);

    private static void RemoveSshKeystoreRow(SignerTestWorld world)
    {
        using var db = world.OpenDb();
        db.Keystores.Remove(db.Keystores.Single(k => k.Name == KeyRef.SshKeystore));
        db.SaveChanges();
    }

    private static string[] FilesNamed(SignerTestWorld world, string prefix)
        => Directory.GetFiles(world.Files!.Directory, prefix + "*").Select(Path.GetFileName).OrderBy(n => n, StringComparer.Ordinal).ToArray()!;

    [Fact]
    public async Task A_restore_of_a_state_without_an_ssh_keystore_moves_a_live_one_aside_only_when_the_database_has_no_row_for_it()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var sshPath = world.Files!.Path(KeyRef.SshKeystore);
        var (_, caId, keyId, _) = await CommitSshKeyAsync(world, signer);
        var live = File.ReadAllBytes(sshPath);
        var certs = File.ReadAllBytes(world.Files.Path(KeyRef.DefaultKeystore));

        // A keystore the database knows is never moved aside, whoever asks and however.
        await RefusedAsync(SigningRefusalReason.OperationUnsupported, () => signer.ImportKeyAsync(SshKeystoreAbsent(), RestoreContext), "move aside a keystore that has its row");
        Assert.Equal(live, File.ReadAllBytes(sshPath));

        // The database is replaced by one from before the first SSH CA key: no Keystores row for the file.
        RemoveSshKeystoreRow(world);
        Assert.Throws<InvalidOperationException>(() => world.Restart());

        // Only a restore says so, only of the SSH keystore, with no bytes and no certificate.
        foreach (var purpose in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Restore))
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                () => signer.ImportKeyAsync(SshKeystoreAbsent(), new SigningContext(Caller, purpose, null, null)), $"declare the SSH keystore absent under {purpose}");
        await RefusedAsync(SigningRefusalReason.ContextRequired,
            () => signer.ImportKeyAsync(SshKeystoreAbsent(), new SigningContext("", SigningPurpose.Restore, null, null)), "declare it absent for no named caller");
        foreach (var other in new[] { KeyRef.DefaultKeystore, KeyRef.TrustKeystore, "other.keystore" })
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted, () => signer.ImportKeyAsync(SshKeystoreAbsent(other), RestoreContext), $"declare {other} absent");
        await RefusedAsync(SigningRefusalReason.OperationUnsupported, () => signer.ImportKeyAsync(SshKeystoreAbsent(bytes: [1, 2, 3]), RestoreContext), "declare it absent with bytes");
        await RefusedAsync(SigningRefusalReason.OperationUnsupported, () => signer.ImportKeyAsync(SshKeystoreAbsent(certificateId: keyId), RestoreContext), "declare a key absent");
        Assert.Equal(live, File.ReadAllBytes(sshPath));
        Assert.Equal(new[] { KeyRef.SshKeystore }, FilesNamed(world, KeyRef.SshKeystore));

        // The restore's own call: the file is moved aside whole, nothing else is touched.
        var answered = await signer.ImportKeyAsync(SshKeystoreAbsent(), RestoreContext);

        Assert.Equal(KeyRef.ForKeystore(KeyRef.SshKeystore), answered);
        Assert.False(File.Exists(sshPath));
        var aside = Assert.Single(FilesNamed(world, KeyRef.SshKeystore));
        Assert.StartsWith(KeyRef.SshKeystore + ".bak.", aside);
        Assert.Equal(live, File.ReadAllBytes(world.Files.Path(aside)));
        Assert.Equal(certs, File.ReadAllBytes(world.Files.Path(KeyRef.DefaultKeystore)));

        // With the file out of the way the signer unlocks again, holding no SSH key, and a backup has no SSH keystore to take.
        var restarted = world.Restart();
        Assert.True(restarted.Files!.Bootstrap.Unlocked);
        var second = await CreateSignerAsync(restarted);
        Assert.Empty(await ListedSshKeysAsync(second));
        await RefusedAsync(SigningRefusalReason.UnknownKey,
            () => second.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.SshKeystore), ExportWrap.ForKeystoreFile(), new SigningContext(Caller, SigningPurpose.Backup, null, null)), "export the keystore moved aside");

        // Said again with nothing there, it is allowed and does nothing.
        await second.ImportKeyAsync(SshKeystoreAbsent(), RestoreContext);
        Assert.Single(FilesNamed(restarted, KeyRef.SshKeystore));

        // Both decisions are in the signer's audit: the refusal with its reason, the move with where the file went.
        var rows = (await ReadAuditAsync(world)).Where(r => r.Operation == "ImportKey" && r.Keystore == KeyRef.SshKeystore && r.Purpose == "Restore").ToList();
        Assert.Contains(rows, r => r.Outcome == SignerAuditEntity.RefusedOutcome && r.Reason!.Contains("has a Keystores row"));
        Assert.Contains(rows, r => r.Outcome == SignerAuditEntity.AllowedOutcome && r.Reason!.Contains(aside));
        _ = caId;
    }

    [Fact]
    public async Task An_ssh_keystore_file_is_not_restored_into_a_database_that_has_no_row_for_it()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var sshPath = world.Files!.Path(KeyRef.SshKeystore);
        await CommitSshKeyAsync(world, signer);
        var file = File.ReadAllBytes(sshPath);

        // With its row, the file goes back; that is the order a restore keeps: the database first.
        await signer.ImportKeyAsync(new KeyMaterial((byte[])file.Clone(), KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.SshKeystore), RestoreContext);
        Assert.Equal(file, File.ReadAllBytes(sshPath));

        // Without its row it has no pin to be verified against, and it is refused rather than verified against anything else.
        RemoveSshKeystoreRow(world);
        File.Delete(sshPath);
        foreach (var bak in FilesNamed(world, KeyRef.SshKeystore + ".bak."))
            File.Delete(world.Files.Path(bak));

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ImportKeyAsync(new KeyMaterial((byte[])file.Clone(), KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.SshKeystore), RestoreContext));

        Assert.Equal(SigningRefusalReason.IntegrityFailure, ex.Reason);
        Assert.Contains("no Keystores row", ex.Message);
        Assert.Empty(FilesNamed(world, KeyRef.SshKeystore));
        // The other two files are still restored as they always were.
        var certs = File.ReadAllBytes(world.Files.Path(KeyRef.DefaultKeystore));
        await signer.ImportKeyAsync(new KeyMaterial((byte[])certs.Clone(), KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.DefaultKeystore), RestoreContext);
        Assert.True(world.Restart().Files!.Bootstrap.Unlocked);
    }

    /// <summary>
    /// The first SSH key writes the file beside its place and names it only once the row is in
    /// the database. A stop before the row leaves a staged file nothing loads; a stop after it
    /// is finished by the next unlock, or by the next write. Neither leaves the signer locked.
    /// </summary>
    [Theory]
    [InlineData("the next unlock")]
    [InlineData("the next write")]
    public async Task A_first_ssh_key_write_that_stopped_half_way_never_leaves_the_signer_locked(string finishedBy)
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var sshPath = world.Files!.Path(KeyRef.SshKeystore);
        var staged = sshPath + KeystoreService.CreatingSuffix;
        var (_, _, firstKey, _) = await CommitSshKeyAsync(world, signer);
        Assert.False(File.Exists(staged), "A finished creation leaves no staged file.");

        // Stopped after the row was written and before the file took its name: the row, and the staged file.
        File.Move(sshPath, staged);

        if (finishedBy == "the next unlock")
        {
            var restarted = world.Restart();
            Assert.True(restarted.Files!.Bootstrap.Unlocked);
            Assert.True(File.Exists(sshPath));
            Assert.False(File.Exists(staged));
            Assert.Equal(firstKey, Assert.Single(await ListedSshKeysAsync(await CreateSignerAsync(restarted))).Key);
        }
        else
        {
            // The running signer commits another key: the staged file is put in place and the key appended to it.
            var (_, _, secondKey, _) = await CommitSshKeyAsync(world, signer, "ECDSA", "P-256");
            Assert.True(File.Exists(sshPath));
            Assert.False(File.Exists(staged));
            var listed = await ListedSshKeysAsync(await CreateSignerAsync(world.Restart()));
            Assert.Equal(new[] { firstKey, secondKey }.OrderBy(id => id), listed.Keys.OrderBy(id => id));
        }

        // Stopped before the row was written: a staged file and no row. Nothing loads it, the
        // signer unlocks without an SSH keystore, and the next first key starts over it.
        File.Move(sshPath, staged);
        RemoveSshKeystoreRow(world);
        var fresh = world.Restart();
        Assert.True(fresh.Files!.Bootstrap.Unlocked);
        var freshSigner = await CreateSignerAsync(fresh);
        Assert.Empty(await ListedSshKeysAsync(freshSigner));
        Assert.False(File.Exists(sshPath));

        var (_, _, newKey, _) = await CommitSshKeyAsync(fresh, freshSigner, "ECDSA", "P-384");
        Assert.True(File.Exists(sshPath));
        Assert.False(File.Exists(staged));
        Assert.Equal(newKey, Assert.Single(await ListedSshKeysAsync(await CreateSignerAsync(fresh.Restart()))).Key);
    }

    /// <summary>
    /// The break-glass tool against the SSH keystore. Nobody was ever shown its main passphrase:
    /// the signer generated it, and it is kept only in the keystore's row, wrapped under the
    /// secondary passphrase. The tool reads it from there, where it asks for the other two.
    /// </summary>
    [Fact]
    public async Task The_break_glass_tool_opens_the_ssh_keystore_with_the_main_passphrase_its_row_holds()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var (generated, _, _, _) = await CommitSshKeyAsync(world, signer, "ECDSA", "P-256");
        var sshPath = world.Files!.Path(KeyRef.SshKeystore);

        Assert.True(Unlocker.HasSignerGeneratedMainPassphrase(sshPath));
        Assert.True(Unlocker.HasSignerGeneratedMainPassphrase(KeyRef.SshKeystore));
        Assert.False(Unlocker.HasSignerGeneratedMainPassphrase(world.Files.Path(KeyRef.DefaultKeystore)));
        Assert.False(Unlocker.HasSignerGeneratedMainPassphrase(world.Files.Path(KeyRef.TrustKeystore)));

        // What the tool does for it: the passphrase from the row, the pin verified, every entry decrypted and verified.
        using var db = world.OpenDb();
        var secondary = ModularCA.Keystore.Config.KeystoreYamlLoader.LoadSecondaryPassphrase(world.Files.YamlPath, KeyRef.SshKeystore);
        var keystore = KeystoreFileParser.Parse(sshPath);
        var pinned = KeystoreService.LoadVerifiedPinnedSpki(db, KeyRef.SshKeystore, secondary);
        KeystoreService.VerifyKeystoreFileSignature(keystore, db, pinned);
        var main = KeystoreDbPassphraseLoader.RetrieveFromDatabase(db, KeyRef.SshKeystore, secondary);
        var key = ScryptKeyDeriver.DeriveFileKey(main, secondary, keystore);

        var entries = new List<byte[]>();
        KeystoreService.DecryptEntries(keystore, key, db, pinned, verifyEntrySignatures: true, (_, plaintext) => entries.Add(plaintext.ToArray()));

        var recovered = PrivateKeyFactory.CreateKey(Assert.Single(entries));
        Assert.Equal(SshKeyOf(generated.PublicKeyDer), SshPublicKey.FromKeyParameter(PublicOf(recovered)));

        // A passphrase an operator could type is not it, which is why the tool does not ask.
        var typed = ScryptKeyDeriver.DeriveFileKey("main-passphrase-an-operator-knows", secondary, keystore);
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
            KeystoreService.DecryptEntries(keystore, typed, db, pinned, verifyEntrySignatures: true, (_, _) => { }));
    }
}
