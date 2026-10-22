using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Ssh;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// What the readiness page, the admin key list and the plaintext notice read
/// (<c>docs/architecture/ssh-keystore.md</c>, stage 4): where every SSH CA key is, why a key is
/// not held, and which keys were plaintext files before the signer took them.
/// </summary>
public class SshKeyCustodyTests
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task Each_key_is_held_awaiting_import_with_its_reason_or_recorded_as_the_signers_while_the_signer_lists_none()
    {
        using var install = new LegacySshInstall();
        var imported = install.Seed("A Imported", "ed25519");
        var encrypted = install.Seed("B Not A Key", "p256");
        File.WriteAllText(install.FileOf(encrypted), "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90IGEga2V5\n-----END OPENSSH PRIVATE KEY-----\n");
        var missing = install.Seed("C Missing", "p384", writeFile: false);
        await install.Import().RunAsync();
        // A key the signer generated and holds, and one whose creation stopped between its rows and the commit of its key.
        var created = await install.Node.CreateCaAsync("D Created");
        var uncommitted = Guid.NewGuid();
        using (var db = install.Node.Reopen())
        {
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "E Uncommitted", Label = "e-uncommitted", Type = "SSH", IsSshCa = true, IsEnabled = true };
            db.CertificateAuthorities.Add(ca);
            db.SshCaKeys.Add(new SshCaKeyEntity
            {
                Id = uncommitted, Name = "E Uncommitted", KeyType = "ed25519", CertificateAuthorityId = ca.Id,
                PublicKey = SshFixtures.Text("ca-p521.pub").Trim(), KeyStorage = SshCaKeyStorage.Signer, IsUserCa = true, MaxValidityHours = 24,
            });
            db.SaveChanges();
        }

        using var read = install.Node.Reopen();
        var report = await SshKeyCustody.ReadAsync(read, install.Node.Relay, install.State);

        Assert.True(report.SignerUnlocked && report.SignerListed);
        var states = report.Keys.ToDictionary(k => k.Id);
        Assert.Equal(5, states.Count);
        Assert.Equal(SshKeyCustody.Held, states[imported.Id].State);
        Assert.NotNull(states[imported.Id].ImportedAt);
        Assert.Null(states[imported.Id].ReasonCode);
        Assert.Equal(SshKeyCustody.Held, states[created.Id].State);
        Assert.Null(states[created.Id].ImportedAt);

        Assert.Equal(SshKeyCustody.AwaitingImport, states[encrypted.Id].State);
        Assert.Equal(SshKeyImportReasons.FileNotAKey, states[encrypted.Id].ReasonCode);
        Assert.Equal(install.FileOf(encrypted), states[encrypted.Id].KeyFile);
        Assert.Contains(install.FileOf(encrypted), states[encrypted.Id].Detail);
        Assert.Equal(SshKeyImportReasons.FileMissing, states[missing.Id].ReasonCode);
        Assert.Contains(install.FileOf(missing), states[missing.Id].Detail);

        Assert.Equal(SshKeyCustody.NotHeld, states[uncommitted].State);
        Assert.Equal(SshKeyCustody.SignerHoldsNoKey, states[uncommitted].ReasonCode);
        Assert.Contains("signs nothing", states[uncommitted].Reason);

        Assert.Equal(2, report.Held);
        Assert.Equal(new[] { encrypted.Id, missing.Id }, report.AwaitingImport.Select(k => k.Id));
        Assert.Equal(new[] { uncommitted }, report.NotHeld.Select(k => k.Id));

        // What the readiness page gets: counts, ids, names, codes and fixed sentences. No path, and nothing a file or the signer said.
        var readiness = report.ToReadiness();
        Assert.Equal((5, 2, 0), (readiness.Total, readiness.Held, readiness.Unknown));
        Assert.Equal(new[] { (encrypted.Id, "B Not A Key", SshKeyImportReasons.FileNotAKey), (missing.Id, "C Missing", SshKeyImportReasons.FileMissing) },
            readiness.AwaitingImport.Select(k => (k.Id, k.Name, k.ReasonCode)));
        Assert.Equal((uncommitted, SshKeyCustody.SignerHoldsNoKey), (Assert.Single(readiness.NotHeld).Id, readiness.NotHeld[0].ReasonCode));
        var json = JsonSerializer.Serialize(readiness, Web);
        Assert.DoesNotContain(Path.GetFileName(install.BaseDirectory), json);
        Assert.DoesNotContain("ssh-ca-keys", json);
        Assert.DoesNotContain(encrypted.Id.ToString() + ".pub", json);
        using var parsed = JsonDocument.Parse(json);
        Assert.Equal(new[] { "total", "held", "awaitingImport", "notHeld", "unknown" }, parsed.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(new[] { "id", "name", "reasonCode", "reason" }, parsed.RootElement.GetProperty("awaitingImport")[0].EnumerateObject().Select(p => p.Name));
        Assert.All(readiness.AwaitingImport, k => Assert.Equal(SshKeyImportReasons.Sentence(k.ReasonCode), k.Reason));
    }

    [Fact]
    public async Task With_the_signer_locked_or_not_answering_no_key_is_called_missing_and_legacy_keys_still_show_as_awaiting_import()
    {
        using var install = new LegacySshInstall();
        var legacy = install.Seed("A Legacy");
        var created = await install.Node.CreateCaAsync("B Created");

        using var read = install.Node.Reopen();
        var locked = await SshKeyCustody.ReadAsync(read, install.LockedSigner(), imports: null);

        Assert.False(locked.SignerUnlocked);
        Assert.False(locked.SignerListed);
        Assert.Equal(SshKeyCustody.Unknown, locked.Keys.Single(k => k.Id == created.Id).State);
        Assert.Empty(locked.NotHeld);
        // No import has run in this process (a node without the control role): the key awaits import, the reason says who imports.
        var awaiting = Assert.Single(locked.AwaitingImport);
        Assert.Equal((legacy.Id, SshKeyImportReasons.NotAttempted), (awaiting.Id, awaiting.ReasonCode));
        Assert.Contains("control role", awaiting.Reason);
        Assert.Equal((2, 0, 1), (locked.ToReadiness().Total, locked.ToReadiness().Held, locked.ToReadiness().Unknown));

        // A signer whose list cannot be read is not taken for one that holds nothing.
        install.Node.Relay.RewriteListed = _ => throw new InvalidOperationException("The list failed.");
        var unlisted = await SshKeyCustody.ReadAsync(read, install.Node.Relay, install.State);
        Assert.True(unlisted.SignerUnlocked);
        Assert.False(unlisted.SignerListed);
        Assert.Empty(unlisted.NotHeld);
        Assert.Equal(SshKeyCustody.Unknown, unlisted.Keys.Single(k => k.Id == created.Id).State);
    }

    [Fact]
    public async Task An_install_with_no_ssh_ca_reports_nothing_and_asks_the_signer_nothing()
    {
        using var node = new SshNode();
        var report = await SshKeyCustody.ReadAsync(node.Db, new UnaskedSigner(), null);

        Assert.Empty(report.Keys);
        Assert.Equal((0, 0), (report.ToReadiness().Total, report.ToReadiness().Held));
    }

    [Fact]
    public async Task A_row_rewritten_to_another_key_than_the_signer_holds_for_it_is_not_reported_as_held()
    {
        using var install = new LegacySshInstall();
        var key = await install.Node.CreateCaAsync("Fleet SSH");
        using (var db = install.Node.Reopen())
        {
            db.SshCaKeys.Single(k => k.Id == key.Id).PublicKey = SshFixtures.Text("ca-ed25519.pub").Trim();
            db.SaveChanges();
        }

        using var read = install.Node.Reopen();
        var report = await SshKeyCustody.ReadAsync(read, install.Node.Relay, install.State);

        Assert.Equal(SshKeyCustody.NotHeld, Assert.Single(report.Keys).State);
    }

    // ---- The plaintext notice ---------------------------------------------------------------------

    [Fact]
    public async Task The_plaintext_notice_names_the_keys_that_were_files_when_they_were_imported_and_the_archives_made_before()
    {
        using var install = new LegacySshInstall();
        var backups = Path.Combine(install.BaseDirectory, "backups");
        Directory.CreateDirectory(backups);

        // An install that never kept an SSH key in a file has no notice, whatever its backups.
        File.WriteAllText(Path.Combine(backups, "modularca-backup-20260101-000000.enc"), "x");
        File.SetLastWriteTimeUtc(Path.Combine(backups, "modularca-backup-20260101-000000.enc"), DateTime.UtcNow.AddDays(-30));
        await install.Node.CreateCaAsync("Signer Born");
        using (var db = install.Node.Reopen())
        {
            var none = await SshPlaintextNotices.ReadAsync(db, backups);
            Assert.False(none.Applies);
            Assert.Empty(none.Imported);
            Assert.Empty(none.EarlierArchives);
        }

        var first = install.Seed("A Old", "ed25519");
        var stuck = install.Seed("B Stuck", "p256", writeFile: false);
        using (var db = install.Node.Reopen())
        {
            // Before the import: it applies, because keys are still files.
            var before = await SshPlaintextNotices.ReadAsync(db, backups);
            Assert.True(before.Applies);
            Assert.Equal(2, before.AwaitingImport);
            Assert.Null(before.LastImportedAt);
        }

        await install.Import().RunAsync();
        File.WriteAllText(Path.Combine(backups, "pre-restore-20260201-000000.zip"), "x");
        File.SetLastWriteTimeUtc(Path.Combine(backups, "pre-restore-20260201-000000.zip"), DateTime.UtcNow.AddDays(-20));
        File.WriteAllText(Path.Combine(backups, "modularca-backup-after.enc"), "x");
        File.SetLastWriteTimeUtc(Path.Combine(backups, "modularca-backup-after.enc"), DateTime.UtcNow.AddMinutes(5));
        File.WriteAllText(Path.Combine(backups, "notes.txt"), "x");
        File.SetLastWriteTimeUtc(Path.Combine(backups, "notes.txt"), DateTime.UtcNow.AddDays(-20));

        using var read = install.Node.Reopen();
        var notice = await SshPlaintextNotices.ReadAsync(read, backups);

        Assert.True(notice.Applies);
        var entry = Assert.Single(notice.Imported);
        Assert.Equal((first.Id, "A Old", SshFixtures.CaPublic("ed25519").Fingerprint, install.FileOf(first), true),
            (entry.Id, entry.Name, entry.Fingerprint, entry.File, entry.FileRemoved));
        Assert.InRange(entry.ImportedAt, DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddSeconds(5));
        Assert.Equal(entry.ImportedAt, notice.FirstImportedAt);
        Assert.Equal(entry.ImportedAt, notice.LastImportedAt);
        Assert.Equal(1, notice.AwaitingImport);
        _ = stuck;
        // The archives written before the import, newest first; not the one written after, and nothing that is no archive.
        Assert.Equal(new[] { "pre-restore-20260201-000000.zip", "modularca-backup-20260101-000000.enc" }, notice.EarlierArchives.Select(a => a.Name));
        Assert.Contains("stored on the node in plaintext", notice.Message);
        Assert.Contains("Rotating an SSH CA", notice.Message);

        // The record is in the application database: it does not depend on the audit, and it survives the key files.
        Assert.False(File.Exists(install.FileOf(first)));
        Assert.True((await SshPlaintextNotices.ReadAsync(read, backupDirectory: null)).Applies);
        Assert.Empty((await SshPlaintextNotices.ReadAsync(read, Path.Combine(backups, "no-such-directory"))).EarlierArchives);
    }

    // ---- The upgrade check ------------------------------------------------------------------------

    private static SshUpgradeKeyRow Row(SshCaKeyEntity key, bool enabled = true) => new(key.Id, key.Name, key.PublicKey, key.PrivateKeyPath, enabled);

    [Fact]
    public void The_upgrade_check_is_ok_with_no_key_file_ok_with_the_count_when_every_file_is_there_and_refused_when_one_is_not()
    {
        using var install = new LegacySshInstall();

        // No row names a key file.
        var none = SshUpgradeCheck.Keys([], install.BaseDirectory);
        Assert.False(none.Refused);
        Assert.Equal("no SSH CA key is a file on a node; nothing to import.", none.Detail);

        // Every file present and holding its row's key: the count, and what becomes of the files. One row gives a relative path.
        var a = install.Seed("A SSH", "ed25519");
        var b = install.Seed("B SSH", "rsa", path: (_, id) => $"config/ssh-ca-keys/{id}");
        var ok = SshUpgradeCheck.Keys([Row(a), Row(b)], install.BaseDirectory);
        Assert.False(ok.Refused);
        Assert.Equal("2 SSH CA key(s) will be imported into the signer at first start and their files deleted; "
            + "archives made before this upgrade still contain them in plaintext", ok.Detail);
        Assert.Equal("SSH CA keys", ok.Summary);
        // The check read the files and changed nothing.
        Assert.True(File.Exists(install.FileOf(a)) && File.Exists(install.FileOf(b)));

        // A missing file and a file that is another key: refused, each named with its row id and the path expected.
        var missing = install.Seed("C Missing", "p256", writeFile: false);
        var mismatch = install.Seed("D Mismatch", "p384");
        File.Copy(SshFixtures.PathOf("ca-p521.testkey"), install.FileOf(mismatch), overwrite: true);
        var refused = SshUpgradeCheck.Keys([Row(a), Row(b), Row(missing), Row(mismatch)], install.BaseDirectory);
        Assert.True(refused.Refused);
        Assert.Equal("SSH CA keys: 2 key file(s) missing or not matching", refused.Summary);
        Assert.Contains($"'C Missing' ({missing.Id}), expected at {install.FileOf(missing)}", refused.Detail);
        Assert.Contains($"'D Mismatch' ({mismatch.Id}), expected at {install.FileOf(mismatch)}", refused.Detail);
        Assert.DoesNotContain("'A SSH'", refused.Detail);
        Assert.Contains("or disable those SSH CAs", refused.Detail);
        Assert.Contains("on a split install, run this check on that host", refused.Detail);

        // Disabling those SSH CAs is the other remedy the refusal offers, so it has to work: not refused, and said.
        var disabled = SshUpgradeCheck.Keys([Row(a), Row(b), Row(missing, enabled: false), Row(mismatch, enabled: false)], install.BaseDirectory);
        Assert.False(disabled.Refused);
        Assert.StartsWith("2 SSH CA key(s) will be imported into the signer at first start", disabled.Detail);
        Assert.Contains("2 disabled SSH CA key(s) have no usable key file and stay as they are", disabled.Detail);
        Assert.Contains($"'C Missing' ({missing.Id})", disabled.Detail);

        // A relative path is relative to the installed application directory the check is pointed at:
        // looked for under another directory the file is not there, while an absolute path does not move.
        var elsewhere = Path.Combine(install.BaseDirectory, "another-install");
        Assert.True(SshUpgradeCheck.Keys([Row(b)], elsewhere).Refused);
        Assert.Contains(Path.Combine(elsewhere, "config", "ssh-ca-keys", b.Id.ToString()), SshUpgradeCheck.Keys([Row(b)], elsewhere).Detail);
        Assert.False(SshUpgradeCheck.Keys([Row(a)], elsewhere).Refused);
    }

    [Fact]
    public void The_upgrade_check_lists_the_user_signing_profiles_whose_certificates_no_longer_carry_all_five_permits()
    {
        var all = "[\"permit-X11-forwarding\",\"permit-agent-forwarding\",\"permit-port-forwarding\",\"permit-pty\",\"permit-user-rc\"]";
        var ptyOnly = new SshUpgradeSigningProfile(Guid.NewGuid(), "pty only", true, "[\"permit-pty\"]");
        var seeded = new SshUpgradeSigningProfile(Guid.NewGuid(), "default user signing", true, "[\"permit-pty\",\"permit-agent-forwarding\",\"permit-port-forwarding\"]");
        var complete = new SshUpgradeSigningProfile(Guid.NewGuid(), "complete", true, all);
        var none = new SshUpgradeSigningProfile(Guid.NewGuid(), "nothing named", true, "[]");
        var withheld = new SshUpgradeSigningProfile(Guid.NewGuid(), "withholds pty", true, all.Replace("]", ",\"no-pty\"]"));
        var host = new SshUpgradeSigningProfile(Guid.NewGuid(), "host signing", false, "[]");
        var unreadable = new SshUpgradeSigningProfile(Guid.NewGuid(), "unreadable", true, "not json");
        SshUpgradeSigningProfile[] profiles = [ptyOnly, seeded, complete, none, withheld, host, unreadable];

        // No cert profile: a certificate carries what the signing profile names, and nothing else.
        var note = SshUpgradeCheck.ProfilesNote(profiles, [])!;
        Assert.StartsWith("5 SSH signing profile(s) for user certificates relied on the extensions", note);
        Assert.Contains("will be narrower than before", note);
        Assert.Contains($"'pty only' ({ptyOnly.Id}): names permit-pty; certificates from it will no longer carry permit-X11-forwarding, permit-agent-forwarding, permit-port-forwarding, permit-user-rc", note);
        Assert.Contains($"'default user signing' ({seeded.Id}): names permit-agent-forwarding, permit-port-forwarding, permit-pty; certificates from it will no longer carry permit-X11-forwarding, permit-user-rc", note);
        Assert.Contains($"'nothing named' ({none.Id}): names no permit;", note);
        Assert.Contains($"'withholds pty' ({withheld.Id})", note);
        Assert.Contains("will no longer carry permit-pty", note[note.IndexOf("'withholds pty'", StringComparison.Ordinal)..].Split('\n')[0]);
        Assert.Contains($"'unreadable' ({unreadable.Id}): names no permit;", note);
        Assert.DoesNotContain("'complete'", note);
        Assert.DoesNotContain("'host signing'", note);

        // A cert profile adds its required extensions to every certificate: what every cert profile requires is not missing.
        var requiresTwo = new SshUpgradeCertProfile(Guid.NewGuid(), "requires two", "[\"permit-X11-forwarding\",\"permit-user-rc\"]");
        var withRequired = SshUpgradeCheck.ProfilesNote(profiles, [requiresTwo])!;
        Assert.DoesNotContain("'default user signing'", withRequired);
        Assert.Contains($"'pty only' ({ptyOnly.Id}): names permit-pty; certificates from it will no longer carry permit-agent-forwarding, permit-port-forwarding", withRequired);
        Assert.StartsWith("4 SSH signing profile(s)", withRequired);
        // ...but only what every one of them requires: a second cert profile that requires nothing takes that away again.
        var requiresNothing = new SshUpgradeCertProfile(Guid.NewGuid(), "requires nothing", "[]");
        Assert.Contains("'default user signing'", SshUpgradeCheck.ProfilesNote(profiles, [requiresTwo, requiresNothing]));

        // Nothing to say when every user profile names all five, and never a refusal: the note is text or nothing.
        Assert.Null(SshUpgradeCheck.ProfilesNote([complete, host], []));
        Assert.Null(SshUpgradeCheck.ProfilesNote([], [requiresTwo]));

        // On a database already past the change the same profiles are listed, without the promise of a change to come.
        var after = SshUpgradeCheck.ProfilesNote(profiles, [], beforeUpgrade: false)!;
        Assert.DoesNotContain("will be narrower", after);
        Assert.Contains("certificates from it do not carry permit-X11-forwarding", after);
    }

    [Fact]
    public async Task What_the_profile_note_says_a_certificate_carries_is_what_the_signer_issues_for_that_profile()
    {
        // The note is computed with the option mapping the service signs with: a profile it says
        // lacks four permits yields a certificate with exactly the other one. The profile is the
        // one created with a key, which permits a terminal and no forwarding.
        using var node = new SshNode();
        var ca = await node.CreateCaAsync("Fleet SSH");
        var profile = node.Db.SshSigningProfiles.Single(p => p.SshCaKeyId == ca.Id && p.AllowUserCerts);
        var note = SshUpgradeCheck.ProfilesNote([new SshUpgradeSigningProfile(profile.Id, profile.Name, true, profile.DefaultExtensions)], [])!;
        Assert.Contains("will no longer carry permit-X11-forwarding, permit-agent-forwarding, permit-port-forwarding, permit-user-rc", note);

        var defaults = JsonSerializer.Deserialize<List<string>>(profile.DefaultExtensions)!;
        var certificate = ModularCA.Ssh.SshCertificate.ParseOpenSsh(
            (await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, defaults, node.Actor)).SignedCertificate);

        Assert.Equal(new[] { "permit-pty" },
            certificate.Fields.Extensions.Select(e => e.Name).OrderBy(n => n, StringComparer.Ordinal));
    }
}
