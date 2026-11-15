using Xunit;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Journal;
using ModularCA.Database;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The facts the node asserts: that a save queues the fact of each change it makes, in the same
/// save; that the queue is offered to the signer and emptied by what the signer took; that a
/// fact the signer does not take stays, through a restart of the node, and never stops the
/// change it describes; and that the kinds of the Disabled fact and the mode gate's
/// restrictions are listed together.
/// </summary>
public class SignerFactQueueTests
{
    private sealed class Node
    {
        public SignerTestWorld World { get; } = SignerTestWorld.Create();
        public SignerTestKey Ca => World["ca-rsa"];
        public byte[] CaKey => SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Ca.PublicKey).GetDerEncoded());

        public ModularCADbContext Open() => World.OpenDb();

        public List<SignerFactEntity> Facts()
        {
            using var db = Open();
            return db.SignerFacts.OrderBy(f => f.Id).ToList();
        }

        public CertificateEntity Leaf(string serial = "0A1B2C", bool legacy = false)
        {
            using var db = Open();
            var row = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = serial, SubjectDN = "CN=fact leaf", Issuer = Ca.Certificate.SubjectDN.ToString(),
                IssuerCertificateId = legacy ? null : Ca.Ref.CertificateId, NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddDays(30),
            };
            db.Certificates.Add(row);
            db.SaveChanges();
            return row;
        }
    }

    [Fact]
    public void Revoking_a_certificate_queues_a_revocation_in_the_same_save()
    {
        var node = new Node();
        var leaf = node.Leaf();
        Assert.Empty(node.Facts());

        using (var db = node.Open())
        {
            var row = db.Certificates.Single(c => c.CertificateId == leaf.CertificateId);
            row.Revoked = true;
            row.RevocationReason = "KeyCompromise";
            row.RevocationDate = new DateTime(2026, 11, 12, 10, 0, 0, DateTimeKind.Utc);
            db.SaveChanges();
        }

        var fact = Assert.Single(node.Facts());
        Assert.Equal(RecordType.Revocation, fact.Type);
        var payload = RevocationPayload.Decode(fact.Payload);
        Assert.Equal(new byte[] { 0x0a, 0x1b, 0x2c }, payload.Serial);
        Assert.Equal(node.CaKey, payload.CaKey);
        Assert.Equal(node.Ca.CaId!.Value.ToString("D"), payload.Ca);
        Assert.Equal(1ul, payload.Reason);
        Assert.Equal(JournalFormat.ToMicros(new DateTimeOffset(2026, 11, 12, 10, 0, 0, TimeSpan.Zero)), payload.Time);
        Assert.True(payload.Known);
        Assert.Equal(RevocationForm.Revoked, payload.Form);
    }

    [Fact]
    public void A_hold_its_release_a_permanent_revocation_and_a_retirement_are_each_a_fact()
    {
        var node = new Node();
        var leaf = node.Leaf();

        void Change(Action<CertificateEntity> change)
        {
            using var db = node.Open();
            change(db.Certificates.Single(c => c.CertificateId == leaf.CertificateId));
            db.SaveChanges();
        }
        Change(c => { c.Revoked = true; c.RevocationReason = "CertificateHold"; c.RevocationDate = DateTime.UtcNow; });
        Change(c => { c.Revoked = false; c.RevocationReason = null; c.RevocationDate = null; });
        Change(c => { c.Revoked = true; c.RevocationReason = "CertificateHold"; c.RevocationDate = DateTime.UtcNow; });
        // A hold made permanent without being released first.
        Change(c => { c.RevocationReason = "Superseded"; c.RevocationDate = DateTime.UtcNow; });
        Change(c => c.RetiredAt = DateTime.UtcNow);
        // Saving a revoked certificate again for another reason says nothing new.
        Change(c => c.SubjectDN = "CN=renamed");

        var facts = node.Facts();
        Assert.Equal(new[] { (int)RecordType.Revocation, RecordType.Unrevocation, RecordType.Revocation, RecordType.Revocation, RecordType.Revocation }, facts.Select(f => f.Type));
        Assert.Equal(RevocationForm.Hold, RevocationPayload.Decode(facts[0].Payload).Form);
        Assert.Equal(6ul, RevocationPayload.Decode(facts[0].Payload).Reason);
        Assert.Equal(new byte[] { 0x0a, 0x1b, 0x2c }, UnrevocationPayload.Decode(facts[1].Payload).Serial);
        Assert.Equal(node.CaKey, UnrevocationPayload.Decode(facts[1].Payload).CaKey);
        Assert.Equal(RevocationForm.Hold, RevocationPayload.Decode(facts[2].Payload).Form);
        Assert.Equal((RevocationForm.Revoked, 4ul), (RevocationPayload.Decode(facts[3].Payload).Form, RevocationPayload.Decode(facts[3].Payload).Reason));
        Assert.Equal(RevocationForm.Retired, RevocationPayload.Decode(facts[4].Payload).Form);
    }

    [Fact]
    public void A_revocation_that_is_rolled_back_leaves_no_fact()
    {
        var node = new Node();
        var leaf = node.Leaf();

        using (var db = node.Open())
        {
            var row = db.Certificates.Single(c => c.CertificateId == leaf.CertificateId);
            row.Revoked = true;
            row.RevocationReason = "KeyCompromise";
            // The save never happens: the unit of work is abandoned.
        }

        Assert.Empty(node.Facts());
        using var check = node.Open();
        Assert.False(check.Certificates.Single(c => c.CertificateId == leaf.CertificateId).Revoked);
    }

    [Fact]
    public void A_certificate_from_before_issuer_links_is_named_by_its_issuers_name()
    {
        var node = new Node();
        var leaf = node.Leaf("FF01", legacy: true);

        using (var db = node.Open())
        {
            var row = db.Certificates.Single(c => c.CertificateId == leaf.CertificateId);
            row.Revoked = true;
            row.RevocationReason = "Superseded";
            db.SaveChanges();
        }

        Assert.Equal(node.CaKey, RevocationPayload.Decode(Assert.Single(node.Facts()).Payload).CaKey);
    }

    [Fact]
    public void A_serial_revoked_with_no_certificate_is_a_revocation_the_ca_has_no_record_of()
    {
        var node = new Node();

        using (var db = node.Open())
        {
            db.RevokedSerialTombstones.Add(new RevokedSerialTombstoneEntity
            {
                CaCertificateId = node.Ca.Ref.CertificateId, CertificateAuthorityId = node.Ca.CaId!.Value, IssuerDN = node.Ca.Certificate.SubjectDN.ToString(),
                SerialNumber = "7001", RevocationDate = DateTime.UtcNow, RevocationReason = "KeyCompromise", ListedUntil = DateTime.UtcNow.AddYears(1),
            });
            db.SaveChanges();
        }

        var payload = RevocationPayload.Decode(Assert.Single(node.Facts()).Payload);
        Assert.False(payload.Known);
        Assert.Equal(new byte[] { 0x70, 0x01 }, payload.Serial);
        Assert.Equal(node.CaKey, payload.CaKey);
        Assert.Equal(1ul, payload.Reason);
    }

    [Fact]
    public void Disabling_is_a_fact_and_enabling_again_is_not()
    {
        var node = new Node();
        var ids = new Dictionary<ulong, Guid>();
        using (var db = node.Open())
        {
            var space = new SpaceEntity { Id = Guid.NewGuid(), Name = "facts", Slug = "facts" };
            var user = new UserEntity { Id = Guid.NewGuid(), Username = "fact-user", Email = "fact-user@example.test", PasswordHash = "x" };
            var locked = new UserEntity { Id = Guid.NewGuid(), Username = "fact-locked", Email = "fact-locked@example.test", PasswordHash = "x" };
            var credential = new MtlsCredentialEntity { Id = Guid.NewGuid(), UserId = user.Id };
            var apiKey = new ApiKeyEntity { Id = Guid.NewGuid(), Name = "fact-key" };
            db.AddRange(space, user, locked, credential, apiKey);
            db.SaveChanges();
            ids[DisabledKind.Space] = space.Id;
            ids[DisabledKind.Account] = user.Id;
            ids[0] = locked.Id;
            ids[DisabledKind.SignInCredential] = credential.Id;
            ids[100] = apiKey.Id;
        }
        var (sshCa, sshKey, _) = node.World.SeedBoundSshKey();
        Assert.Empty(node.Facts());

        using (var db = node.Open())
        {
            db.CertificateAuthorities.Single(c => c.Id == node.Ca.CaId).IsEnabled = false;
            db.SshCaKeys.Single(k => k.Id == sshKey.CertificateId).IsEnabled = false;
            db.Spaces.Single(s => s.Id == ids[DisabledKind.Space]).IsEnabled = false;
            db.Users.Single(u => u.Id == ids[DisabledKind.Account]).IsActive = false;
            db.Users.Single(u => u.Id == ids[0]).IsLocked = true;
            db.MtlsCredentials.Single(c => c.Id == ids[DisabledKind.SignInCredential]).IsRevoked = true;
            db.ApiKeys.Single(k => k.Id == ids[100]).RevokedAt = DateTime.UtcNow;
            db.SaveChanges();
        }

        var facts = node.Facts().Select(f => { Assert.Equal(RecordType.Disabled, f.Type); return DisabledPayload.Decode(f.Payload); }).ToList();
        Assert.Equal(7, facts.Count);
        Assert.Contains(new { Kind = DisabledKind.Ca, Id = node.Ca.CaId!.Value.ToString("D") }, facts.Select(f => new { f.Kind, f.Id }));
        Assert.Contains(new { Kind = DisabledKind.SshCaKey, Id = sshKey.CertificateId.ToString("D") }, facts.Select(f => new { f.Kind, f.Id }));
        Assert.Contains(new { Kind = DisabledKind.Space, Id = ids[DisabledKind.Space].ToString("D") }, facts.Select(f => new { f.Kind, f.Id }));
        Assert.Equal(new[] { ids[DisabledKind.Account].ToString("D"), ids[0].ToString("D") }.Order(), facts.Where(f => f.Kind == DisabledKind.Account).Select(f => f.Id).Order());
        Assert.Equal(new[] { ids[DisabledKind.SignInCredential].ToString("D"), ids[100].ToString("D") }.Order(), facts.Where(f => f.Kind == DisabledKind.SignInCredential).Select(f => f.Id).Order());
        Assert.All(facts, f => Assert.InRange(JournalFormat.FromMicros(f.Time), DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1)));
        // Every kind the layout names was produced.
        Assert.Equal(DisabledKind.All.Order(), facts.Select(f => f.Kind).Distinct().Order());

        // Enabling again is not recorded.
        using (var db = node.Open())
        {
            db.CertificateAuthorities.Single(c => c.Id == node.Ca.CaId).IsEnabled = true;
            db.Spaces.Single(s => s.Id == ids[DisabledKind.Space]).IsEnabled = true;
            db.Users.Single(u => u.Id == ids[DisabledKind.Account]).IsActive = true;
            db.Users.Single(u => u.Id == ids[0]).IsLocked = false;
            db.SaveChanges();
        }
        Assert.Equal(7, node.Facts().Count);
        _ = sshCa;
    }

    [Fact]
    public void A_spent_binding_and_a_changed_incarnation_are_facts()
    {
        var node = new Node();
        Guid eab;
        using (var db = node.Open())
        {
            var key = new AcmeEabKeyEntity { Id = Guid.NewGuid(), KeyId = "kid-1", HmacKey = "never-in-the-journal" };
            db.AcmeEabKeys.Add(key);
            db.InstanceIncarnation.Add(new InstanceIncarnationEntity { Source = "injected", ValueHash = new string('A', 64), RecordedBy = "test" });
            db.SaveChanges();
            eab = key.Id;
        }
        Assert.Empty(node.Facts());

        using (var db = node.Open())
        {
            var key = db.AcmeEabKeys.Single();
            key.IsUsed = true;
            key.UsedAt = DateTime.UtcNow;
            db.InstanceIncarnation.Single().ValueHash = new string('B', 64);
            db.SaveChanges();
        }

        var facts = node.Facts();
        var spent = SpentWithoutCertificatePayload.Decode(facts.Single(f => f.Type == RecordType.SpentWithoutCertificate).Payload);
        Assert.Equal((TokenKind.AcmeExternalAccountBinding, eab.ToString("D")), (spent.Kind, spent.Id));
        var changed = ContinuityEventPayload.Decode(facts.Single(f => f.Type == RecordType.ContinuityEvent).Payload);
        Assert.Equal(Convert.FromHexString(new string('A', 64)), changed.OldIncarnation);
        Assert.Equal(Convert.FromHexString(new string('B', 64)), changed.NewIncarnation);
        // The fact carries the row's id and nothing of the key.
        Assert.All(facts, f => Assert.DoesNotContain("never-in-the-journal", System.Text.Encoding.UTF8.GetString(f.Payload), StringComparison.Ordinal));
    }

    [Fact]
    public void A_context_told_not_to_queues_nothing()
    {
        var node = new Node();
        var leaf = node.Leaf();

        using (var db = node.Open())
        {
            db.SuppressSignerFacts = true;
            db.Certificates.Single(c => c.CertificateId == leaf.CertificateId).Revoked = true;
            db.SaveChanges();
        }

        Assert.Empty(node.Facts());
    }

    [Fact]
    public async Task The_queue_is_offered_to_the_signer_in_order_and_emptied_by_what_it_took()
    {
        var node = new Node();
        using var sandbox = new JournalSandbox();
        await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "t", new byte[32]), NullLogger.Instance);
        var signer = TestSigner.Over(node.World.Keystore, node.World.DatabaseName, node.World.Persistence, journal);
        using (var db = node.Open())
        {
            for (var i = 0; i < 3; i++)
                db.QueueSignerFact(RecordType.Disabled, new DisabledPayload(DisabledKind.Space, "space-" + i, i).Encode());
            db.SaveChanges();
        }

        using (var db = node.Open())
            Assert.Equal(3, await SignerFactDrain.DrainOnceAsync(db, signer, NullLogger.Instance));

        Assert.Empty(node.Facts());
        var recorded = sandbox.Records().Where(r => r.Record.Type == RecordType.Disabled).Select(r => r.Record).ToList();
        Assert.Equal(new[] { "space-0", "space-1", "space-2" }, recorded.Select(r => DisabledPayload.Decode(r.Payload).Id));
        Assert.All(recorded, r => Assert.True(r.NodeAsserted));
        using (var db = node.Open())
            Assert.Equal(0, await SignerFactDrain.DrainOnceAsync(db, signer, NullLogger.Instance));
    }

    [Fact]
    public async Task A_fact_the_signer_does_not_take_stays_queued_through_a_restart_and_stops_nothing()
    {
        var node = new Node();
        var leaf = node.Leaf();
        using var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles();
        await using var journal = new SignerJournal(() => sandbox.Options(files), new SignerJournalSettings(sandbox.Home, true, "t", new byte[32]), NullLogger.Instance);
        var signer = TestSigner.Over(node.World.Keystore, node.World.DatabaseName, node.World.Persistence, journal);
        files.FailAppend = (_, _) => new IOException("There is not enough space on the disk.");

        // The revocation goes through with the journal unable to take anything.
        using (var db = node.Open())
        {
            var row = db.Certificates.Single(c => c.CertificateId == leaf.CertificateId);
            row.Revoked = true;
            row.RevocationReason = "KeyCompromise";
            row.RevocationDate = DateTime.UtcNow;
            db.QueueSignerFact(RecordType.Disabled, new DisabledPayload(DisabledKind.Space, "after", 1).Encode());
            db.SaveChanges();
        }
        using (var db = node.Open())
        {
            Assert.True(db.Certificates.Single(c => c.CertificateId == leaf.CertificateId).Revoked);
            Assert.Equal(2, await SignerFactDrain.DrainOnceAsync(db, signer, NullLogger.Instance));
        }
        var waiting = node.Facts();
        Assert.Equal(2, waiting.Count);
        Assert.Equal(1, waiting[0].Attempts);
        Assert.Contains("space", waiting[0].LastError!, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(waiting[0].NextAttemptAt);
        Assert.NotNull(waiting[1].NextAttemptAt);
        Assert.DoesNotContain(sandbox.Records(), r => r.Record.NodeAsserted);

        // The node restarts: nothing it held in memory is left, and the queue is in the database.
        files.FailAppend = null;
        await Task.Delay(1100);
        using (var db = node.Open())
        {
            foreach (var fact in db.SignerFacts)
                fact.NextAttemptAt = DateTime.UtcNow.AddSeconds(-1);
            db.SuppressSignerFacts = true;
            db.SaveChanges();
        }
        var restarted = TestSigner.Over(node.World.Keystore, node.World.DatabaseName, node.World.Persistence, journal);
        using (var db = node.Open())
            Assert.Equal(2, await SignerFactDrain.DrainOnceAsync(db, restarted, NullLogger.Instance));

        Assert.Empty(node.Facts());
        var asserted = sandbox.Records().Where(r => r.Record.NodeAsserted).Select(r => r.Record.Type).ToList();
        // In the order they were queued: the fact the caller queued, then the one the save added for the revocation.
        Assert.True(asserted.SequenceEqual(new[] { RecordType.Disabled, RecordType.Revocation }), "asserted records: " + string.Join(", ", asserted));
    }

    [Fact]
    public async Task A_signer_that_keeps_no_journal_leaves_the_facts_queued()
    {
        var node = new Node();
        var signer = TestSigner.Over(node.World.Keystore, node.World.DatabaseName, node.World.Persistence);
        using (var db = node.Open())
        {
            db.QueueSignerFact(RecordType.Disabled, new DisabledPayload(DisabledKind.Space, "s", 1).Encode());
            db.QueueSignerFact(RecordType.Disabled, new DisabledPayload(DisabledKind.Space, "t", 1).Encode());
            db.SaveChanges();
        }

        using (var db = node.Open())
            await SignerFactDrain.DrainOnceAsync(db, signer, NullLogger.Instance);

        var facts = node.Facts();
        Assert.Equal(2, facts.Count);
        Assert.Equal(1, facts[0].Attempts);
        Assert.Equal(0, facts[1].Attempts);
    }

    /// <summary>
    /// What each endpoint the mode gate classes as a restriction records in the journal. An
    /// endpoint added to that class has to be listed here, with the fact it produces, and a
    /// kind added to the Disabled fact has to have an endpoint: neither changes alone
    /// (the layout, section 5).
    /// </summary>
    private static readonly Dictionary<string, string> RestrictionFacts = new(StringComparer.Ordinal)
    {
        ["AcmeOrderController.RevokeCert"] = "Revocation",
        ["AdminAcmeEabController.DeleteEabKey"] = "none: a binding key is removed; nothing was spent and nothing the journal names is disabled",
        ["AdminApiKeyController.Revoke"] = "Disabled:" + DisabledKind.SignInCredential,
        ["AdminCaController.UpdateCa"] = "Disabled:" + DisabledKind.Ca,
        ["AdminCertSignRequestController.Cancel"] = "none: a request withdrawn issues nothing",
        ["AdminCertSignRequestController.Reject"] = "none: a request refused issues nothing",
        ["AdminCertificateController.RetireCertificate"] = "Revocation",
        ["AdminEnrollmentTokenController.RevokeToken"] = "none: a token withdrawn was not spent",
        ["AdminRevocationController.BulkRevoke"] = "Revocation",
        ["AdminRevocationController.HoldByCertId"] = "Revocation",
        ["AdminRevocationController.HoldByCertSerial"] = "Revocation",
        ["AdminRevocationController.RevokeByCertId"] = "Revocation",
        ["AdminRevocationController.RevokeByCertSerial"] = "Revocation",
        ["AdminRevokedSerialController.Record"] = "Revocation",
        ["AdminRevokedSerialController.RecordMany"] = "Revocation",
        ["AdminRevokedSerialController.RevokeAllMissing"] = "Revocation",
        ["AdminSpaceController.Disable"] = "Disabled:" + DisabledKind.Space,
        ["AdminSshController.DisableSshCaKey"] = "Disabled:" + DisabledKind.SshCaKey,
        ["AdminSshController.RevokeCertificate"] = "SshRevocationList",
        ["AdminSshLoginNameController.RevokeUserCertificates"] = "SshRevocationList",
        ["AdminUserManagerController.UpdateUser"] = "Disabled:" + DisabledKind.Account,
        ["InfraController.RevokeCertificate"] = "Revocation",
        ["MtlsController.RevokeCredential"] = "Disabled:" + DisabledKind.SignInCredential,
        ["UserCertificateController.RevokeOwnCertificate"] = "Revocation",
    };

    [Fact]
    public void The_kinds_of_the_Disabled_fact_and_the_mode_gates_restrictions_are_listed_together()
    {
        var restrictions = ModularCA.Tests.Roles.ApiAssembly.ControllerTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(m => m.GetCustomAttributes().OfType<ModeGateAttribute>().Any(g => g.Operation == ModeOperation.Restriction))
                .Select(m => $"{t.Name}.{m.Name}"))
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.True(RestrictionFacts.Keys.Order(StringComparer.Ordinal).SequenceEqual(restrictions),
            "The endpoints classed as a restriction are: " + string.Join(", ", restrictions));

        // Every kind of the Disabled fact is what some restriction produces, and no restriction names a kind that does not exist.
        var kinds = RestrictionFacts.Values.Where(v => v.StartsWith("Disabled:", StringComparison.Ordinal))
            .Select(v => ulong.Parse(v["Disabled:".Length..], System.Globalization.CultureInfo.InvariantCulture)).Distinct().Order().ToList();
        Assert.Equal(DisabledKind.All.Order(), kinds);
        // And the numbers are the layout's: CA, SSH CA key, space, account, sign-in credential.
        Assert.Equal(new ulong[] { 1, 2, 3, 4, 5 }, new[] { DisabledKind.Ca, DisabledKind.SshCaKey, DisabledKind.Space, DisabledKind.Account, DisabledKind.SignInCredential });
    }
}
