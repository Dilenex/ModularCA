using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Journal;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The system signing CA's certificate renewed over its key, on real keystore files with the
/// signer's journal behind the signer: what is tied to the system key (the keystore pins, the
/// instance identifier the journal carries, the checkpoint key block) is what it was, the
/// keystore files are not rewritten, and a signer restarted afterwards continues its journal
/// with no key change.
/// </summary>
public sealed class SystemCaRenewalTests
{
    private static ISigningService Signer(SignerTestWorld world, string journalDirectory)
        => world.Files!.Bootstrap.CreateSigner(world.Files.Directory, world.Files.YamlPath, world.Scopes,
            new DatabaseSignerAuditSink(world.Scopes), NullLogger<InProcessSigningService>.Instance, keyWrapping: null,
            journal: new SignerJournalSettings(journalDirectory, true, "0.0.0-test", new byte[32]));

    private static void Issue(ISigningService signer, SignerTestKey ca, int serial)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(serial));
        generator.SetIssuerDN(ca.Certificate.SubjectDN);
        generator.SetSubjectDN(new Org.BouncyCastle.Asn1.X509.X509Name($"CN=leaf-{serial}"));
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        generator.SetPublicKey(KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Public);
        generator.Generate(new SigningServiceSignatureFactory(signer, ca.Ref, SignatureAlgorithm.ForPublicKey(ca.PublicKey),
            SigningContext.ForCa("system-renewal-test", SigningPurpose.Certificate, ca.CaId!.Value, ca.SpaceId)));
    }

    [Fact]
    public async Task Renewing_the_system_signing_ca_changes_nothing_that_is_tied_to_its_key()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        using var sandbox = new JournalSandbox();
        var system = world["ca-rsa"];       // the key the keystore files are pinned to and signed by
        string pin;
        List<(string Name, string? Pin, string? Mac)> pinsBefore;
        using (var db = world.OpenDb())
        {
            pin = KeystoreService.GetPinnedSignerSpki(db, KeyRef.DefaultKeystore)!;
            // The CA row of the pinned key, labelled as bootstrap labels the system signing CA.
            var row = db.CertificateAuthorities.Single(c => c.Id == system.CaId);
            row.Label = "system-signing-ca";
            db.SaveChanges();
        }
        var files = new[] { KeyRef.DefaultKeystore, KeyRef.TrustKeystore }.ToDictionary(n => n, n => File.ReadAllBytes(world.Files!.Path(n)));

        var signer = Signer(world, sandbox.Home);
        Issue(signer, world["ca-ec"], 1);
        using (var db = world.OpenDb())
            pinsBefore = db.Keystores.AsNoTracking().OrderBy(k => k.Name).AsEnumerable().Select(k => (k.Name, k.SigningCaSpkiSha256, k.SigningCaSpkiSha256Mac == null ? null : Convert.ToHexString(k.SigningCaSpkiSha256Mac))).ToList();
        var headBefore = sandbox.Verify().Head!;

        // The renewal, through the real service and this signer.
        Guid renewedId;
        X509Certificate renewed;
        using (var db = world.OpenDb())
        {
            var renewal = new CaCertificateRenewalService(db, signer, world.Keystore,
                InstanceCeremonyEndpointTests.Fake<ICaServiceUrlService>.Create(), InstanceCeremonyEndpointTests.Fake<ICrlService>.Create(),
                NullLogger<CaCertificateRenewalService>.Instance);
            var plan = await renewal.PlanAsync(system.CaId!.Value, 40, DateTime.UtcNow);
            Assert.True(plan.IsRoot);
            var result = await renewal.RenewAsync(system.CaId.Value, plan.NotAfter, null, "tester");
            (renewedId, renewed) = (result.Renewed.CertificateId, result.Certificate);
        }
        Assert.Equal(system.Certificate.GetPublicKey(), renewed.GetPublicKey());
        Assert.NotEqual(system.Certificate.SerialNumber, renewed.SerialNumber);
        renewed.Verify(system.Certificate.GetPublicKey());

        // The key signs on under the new certificate, and the journal is whole.
        Issue(signer, world["ca-ec"], 2);
        await ((IAsyncDisposable)signer).DisposeAsync();

        using (var db = world.OpenDb())
        {
            // The pins, and with them the instance identifier and the hub's systemKey, are the rows they were.
            Assert.Equal(pinsBefore, db.Keystores.AsNoTracking().OrderBy(k => k.Name).AsEnumerable().Select(k => (k.Name, k.SigningCaSpkiSha256, k.SigningCaSpkiSha256Mac == null ? null : Convert.ToHexString(k.SigningCaSpkiSha256Mac))).ToList());
            Assert.Equal(pin, KeystoreService.GetPinnedSignerSpki(db, KeyRef.DefaultKeystore));
            Assert.Equal(renewedId, db.CertificateAuthorities.Single(c => c.Id == system.CaId).CertificateId);
            // The renewed certificate carries the pinned key, so it verifies the keystore files as the old one does.
            Assert.Equal(pin, CaCertificateHistory.KeyIdOf(db.Certificates.Single(c => c.CertificateId == renewedId)));
        }
        // No keystore file was rewritten.
        foreach (var (name, bytes) in files)
            Assert.Equal(bytes, File.ReadAllBytes(world.Files!.Path(name)));

        // A signer started after the renewal, from the same files: it unlocks, verifies its
        // journal, and continues it under the same checkpoint key block.
        var restarted = world.Restart();
        var again = Signer(restarted, sandbox.Home);
        using (var db = restarted.OpenDb())
            Assert.Equal(1, await CaCertificateHistory.RegisterRenewedAsync(db, restarted.Keystore));
        Issue(again, restarted["ca-ec"], 3);
        // The system key still signs for its CA, addressed by the new certificate.
        var keys = await again.ListKeysAsync(SigningContext.ForCa("system-renewal-test", SigningPurpose.Crl, system.CaId!.Value, system.SpaceId));
        Assert.Contains(keys, k => k.Kind == KeyKind.Ca && k.Key.CertificateId == renewedId);
        await ((IAsyncDisposable)again).DisposeAsync();

        Assert.DoesNotContain(sandbox.Records(), r => r.Record.Type == RecordType.CheckpointKeyChanged);
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        var head = verification.Head!;
        Assert.Equal(headBefore.InstanceId, head.InstanceId);
        Assert.Equal(pin, head.InstanceId);
        Assert.Equal(headBefore.Key!.SystemKey, head.Key!.SystemKey);
        Assert.Equal(headBefore.Key.Key, head.Key.Key);
        // The renewal is in the journal as a CA certificate signed by the system key.
        var record = sandbox.Records().Where(r => r.Record.Type == RecordType.Certificate).Select(r => CertificatePayload.Decode(r.Record.Payload))
            .Single(p => new BigInteger(1, p.Serial).Equals(renewed.SerialNumber));
        Assert.True(record.IsCa);
        Assert.Equal(pin, Convert.ToHexStringLower(record.CaKey));
    }

    /// <summary>
    /// An archive taken before the renewal and restored after it: the database names the earlier
    /// certificate again and has no trace of the renewal, the key is the same, and everything
    /// goes on. The certificate that was renewed is simply gone from the database, as any change
    /// made after a backup is.
    /// </summary>
    [Fact]
    public async Task A_database_taken_back_to_before_the_renewal_is_whole_and_the_ca_signs_under_its_earlier_certificate()
    {
        await using var world = new ModularCA.Tests.Core.Services.CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Restored Root", null, null);
        var oldId = root.CertificateId!.Value;
        var (leafBefore, _) = await world.LeafAsync(root, "before-backup");
        var renewedId = (await world.RenewAsync(root)).Renewed.CertificateId;

        // What the restore of an earlier archive does to the rows a renewal wrote.
        using (var db = w.World.OpenDb())
        {
            db.CaCertificates.RemoveRange(db.CaCertificates.Where(h => h.CertificateId == renewedId));
            foreach (var history in db.CaCertificates.Where(h => h.CertificateId == oldId)) history.SupersededAt = null;
            db.CertificateAuthorities.Single(c => c.Id == root.Id).CertificateId = oldId;
            foreach (var profile in db.SigningProfiles.Where(p => p.IssuerId == renewedId)) profile.IssuerId = oldId;
            foreach (var schedule in db.CrlConfigurations.Where(c => c.CaCertificateId == renewedId)) schedule.CaCertificateId = oldId;
            foreach (var urls in db.CaServiceUrls.Where(u => u.CaCertificateId == renewedId)) urls.CaCertificateId = oldId;
            db.Certificates.Single(c => c.CertificateId == oldId).ExpiryWarningDismissedAt = null;
            db.SaveChanges();
            db.Certificates.Remove(db.Certificates.Single(c => c.CertificateId == renewedId));
            db.SaveChanges();
        }
        w.Db.ChangeTracker.Clear();

        // Nothing to register at the next start, the earlier certificate is the CA's again, and it issues.
        using (var db = w.World.OpenDb())
        {
            Assert.Equal(0, await CaCertificateHistory.RegisterRenewedAsync(db, w.World.Keystore));
            Assert.Equal(new[] { oldId }, await IssuerChainResolver.CaCertificateIdsAsync(db, root.Id));
        }
        var (leafAfter, certificate) = await world.LeafAsync(root, "after-restore");
        Assert.Equal(oldId, leafAfter.IssuerCertificateId);
        certificate.Verify(world.Certificate(oldId).GetPublicKey());
        Assert.Equal(oldId, leafBefore.IssuerCertificateId);

        // And it can be renewed again.
        Assert.NotEqual(oldId, (await world.RenewAsync(root)).Renewed.CertificateId);
    }
}
