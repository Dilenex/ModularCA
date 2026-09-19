using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Short custody of a server-generated request key: it is wrapped onto its own row and nowhere
/// else, it leaves once as a PKCS#12 that carries the certificate, its chain and the key, and
/// it is deleted the moment it leaves or the moment it can no longer be delivered.
/// </summary>
public sealed class HeldKeyServiceTests
{
    private static readonly DateTime Now = new(2026, 9, 17, 15, 0, 0, DateTimeKind.Utc);
    private const string Password = "correct horse battery";

    /// <summary>A CA, a signing profile under it, and a service over an ephemeral Data Protection ring.</summary>
    private sealed class World
    {
        public string DatabaseName { get; } = $"held-{Guid.NewGuid():N}";
        public ModularCADbContext Db { get; }
        public EphemeralDataProtectionProvider DataProtection { get; } = new();
        public RecordingAuditService Audit { get; } = new();
        public FixedTimeProvider Clock { get; } = new(new DateTimeOffset(Now));
        public HeldKeyService Service { get; }
        public TestCaMaterial Ca { get; } = TestCaMaterial.CreateCa("CN=Held Key Test CA, O=ModularCA");
        public CertificateEntity CaCert { get; }
        public SigningProfileEntity SigningProfile { get; }
        public Guid Owner { get; } = Guid.NewGuid();
        private int _serial = 100;

        public World()
        {
            Db = InMemoryDbContextFactory.Create(DatabaseName);
            Service = new HeldKeyService(Db, DataProtection, Audit, Clock);
            CaCert = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = "1", SubjectDN = Ca.SubjectDn, Issuer = Ca.SubjectDn,
                Pem = CertificateUtil.ExportCertificateToPem(Ca.Certificate), IsCA = true,
                NotBefore = Now.AddYears(-1), NotAfter = Now.AddYears(3),
            };
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Held Key Test CA", Label = "held-test", CertificateId = CaCert.CertificateId, TenantId = Guid.NewGuid() };
            SigningProfile = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "held-test", IssuerId = CaCert.CertificateId, AllowedAlgorithms = "[]" };
            Db.Certificates.Add(CaCert);
            Db.CertificateAuthorities.Add(ca);
            Db.SigningProfiles.Add(SigningProfile);
            Db.SaveChanges();
        }

        /// <summary>A request with a generated key held on it, unissued.</summary>
        public (CertRequestEntity Request, AsymmetricCipherKeyPair KeyPair) PendingRequest(string subject = "CN=holder.example.test")
        {
            var keyPair = KeyGenerationUtil.GenerateKeyPair("RSA", "2048");
            var request = new CertRequestEntity
            {
                Id = Guid.NewGuid(), Subject = subject, CSR = "-----BEGIN CERTIFICATE REQUEST-----", Status = "Pending",
                SubmittedAt = Now.AddMinutes(-10), RequestorUserId = Owner, SigningProfileId = SigningProfile.Id, KeyAlgorithm = "RSA", KeySize = "2048",
            };
            Service.Hold(request, keyPair.Private, "RSA");
            Db.CertificateRequests.Add(request);
            Db.SaveChanges();
            return (request, keyPair);
        }

        /// <summary>A request whose certificate has been issued over the held key.</summary>
        public (CertRequestEntity Request, CertificateEntity Certificate, AsymmetricCipherKeyPair KeyPair) IssuedRequest(
            string subject = "CN=holder.example.test", DateTime? notAfter = null)
        {
            var (request, keyPair) = PendingRequest(subject);
            var leaf = Ca.Issue(BigInteger.ValueOf(_serial++), subject, keyPair.Public);
            var cert = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = leaf.SerialNumber.ToString(16).ToUpperInvariant(), SubjectDN = leaf.SubjectDN.ToString(),
                Issuer = Ca.SubjectDn, Pem = CertificateUtil.ExportCertificateToPem(leaf), SigningProfileId = SigningProfile.Id,
                NotBefore = Now.AddDays(-1), NotAfter = notAfter ?? Now.AddYears(1),
            };
            Db.Certificates.Add(cert);
            request.Status = "Issued";
            request.IssuedCertificateId = cert.CertificateId;
            Db.SaveChanges();
            return (request, cert, keyPair);
        }

        public HeldKeyRequester AsOwner(bool mustOwn = true) => new(Owner, "holder", "10.0.0.1", mustOwn);
        public HeldKeyRequester AsStranger() => new(Guid.NewGuid(), "stranger", "10.0.0.2", MustOwnRequest: true);

        /// <summary>The row as a fresh context sees it, so a saved change is what is asserted.</summary>
        public CertRequestEntity Reload(Guid id)
        {
            using var db = InMemoryDbContextFactory.Create(DatabaseName);
            return db.CertificateRequests.AsNoTracking().Single(r => r.Id == id);
        }
    }

    private static Pkcs12Store Open(byte[] pkcs12, string password)
    {
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(new MemoryStream(pkcs12), password.ToCharArray());
        return store;
    }

    [Fact]
    public void A_held_key_round_trips_through_data_protection_and_is_bound_to_its_row()
    {
        var world = new World();
        var (request, keyPair) = world.PendingRequest();
        var der = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetDerEncoded();

        var held = world.Reload(request.Id);
        Assert.NotNull(held.HeldPrivateKey);
        Assert.Equal("RSA", held.HeldPrivateKeyAlgorithm);
        Assert.Null(held.HeldKeyDeliveredAt);
        Assert.NotEqual(der, held.HeldPrivateKey);
        // The modulus is the most recognisable stretch of an RSA key; it must not be in the wrap.
        var modulus = ((RsaPrivateCrtKeyParameters)keyPair.Private).Modulus.ToByteArrayUnsigned();
        var needle = modulus.AsSpan(1, 32).ToArray();
        Assert.DoesNotContain(Windows(held.HeldPrivateKey!, 32), window => window.SequenceEqual(needle));

        var unwrapped = world.DataProtection.CreateProtector(HeldKeyService.ProtectorPurpose, request.Id.ToString("D")).Unprotect(held.HeldPrivateKey!);
        Assert.Equal(der, unwrapped);
        Assert.Equal(keyPair.Private, PrivateKeyFactory.CreateKey(unwrapped));

        // Another row's protector, or another node's ring, cannot read it.
        Assert.Throws<CryptographicException>(() =>
            world.DataProtection.CreateProtector(HeldKeyService.ProtectorPurpose, Guid.NewGuid().ToString("D")).Unprotect(held.HeldPrivateKey!));
        Assert.Throws<CryptographicException>(() =>
            new EphemeralDataProtectionProvider().CreateProtector(HeldKeyService.ProtectorPurpose, request.Id.ToString("D")).Unprotect(held.HeldPrivateKey!));
    }

    [Fact]
    public async Task Delivery_returns_a_pkcs12_with_certificate_chain_and_key_and_deletes_the_key()
    {
        var world = new World();
        var (request, cert, keyPair) = world.IssuedRequest();

        var delivery = await world.Service.DeliverAsync(request.Id, Password, world.AsOwner());

        Assert.Equal(HeldKeyDeliveryOutcome.Delivered, delivery.Outcome);
        Assert.Equal("holder.example.test.pfx", delivery.FileName);
        var store = Open(delivery.Pkcs12!, Password);
        var alias = Assert.Single(store.Aliases, store.IsKeyEntry);
        Assert.Equal(keyPair.Private, store.GetKey(alias).Key);
        var chain = store.GetCertificateChain(alias);
        Assert.Equal(2, chain.Length);
        Assert.Equal(CertificateUtil.ParseFromPem(cert.Pem), chain[0].Certificate);
        Assert.Equal(world.Ca.Certificate, chain[1].Certificate);
        Assert.Equal(keyPair.Public, chain[0].Certificate.GetPublicKey());

        var row = world.Reload(request.Id);
        Assert.Null(row.HeldPrivateKey);
        Assert.Equal(Now, row.HeldKeyDeliveredAt);
        Assert.Equal("RSA", row.HeldPrivateKeyAlgorithm);

        var audit = Assert.Single(world.Audit.Entries);
        Assert.Equal(AuditActionType.HeldKeyDelivered, audit.Action);
        Assert.Equal(request.Id.ToString(), audit.TargetId);
    }

    [Fact]
    public async Task The_pkcs12_does_not_open_with_another_password()
    {
        var world = new World();
        var (request, _, _) = world.IssuedRequest();

        var delivery = await world.Service.DeliverAsync(request.Id, Password, world.AsOwner());

        Assert.ThrowsAny<Exception>(() => Open(delivery.Pkcs12!, "not the password"));
    }

    [Fact]
    public async Task A_second_delivery_is_refused_and_names_the_date()
    {
        var world = new World();
        var (request, _, _) = world.IssuedRequest();
        Assert.Equal(HeldKeyDeliveryOutcome.Delivered, (await world.Service.DeliverAsync(request.Id, Password, world.AsOwner())).Outcome);

        var again = await world.Service.DeliverAsync(request.Id, Password, world.AsOwner());

        Assert.Equal(HeldKeyDeliveryOutcome.AlreadyDelivered, again.Outcome);
        Assert.Null(again.Pkcs12);
        Assert.Equal("The private key was delivered on 2026-09-17 15:00 UTC and is not kept.", again.Detail);
        Assert.Single(world.Audit.Entries);
    }

    [Fact]
    public async Task Delivery_before_issuance_is_refused_and_the_key_stays_held()
    {
        var world = new World();
        var (request, _) = world.PendingRequest();

        var delivery = await world.Service.DeliverAsync(request.Id, Password, world.AsOwner());

        Assert.Equal(HeldKeyDeliveryOutcome.NotIssued, delivery.Outcome);
        Assert.Equal("The certificate has not been issued yet; the key is held until it is.", delivery.Detail);
        Assert.Null(delivery.Pkcs12);
        var row = world.Reload(request.Id);
        Assert.NotNull(row.HeldPrivateKey);
        Assert.Null(row.HeldKeyDeliveredAt);
        Assert.Empty(world.Audit.Entries);
    }

    [Fact]
    public async Task Someone_elses_request_is_not_found_and_the_key_stays_held()
    {
        var world = new World();
        var (request, _, _) = world.IssuedRequest();

        var delivery = await world.Service.DeliverAsync(request.Id, Password, world.AsStranger());

        Assert.Equal(HeldKeyDeliveryOutcome.NotFound, delivery.Outcome);
        Assert.Null(delivery.Pkcs12);
        Assert.NotNull(world.Reload(request.Id).HeldPrivateKey);
        Assert.Empty(world.Audit.Entries);

        // An operator whose right to the certificate the controller checked does not own it.
        var byOperator = await world.Service.DeliverAsync(request.Id, Password, new HeldKeyRequester(Guid.NewGuid(), "operator", null, MustOwnRequest: false));
        Assert.Equal(HeldKeyDeliveryOutcome.Delivered, byOperator.Outcome);
    }

    [Fact]
    public async Task A_request_made_from_a_supplied_csr_has_no_key_to_deliver()
    {
        var world = new World();
        var (request, _, _) = world.IssuedRequest();
        request.HeldPrivateKey = null;
        request.HeldPrivateKeyAlgorithm = null;
        await world.Db.SaveChangesAsync();

        var delivery = await world.Service.DeliverAsync(request.Id, Password, world.AsOwner());

        Assert.Equal(HeldKeyDeliveryOutcome.NoKeyHeld, delivery.Outcome);
        Assert.Equal(HeldKeyService.NoKeyHeldDetail, delivery.Detail);
        Assert.Null(world.Reload(request.Id).HeldKeyDeliveredAt);
    }

    [Fact]
    public async Task A_short_password_is_refused_before_the_key_is_touched()
    {
        var world = new World();
        var (request, _, _) = world.IssuedRequest();

        var delivery = await world.Service.DeliverAsync(request.Id, "short", world.AsOwner());

        Assert.Equal(HeldKeyDeliveryOutcome.InvalidPassword, delivery.Outcome);
        Assert.NotNull(world.Reload(request.Id).HeldPrivateKey);
        Assert.Equal(HeldKeyDeliveryOutcome.NotFound, (await world.Service.DeliverAsync(Guid.NewGuid(), Password, world.AsOwner())).Outcome);
    }

    [Fact]
    public async Task Rejection_and_cancellation_discard_the_held_key()
    {
        var world = new World();
        var (rejected, _) = world.PendingRequest("CN=rejected");
        var (cancelled, _) = world.PendingRequest("CN=cancelled");
        var (open, _) = world.PendingRequest("CN=open");

        // The controller path: the transition and the discard are one save.
        rejected.Status = "Rejected";
        Assert.True(world.Service.Discard(rejected));
        Assert.False(world.Service.Discard(rejected));
        await world.Db.SaveChangesAsync();
        Assert.Null(world.Reload(rejected.Id).HeldPrivateKey);

        // The sweep catches a transition that did not go through the controller.
        cancelled.Status = "Cancelled";
        await world.Db.SaveChangesAsync();
        var discarded = await world.Service.SweepAsync(Now);

        Assert.Equal(1, discarded);
        Assert.Null(world.Reload(cancelled.Id).HeldPrivateKey);
        Assert.NotNull(world.Reload(open.Id).HeldPrivateKey);
        var audit = Assert.Single(world.Audit.Entries);
        Assert.Equal(AuditActionType.HeldKeyDiscarded, audit.Action);
        Assert.Equal(cancelled.Id.ToString(), audit.TargetId);
    }

    [Fact]
    public async Task The_sweep_discards_keys_for_revoked_and_expired_certificates_and_keeps_the_rest()
    {
        var world = new World();
        var (revoked, revokedCert, _) = world.IssuedRequest("CN=revoked");
        revokedCert.Revoked = true;
        revokedCert.RevocationReason = nameof(RevocationReason.KeyCompromise);
        var (onHold, heldCert, _) = world.IssuedRequest("CN=on-hold");
        heldCert.Revoked = true;
        heldCert.RevocationReason = nameof(RevocationReason.CertificateHold);
        var (expired, _, _) = world.IssuedRequest("CN=expired", notAfter: Now.AddMinutes(-1));
        var (valid, _, _) = world.IssuedRequest("CN=valid");
        var (pending, _) = world.PendingRequest("CN=pending");
        var (staleAsk, _) = world.PendingRequest("CN=stale-ask");
        staleAsk.RequestedNotAfter = Now.AddDays(-1);
        await world.Db.SaveChangesAsync();

        var discarded = await world.Service.SweepAsync(Now);

        Assert.Equal(3, discarded);
        Assert.Null(world.Reload(revoked.Id).HeldPrivateKey);
        Assert.Null(world.Reload(expired.Id).HeldPrivateKey);
        Assert.Null(world.Reload(staleAsk.Id).HeldPrivateKey);
        Assert.NotNull(world.Reload(onHold.Id).HeldPrivateKey);
        Assert.NotNull(world.Reload(valid.Id).HeldPrivateKey);
        Assert.NotNull(world.Reload(pending.Id).HeldPrivateKey);
        Assert.Null(world.Reload(revoked.Id).HeldKeyDeliveredAt);
        Assert.Equal(3, world.Audit.Entries.Count(e => e.Action == AuditActionType.HeldKeyDiscarded));

        // A second pass finds nothing left to do.
        Assert.Equal(0, await world.Service.SweepAsync(Now));
    }

    [Fact]
    public async Task A_delivered_or_discarded_key_cannot_come_back_through_the_sweep_or_a_new_delivery()
    {
        var world = new World();
        var (request, cert, _) = world.IssuedRequest();
        Assert.Equal(HeldKeyDeliveryOutcome.Delivered, (await world.Service.DeliverAsync(request.Id, Password, world.AsOwner())).Outcome);
        cert.Revoked = true;
        cert.RevocationReason = nameof(RevocationReason.Superseded);
        await world.Db.SaveChangesAsync();

        Assert.Equal(0, await world.Service.SweepAsync(Now));
        Assert.Equal(HeldKeyDeliveryOutcome.AlreadyDelivered, (await world.Service.DeliverAsync(request.Id, Password, world.AsOwner())).Outcome);
    }

    /// <summary>Every <paramref name="width"/>-byte window of <paramref name="data"/>.</summary>
    private static IEnumerable<byte[]> Windows(byte[] data, int width)
    {
        for (var i = 0; i + width <= data.Length; i++)
            yield return data.AsSpan(i, width).ToArray();
    }
}
