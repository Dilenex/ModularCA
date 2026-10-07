using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Stage 3 of <c>docs/architecture/ssh-keystore.md</c>: the node creates SSH CA keys and signs
/// SSH certificates through the signer, and builds KRLs itself from the public key. The signer
/// in these tests is the real in-process one; <see cref="RelayingSigner"/> stands in front of it
/// only to read what the node sent, or to be the signer no real one can be made to be.
/// </summary>
public class SshCaServiceTests
{
    /// <summary>The key types an SSH CA can have: what a request names, and the OpenSSH key type it comes to.</summary>
    public static TheoryData<string, int?, string> KeyTypes => new()
    {
        { "ed25519", null, SshKeyTypes.Ed25519 },
        { "ecdsa", 256, SshKeyTypes.EcdsaP256 },
        { "ecdsa", 384, SshKeyTypes.EcdsaP384 },
        { "ecdsa", 521, SshKeyTypes.EcdsaP521 },
        { "rsa", 2048, SshKeyTypes.Rsa },
    };

    private static SshPublicKey KeyOf(SshCaKeyEntity row) => SshPublicKey.ParseAuthorizedKey(row.PublicKey);

    private static List<string> Strings(string? json) => json == null ? [] : JsonSerializer.Deserialize<List<string>>(json)!;

    /// <summary>Every row an SSH CA creation writes, read through a second context.</summary>
    private static (int Cas, int Groups, int Roles, int Grants, int Keys, int Profiles) RowCounts(SshNode node)
    {
        using var db = node.Reopen();
        return (db.CertificateAuthorities.IgnoreQueryFilters().Count(), db.CaGroups.Count(), db.RoleAssignments.Count(),
            db.CapabilityGrants.Count(), db.SshCaKeys.Count(), db.SshSigningProfiles.Count());
    }

    private static async Task<bool> SignerStillHoldsPendingAsync(SshNode node, KeyRef key, SigningContext context)
    {
        try
        {
            await node.RealSigner.RetireKeyAsync(key, context);
            return true;
        }
        catch (SigningRefusedException ex) when (ex.Reason == SigningRefusalReason.UnknownKey)
        {
            return false;
        }
    }

    // ---- Create ------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(KeyTypes))]
    public async Task An_ssh_ca_is_created_with_its_key_generated_in_the_signer_and_committed_to_its_row(string keyType, int? keySize, string sshKeyType)
    {
        using var node = new SshNode();

        var created = await node.CreateCaAsync("Fleet SSH", keyType, keySize);

        Assert.Equal(SshCaKeyStorage.Signer, created.KeyStorage);
        Assert.Null(created.PrivateKeyPath);
        Assert.Equal(keyType, created.KeyType);
        Assert.Equal(keySize, created.KeySize);
        var publicKey = KeyOf(created);
        Assert.Equal(sshKeyType, publicKey.KeyType);
        Assert.Equal("Fleet SSH", publicKey.Comment);

        using (var db = node.Reopen())
        {
            var row = await db.SshCaKeys.SingleAsync();
            Assert.Equal(created.PublicKey, row.PublicKey);
            Assert.Equal(SshCaKeyStorage.Signer, row.KeyStorage);
            Assert.Null(row.PrivateKeyPath);

            var ca = await db.CertificateAuthorities.SingleAsync();
            Assert.Equal(row.CertificateAuthorityId, ca.Id);
            Assert.True(ca.IsSshCa && ca.IsEnabled);
            Assert.Null(ca.SpaceId);
            Assert.Equal("fleet-ssh", ca.Label);

            Assert.Equal(new[] { "fleet-ssh-admin", "fleet-ssh-auditor", "fleet-ssh-operator", "fleet-ssh-user" },
                db.CaGroups.Where(g => g.CertificateAuthorityId == ca.Id).Select(g => g.Name).OrderBy(n => n).ToArray());
            Assert.Equal(4, db.RoleAssignments.Count());
            Assert.Equal(2, db.SshSigningProfiles.Count(p => p.SshCaKeyId == row.Id));
        }

        // The signer holds the key, in the SSH keystore and nowhere else, under the row's id.
        var listed = Assert.Single(await node.RealSigner.ListKeysAsync(
            SigningContext.ForCa("test", SigningPurpose.Ceremony, created.CertificateAuthorityId, null)));
        Assert.Equal(KeyKind.SshCa, listed.Kind);
        Assert.Equal(new KeyRef(created.Id, KeyRef.SshKeystore), listed.Key);
        Assert.Equal(publicKey, SshPublicKey.FromKeyParameter(PublicKeyFactory.CreateKey(listed.PublicKeyDer)));
        Assert.Single(node.Persistence.SshAppended);
        Assert.Empty(node.Persistence.Appended);

        // What the node asked for: an SSH key under a ceremony context at instance scope, then a
        // commit to the row naming the new CA.
        var (spec, generation) = Assert.Single(node.Relay.Generated);
        Assert.Equal(KeySpec.SshUsage, spec.Usage);
        Assert.Equal(SigningPurpose.Ceremony, generation.Purpose);
        Assert.True(generation.InstanceScope);
        Assert.Null(generation.SpaceId);
        Assert.Null(generation.CeremonyId);
        var (_, rowId, binding) = Assert.Single(node.Relay.Committed);
        Assert.Equal(created.Id, rowId);
        Assert.Equal(created.CertificateAuthorityId, binding.CaId);
        Assert.True(binding.InstanceScope);
        Assert.Empty(node.Relay.Retired);

        var audit = Assert.Single(node.Audit.Of(AuditActionType.SshCaKeyCreated));
        Assert.True(audit.Success);
        Assert.Equal(created.Id.ToString(), audit.TargetId);
        Assert.Equal(node.Actor.UserId, audit.ActorId);
        Assert.Equal(created.CertificateAuthorityId, audit.CaId);
        Assert.Equal(publicKey.Fingerprint,
            JsonDocument.Parse(JsonSerializer.Serialize(audit.Details)).RootElement.GetProperty("Fingerprint").GetString());
    }

    [Fact]
    public async Task A_key_size_is_chosen_when_none_is_named_and_an_unknown_type_or_size_is_refused_before_the_signer_is_asked()
    {
        using var node = new SshNode();

        Assert.Equal(256, (await node.CreateCaAsync("Default Curve", "ecdsa")).KeySize);
        Assert.Null((await node.CreateCaAsync("Fixed Size", "ED25519", 4096)).KeySize);

        var asked = node.Relay.Generated.Count;
        await Assert.ThrowsAsync<ArgumentException>(() => node.CreateCaAsync("Other A", "dsa"));
        await Assert.ThrowsAsync<ArgumentException>(() => node.CreateCaAsync("Other B", "rsa", 1024));
        await Assert.ThrowsAsync<ArgumentException>(() => node.CreateCaAsync("Other C", "ecdsa", 255));
        Assert.Equal(asked, node.Relay.Generated.Count);
        Assert.Equal(2, RowCounts(node).Cas);
    }

    [Fact]
    public async Task An_instance_that_requires_a_ceremony_gets_no_ssh_ca_without_one_and_the_ceremony_id_reaches_the_signer()
    {
        using var node = new SshNode(requireKeyCeremony: true);

        var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => node.CreateCaAsync());
        Assert.Equal(SigningRefusalReason.CeremonyRequired, refused.Reason);
        Assert.Equal((0, 0, 0, 0, 0, 0), RowCounts(node));
        Assert.False(Assert.Single(node.Audit.Of(AuditActionType.SshCaKeyCreated)).Success);

        var ceremony = new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = "CreateSshCa", Description = "Create SSH CA 'Fleet SSH'", Status = "Approved",
            RequiredApprovals = 1, CurrentApprovals = 1, ExpiresAt = DateTime.UtcNow.AddHours(1), SpaceId = null,
        };
        node.Db.KeyCeremonies.Add(ceremony);
        node.Db.SaveChanges();

        var created = await node.Service.GenerateKeyPairAsync("Fleet SSH", "ed25519", true, false, 24, ceremonyId: ceremony.Id, actor: node.Actor);

        Assert.Equal(ceremony.Id, node.Relay.Generated[^1].Context.CeremonyId);
        Assert.Equal(ceremony.Id, Assert.Single(node.Relay.Committed).Context.CeremonyId);
        Assert.Single(node.Persistence.SshAppended);
        Assert.Equal(1, RowCounts(node).Keys);
        Assert.Contains(ceremony.Id.ToString(), JsonSerializer.Serialize(node.Audit.Of(AuditActionType.SshCaKeyCreated)[^1].Details));
        Assert.Equal(SshCaKeyStorage.Signer, created.KeyStorage);
    }

    /// <summary>
    /// A signer that predates the SSH keystore ignores the key's usage, which is what the relay
    /// does to the specification here, and generates an X.509 key in <c>ca-certs.keystore</c>.
    /// </summary>
    [Fact]
    public async Task A_signer_that_predates_the_ssh_keystore_has_its_key_retired_and_no_ssh_ca_is_created()
    {
        using var node = new SshNode();
        node.Relay.RewriteSpec = spec => spec with { Usage = KeySpec.X509Usage };

        var ex = await Assert.ThrowsAsync<SshCaKeyUnavailableException>(() => node.CreateCaAsync());

        Assert.Contains(SshCaKeyUnavailableException.SignerPredatesSshKeystore, ex.Message);
        Assert.Contains("upgraded first", ex.Message);
        Assert.Null(ex.SignerReason);
        Assert.Equal((0, 0, 0, 0, 0, 0), RowCounts(node));
        Assert.Empty(node.Relay.Committed);
        var (retired, context) = Assert.Single(node.Relay.Retired);
        Assert.Equal(KeyRef.DefaultKeystore, retired.Keystore);
        Assert.False(await SignerStillHoldsPendingAsync(node, retired, context));
        Assert.Empty(node.Persistence.Appended);
        Assert.Empty(node.Persistence.SshAppended);

        var audit = Assert.Single(node.Audit.Of(AuditActionType.SshCaKeyCreated));
        Assert.False(audit.Success);
        Assert.Contains("predates", audit.Error);
    }

    [Fact]
    public async Task A_commit_the_signer_refuses_retires_the_key_and_removes_every_row()
    {
        using var node = new SshNode();
        node.Relay.OnCommit = (_, _, _) => throw new SigningRefusedException(SigningRefusalReason.CertificateMismatch, "The row does not carry the key.");

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => node.CreateCaAsync());

        Assert.Equal(SigningRefusalReason.CertificateMismatch, ex.Reason);
        Assert.Equal((0, 0, 0, 0, 0, 0), RowCounts(node));
        var (retired, context) = Assert.Single(node.Relay.Retired);
        Assert.Equal(KeyRef.SshKeystore, retired.Keystore);
        Assert.False(await SignerStillHoldsPendingAsync(node, retired, context));
        Assert.Empty(node.Persistence.SshAppended);

        // The name is free again: nothing of the failed attempt holds it.
        node.Relay.OnCommit = null;
        Assert.Equal(SshCaKeyStorage.Signer, (await node.CreateCaAsync()).KeyStorage);
    }

    [Fact]
    public async Task A_key_the_signer_cannot_write_to_its_keystore_leaves_no_ssh_ca()
    {
        using var node = new SshNode();
        node.Persistence.FailWith = new IOException("The keystore file cannot be written.");

        await Assert.ThrowsAsync<IOException>(() => node.CreateCaAsync());

        Assert.Equal((0, 0, 0, 0, 0, 0), RowCounts(node));
        Assert.Empty(await node.RealSigner.ListKeysAsync(new SigningContext("test", SigningPurpose.Ceremony, null, null) { InstanceScope = true }));
    }

    [Fact]
    public async Task A_locked_signer_creates_no_ssh_ca_and_is_reported_as_unavailable()
    {
        using var node = new SshNode(unlocked: false);

        var ex = await Assert.ThrowsAsync<SshCaKeyUnavailableException>(() => node.CreateCaAsync());

        Assert.Equal(SigningRefusalReason.SignerLocked, ex.SignerReason);
        Assert.Equal((0, 0, 0, 0, 0, 0), RowCounts(node));
    }

    // ---- Sign --------------------------------------------------------------------------------

    private static void AssertRowIsCertificate(SshCertificateEntity row, SshCertificate certificate)
    {
        var fields = certificate.Fields;
        Assert.Equal(fields.Type == SshCertificateType.Host ? "host" : "user", row.CertificateType);
        Assert.Equal((long)fields.Serial, row.SerialNumber);
        Assert.Equal(fields.KeyId, row.KeyId);
        Assert.Equal(fields.Principals, Strings(row.Principals));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds((long)fields.ValidAfter).UtcDateTime, row.ValidAfter);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds((long)fields.ValidBefore).UtcDateTime, row.ValidBefore);
        Assert.Equal(fields.SubjectKey, SshPublicKey.ParseAuthorizedKey(row.PublicKey));
        Assert.Equal(SshCertificateOptions.Describe(fields.CriticalOptions, fields.Extensions), Strings(row.Extensions));
    }

    [Theory]
    [MemberData(nameof(KeyTypes))]
    public async Task A_user_and_a_host_certificate_are_signed_by_the_signer_and_verify_under_the_ca_key(string keyType, int? keySize, string sshKeyType)
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(keyType: keyType, keySize: keySize);
        var caKey = KeyOf(ca);
        var before = DateTimeOffset.UtcNow;

        var user = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice", "ops"], 2, ["permit-pty"], node.Actor);
        var host = await node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey("ECDSA", "P-256", "host1"), ["host1.example.com"], 4, node.Actor);

        var after = DateTimeOffset.UtcNow;
        foreach (var (row, type, principals, hours) in new[]
                 {
                     (user, SshCertificateType.User, new[] { "alice", "ops" }, 2),
                     (host, SshCertificateType.Host, new[] { "host1.example.com" }, 4),
                 })
        {
            var certificate = SshCertificate.ParseOpenSsh(row.SignedCertificate);
            Assert.True(certificate.VerifySignature());
            Assert.Equal(caKey, certificate.SignatureKey);
            Assert.Equal(SshSignatureAlgorithms.ForKeyType(sshKeyType), certificate.SignatureAlgorithm);
            Assert.Equal(type, certificate.Fields.Type);
            Assert.Equal(principals, certificate.Fields.Principals);
            AssertRowIsCertificate(row, certificate);

            // The window is the hours asked, counted from a start five minutes back.
            Assert.Equal((ulong)hours * 3600, certificate.Fields.ValidBefore - certificate.Fields.ValidAfter);
            var start = DateTimeOffset.FromUnixTimeSeconds((long)certificate.Fields.ValidAfter);
            Assert.InRange(start, before - SshCaService.ValidAfterBackdate - TimeSpan.FromSeconds(2), after - SshCaService.ValidAfterBackdate + TimeSpan.FromSeconds(2));

            Assert.Equal(node.Actor.UserId, row.IssuedByUserId);
            Assert.Equal(node.Actor.SourceIp, row.SourceIp);
            Assert.Equal(ca.Id, row.SshCaKeyId);
        }
        Assert.Equal(SshNode.CiKeyId, user.KeyId);
        Assert.Equal("host1.example.com", host.KeyId);
        Assert.Null(user.SubjectUserId);
        Assert.Null(host.SubjectUserId);
        Assert.Null(host.LoginNameGrounds);
        Assert.Equal(new[] { "typed", "typed" }, SshLoginNameHolding.Parse(user.LoginNameGrounds)!.Select(g => g.Source).ToArray());
        Assert.EndsWith(" alice@laptop", user.SignedCertificate);
        Assert.Null(host.Extensions);

        // Asked under an SSH certificate context that names the SSH CA at instance scope.
        Assert.Equal(2, node.Relay.SshSigned.Count);
        Assert.All(node.Relay.SshSigned, s =>
        {
            Assert.Equal(SigningPurpose.SshCertificate, s.Context.Purpose);
            Assert.Equal(ca.CertificateAuthorityId, s.Context.CaId);
            Assert.True(s.Context.InstanceScope);
            Assert.Null(s.Context.SpaceId);
            Assert.Equal(new KeyRef(ca.Id, KeyRef.SshKeystore), s.Request.Key);
        });

        var audits = node.Audit.Of(AuditActionType.SshCertIssued);
        Assert.Equal(new[] { user.Id.ToString(), host.Id.ToString() }, audits.Select(a => a.TargetId).ToArray());
        Assert.All(audits, a => Assert.True(a.Success));
        using var db = node.Reopen();
        Assert.Equal(2, db.SshCertificates.Count());
    }

    [Fact]
    public async Task The_window_of_a_certificate_never_exceeds_the_key_s_maximum_and_defaults_to_it()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(maxValidityHours: 6);

        var longer = SshCertificate.ParseOpenSsh((await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 100, null, node.Actor)).SignedCertificate);
        var unstated = SshCertificate.ParseOpenSsh((await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], null, null, node.Actor)).SignedCertificate);

        Assert.Equal(6UL * 3600, longer.Fields.ValidBefore - longer.Fields.ValidAfter);
        Assert.Equal(6UL * 3600, unstated.Fields.ValidBefore - unstated.Fields.ValidAfter);
        Assert.Equal(TimeSpan.FromMinutes(5), SshCaService.ValidAfterBackdate);
    }

    /// <summary>What a profile names is what a certificate carries: nothing is added, and nothing is dropped silently.</summary>
    public static TheoryData<string[]?, string[], string[]> ExactOptions => new()
    {
        { null, [], [] },
        { [], [], [] },
        { ["permit-pty"], [], ["permit-pty"] },
        { ["permit-user-rc", "permit-pty", "permit-pty"], [], ["permit-pty", "permit-user-rc"] },
        { ["permit-pty", "permit-x11-forwarding", "force-command=/usr/bin/backup --all 'x' | y", "source-address=10.0.0.0/8,192.0.2.1"],
            ["force-command=/usr/bin/backup --all 'x' | y", "source-address=10.0.0.0/8,192.0.2.1"], ["permit-X11-forwarding", "permit-pty"] },
        { ["permit-pty", "no-pty", "permit-port-forwarding"], [], ["permit-port-forwarding"] },
        { ["no-port-forwarding", "No-X11-Forwarding", "permit-port-forwarding", "permit-X11-forwarding", "permit-agent-forwarding"], [], ["permit-agent-forwarding"] },
        { ["no-pty"], [], [] },
        { ["clear", "permit-agent-forwarding"], [], ["permit-agent-forwarding"] },
        { ["verify-required", "no-touch-required"], ["verify-required"], ["no-touch-required"] },
    };

    [Theory]
    [MemberData(nameof(ExactOptions))]
    public async Task A_user_certificate_carries_exactly_the_options_it_was_asked_with(string[]? asked, string[] criticalOptions, string[] extensions)
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();

        var row = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, asked?.ToList(), node.Actor);

        var certificate = SshCertificate.ParseOpenSsh(row.SignedCertificate);
        Assert.Equal(criticalOptions.OrderBy(o => o, StringComparer.Ordinal), SshCertificateOptions.Describe(certificate.Fields.CriticalOptions, []));
        Assert.Equal(extensions, SshCertificateOptions.Describe([], certificate.Fields.Extensions));
        Assert.Equal(criticalOptions.Length + extensions.Length == 0 ? null : JsonSerializer.Serialize(
            criticalOptions.OrderBy(o => o, StringComparer.Ordinal).Concat(extensions)), row.Extensions);
    }

    [Theory]
    [InlineData("permit-teleport", "permit-teleport")]
    [InlineData("permit-pty=yes", "takes no value")]
    [InlineData("no-pty=1", "no-pty")]
    [InlineData("", "Unknown extension")]
    [InlineData("source-address=10.0.0.1/8", "source-address")]
    public async Task An_option_the_signer_does_not_know_or_cannot_read_is_refused_with_its_reason(string option, string reason)
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();

        var ex = await Assert.ThrowsAsync<InvalidRequestException>(
            () => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, [option], node.Actor));

        Assert.Equal(400, ex.Status);
        Assert.Contains(reason, ex.Message);
        using var db = node.Reopen();
        Assert.Empty(db.SshCertificates);
    }

    [Fact]
    public async Task Two_values_for_one_option_are_refused_rather_than_one_being_chosen()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();

        var ex = await Assert.ThrowsAsync<InvalidRequestException>(() => node.Service.SignUserKeyAsync(
            ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, ["Force-Command=/bin/sh", "force-command=/usr/bin/restricted"], node.Actor));

        Assert.Contains("force-command", ex.Message);
        Assert.Contains("twice", ex.Message);
    }

    [Fact]
    public async Task The_principals_of_a_service_identity_reach_the_certificate_exactly_as_typed_under_the_key_id_the_ca_writes()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var principals = new List<string> { "ro ot", "dev;ops", "häns@example.com", "fe80::1" };

        var row = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, principals, 1, null, node.Actor);

        var certificate = SshCertificate.ParseOpenSsh(row.SignedCertificate);
        Assert.Equal(principals, certificate.Fields.Principals);
        Assert.Equal(SshNode.CiKeyId, certificate.Fields.KeyId);
        Assert.Equal(principals, Strings(row.Principals));
    }

    /// <summary>
    /// The row is read from the certificate the signer returned. Here the signer certifies other
    /// fields than the node asked for, which a real one does not, and the row follows the certificate.
    /// </summary>
    [Fact]
    public async Task The_row_stored_is_what_the_certificate_says_not_what_was_asked()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        node.Relay.OnSignSsh = (request, context) => node.RealSigner.SignSshCertificateAsync(request with
        {
            KeyId = "the-signer-wrote-this",
            Principals = ["someone-else"],
            ValidBefore = request.ValidBefore - 600,
            Extensions = [new SshCertificateOption("permit-user-rc")],
        }, context);

        var row = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 2, ["permit-pty"], node.Actor);

        var certificate = SshCertificate.ParseOpenSsh(row.SignedCertificate);
        AssertRowIsCertificate(row, certificate);
        Assert.Equal("the-signer-wrote-this", row.KeyId);
        Assert.Equal(new[] { "someone-else" }, Strings(row.Principals));
        Assert.Equal(new[] { "permit-user-rc" }, Strings(row.Extensions));
        Assert.Equal(TimeSpan.FromHours(2) - TimeSpan.FromMinutes(10), row.ValidBefore - row.ValidAfter);
        using var db = node.Reopen();
        Assert.Equal("the-signer-wrote-this", db.SshCertificates.Single().KeyId);
    }

    [Theory]
    [InlineData("another subject key")]
    [InlineData("another serial")]
    public async Task A_certificate_that_is_not_the_one_asked_for_is_not_stored(string difference)
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var other = SshPublicKey.ParseAuthorizedKey(SshNode.SubjectKey()).Blob;
        node.Relay.OnSignSsh = (request, context) => node.RealSigner.SignSshCertificateAsync(
            difference == "another serial" ? request with { Serial = request.Serial + 1 } : request with { SubjectPublicKey = other }, context);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor));

        using var db = node.Reopen();
        Assert.Empty(db.SshCertificates);
        Assert.Empty(node.Audit.Of(AuditActionType.SshCertIssued));
    }

    // ---- Subject keys ------------------------------------------------------------------------

    private static string SmallRsaKey()
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 1024, 80));
        return SshPublicKey.FromKeyParameter(generator.GenerateKeyPair().Public).ToAuthorizedKey();
    }

    [Fact]
    public async Task A_subject_key_that_cannot_be_certified_is_refused_as_a_bad_request_before_the_signer_is_asked()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var valid = SshNode.SubjectKey();
        var cases = new (string Key, string Says)[]
        {
            (SshNode.DsaKey(), "DSA"),
            (SmallRsaKey(), "2048"),
            (ca.PublicKey, "CA's own key"),
            ("", "empty"),
            ("ssh-ed25519 not-base64!", "base64"),
            ("ssh-ed25519 " + Convert.ToBase64String(new byte[20]), "cannot be used"),
            (valid + "\n" + valid, "one line"),
            ("sk-ssh-ed25519@openssh.com AAAA", "Security key"),
            (SshCertificate.ParseOpenSsh((await node.Service.SignUserKeyAsync(ca.Id, valid, SshNode.Ci, ["alice"], 1, null, node.Actor)).SignedCertificate).ToOpenSsh(), "certificate"),
        };
        var asked = node.Relay.SshSigned.Count;

        foreach (var (key, says) in cases)
        {
            var user = await Assert.ThrowsAsync<InvalidRequestException>(() => node.Service.SignUserKeyAsync(ca.Id, key, SshNode.Ci, ["alice"], 1, null, node.Actor));
            var host = await Assert.ThrowsAsync<InvalidRequestException>(() => node.Service.SignHostKeyAsync(ca.Id, key, ["host1"], 1, node.Actor));
            Assert.Equal(400, user.Status);
            Assert.Contains(says, user.Message);
            Assert.Contains(says, host.Message);
        }
        Assert.Equal(asked, node.Relay.SshSigned.Count);
    }

    [Fact]
    public async Task A_key_id_too_long_to_store_is_refused_before_anything_is_signed()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();

        var ex = await Assert.ThrowsAsync<InvalidRequestException>(
            () => node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), [new string('h', 256)], 1, node.Actor));

        Assert.Contains("key id", ex.Message);
        Assert.Empty(node.Relay.SshSigned);
    }

    [Fact]
    public async Task A_key_signs_only_the_certificate_types_it_is_configured_for()
    {
        using var node = new SshNode();
        var userOnly = await node.Service.GenerateKeyPairAsync("Users Only", "ed25519", isUserCa: true, isHostCa: false, 24);
        var hostOnly = await node.Service.GenerateKeyPairAsync("Hosts Only", "ed25519", isUserCa: false, isHostCa: true, 24);

        var host = await Assert.ThrowsAsync<ConfigurationValidationException>(() => node.Service.SignHostKeyAsync(userOnly.Id, SshNode.SubjectKey(), ["host1"], 1));
        var user = await Assert.ThrowsAsync<ConfigurationValidationException>(() => node.Service.SignUserKeyAsync(hostOnly.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null));

        Assert.Contains("host certificates", host.Message);
        Assert.Contains("user certificates", user.Message);
        Assert.Empty(node.Relay.SshSigned);
    }

    // ---- Refusals ----------------------------------------------------------------------------

    /// <summary>A key made before the signer held SSH keys is refused on the node: no signer is asked, and its row is left as it is.</summary>
    [Fact]
    public async Task A_key_awaiting_import_signs_nothing_and_the_signer_is_never_asked()
    {
        using var node = new SshNode();
        var legacy = node.SeedLegacyCa();
        var signer = new UnaskedSigner();
        var service = node.ServiceOver(signer);

        var user = await Assert.ThrowsAsync<SshCaKeyUnavailableException>(() => service.SignUserKeyAsync(legacy.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor));
        var host = await Assert.ThrowsAsync<SshCaKeyUnavailableException>(() => service.SignHostKeyAsync(legacy.Id, SshNode.SubjectKey(), ["host1"], 1, node.Actor));

        Assert.Contains(SshCaKeyUnavailableException.AwaitingImport, user.Message);
        Assert.Contains("SSH CA key awaiting import into the signer", host.Message);
        Assert.Null(user.SignerReason);
        Assert.False(user.RetryMayHelp);
        Assert.Equal(0, signer.Calls);

        using var db = node.Reopen();
        var row = await db.SshCaKeys.SingleAsync();
        Assert.Equal(SshCaKeyStorage.LegacyFile, row.KeyStorage);
        Assert.Equal(legacy.PrivateKeyPath, row.PrivateKeyPath);
        Assert.Empty(db.SshCertificates);

        var audits = node.Audit.Of(AuditActionType.SshCertIssued);
        Assert.Equal(2, audits.Count);
        Assert.All(audits, a =>
        {
            Assert.False(a.Success);
            Assert.Contains("awaiting import", a.Error);
            var details = JsonSerializer.Serialize(a.Details);
            Assert.DoesNotContain("alice", details);
            Assert.DoesNotContain("host1", details);
            Assert.Contains("PrincipalCount", details);
        });
    }

    /// <summary>A second signer over the same keystore and database that has not unlocked: the one a locked node asks.</summary>
    private static InProcessSigningService Locked(SshNode node)
    {
        var scopes = TestSigner.ScopesFor(node.DatabaseName);
        return new InProcessSigningService(node.Keystore, scopes, new DatabaseSignerAuditSink(scopes), node.Persistence,
            NullLogger<InProcessSigningService>.Instance, unlocked: false);
    }

    [Fact]
    public async Task A_locked_signer_is_reported_as_unavailable_with_its_reason()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();

        var ex = await Assert.ThrowsAsync<SshCaKeyUnavailableException>(
            () => node.ServiceOver(Locked(node)).SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor));

        Assert.Equal(SigningRefusalReason.SignerLocked, ex.SignerReason);
        Assert.True(ex.RetryMayHelp);
        Assert.Contains("not unlocked", ex.Message);
        Assert.False(Assert.Single(node.Audit.Of(AuditActionType.SshCertIssued)).Success);
    }

    [Fact]
    public async Task A_key_the_signer_does_not_serve_is_reported_as_unavailable_with_its_reason()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();

        // On a token, as far as the row says: the signer signs no SSH certificates for it yet.
        using (var db = node.Reopen())
        {
            db.SshCaKeys.Single().KeyStorage = SshCaKeyStorage.Pkcs11;
            db.SaveChanges();
        }
        node.Db.ChangeTracker.Clear();
        var token = await Assert.ThrowsAsync<SshCaKeyUnavailableException>(
            () => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, token.SignerReason);
        Assert.Contains(SshCaKeyStorage.Pkcs11, token.Message);

        // A signer that predates the call, as the remote client reports one.
        node.Relay.OnSignSsh = (_, _) => throw new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
            "The signer predates the SSH keystore: it does not implement SignSshCertificate. Upgrade the signer first.");
        var older = await Assert.ThrowsAsync<SshCaKeyUnavailableException>(
            () => node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["host1"], 1, node.Actor));
        Assert.Contains("predates the SSH keystore", older.Message);
    }

    [Fact]
    public async Task A_certificate_the_signer_s_rules_refuse_is_a_bad_request_with_the_signer_s_reason()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync(maxValidityHours: 6);

        var none = await Assert.ThrowsAsync<InvalidRequestException>(
            () => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, [], 1, null, node.Actor));
        Assert.Equal(400, none.Status);
        Assert.Contains("At least one principal is required", none.Message);

        var empty = await Assert.ThrowsAsync<InvalidRequestException>(
            () => node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), [""], 1, node.Actor));
        Assert.Contains("A principal is empty", empty.Message);

        var window = await Assert.ThrowsAsync<InvalidRequestException>(
            () => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 0, null, node.Actor));
        Assert.Contains("validity window is empty", window.Message);

        // Over the key's maximum: the node never asks for that, so the request is lengthened on the way.
        node.Relay.OnSignSsh = (request, context) => node.RealSigner.SignSshCertificateAsync(request with { ValidBefore = request.ValidBefore + 3600 }, context);
        var tooLong = await Assert.ThrowsAsync<InvalidRequestException>(
            () => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 6, null, node.Actor));
        Assert.Contains("maximum of 6 hours", tooLong.Message);

        using var db = node.Reopen();
        Assert.Empty(db.SshCertificates);
        Assert.Equal(4, node.Audit.Of(AuditActionType.SshCertIssued).Count(a => !a.Success));
    }

    [Fact]
    public async Task A_row_the_signer_holds_no_key_for_is_reported_as_x509_issuance_reports_a_ca_without_its_key()
    {
        using var node = new SshNode();
        var keyless = node.SeedLegacyCa();
        keyless.KeyStorage = SshCaKeyStorage.Signer;
        keyless.PrivateKeyPath = null;
        node.Db.SaveChanges();

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => node.Service.SignUserKeyAsync(keyless.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor));

        Assert.Equal(ErrorCodes.IssuingCaKeyUnavailable, ex.Code);
        Assert.Equal(400, ex.Status);
    }

    [Fact]
    public async Task Any_other_refusal_reaches_the_caller_as_the_signer_gave_it()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        node.Relay.OnSignSsh = (_, _) => throw new SigningRefusedException(SigningRefusalReason.IntegrityFailure, "The signature did not verify.");

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor));

        Assert.Equal(SigningRefusalReason.IntegrityFailure, ex.Reason);
    }

    /// <summary>The whole table, one reason at a time: three reasons are translated when signing, two when creating, and nothing else.</summary>
    [Fact]
    public void The_refusal_table_translates_the_reasons_it_names_and_no_others()
    {
        foreach (var reason in Enum.GetValues<SigningRefusalReason>())
        {
            var refusal = new SigningRefusedException(reason, $"refused: {reason}");
            var signing = SshSignerRefusals.ForSigning(refusal, "Fleet SSH");
            var creating = SshSignerRefusals.ForKeyCreation(refusal);

            switch (reason)
            {
                case SigningRefusalReason.SignerLocked:
                case SigningRefusalReason.OperationUnsupported:
                    Assert.Equal(reason, Assert.IsType<SshCaKeyUnavailableException>(signing).SignerReason);
                    Assert.Equal(refusal.Message, signing.Message);
                    Assert.Equal(reason, Assert.IsType<SshCaKeyUnavailableException>(creating).SignerReason);
                    break;
                case SigningRefusalReason.UntypedData:
                    Assert.Equal(400, Assert.IsType<InvalidRequestException>(signing).Status);
                    Assert.Equal(refusal.Message, signing.Message);
                    Assert.Same(refusal, creating);
                    break;
                case SigningRefusalReason.UnknownKey:
                    Assert.Equal(ErrorCodes.IssuingCaKeyUnavailable, Assert.IsType<ConfigurationValidationException>(signing).Code);
                    Assert.Same(refusal, creating);
                    break;
                default:
                    Assert.Same(refusal, signing);
                    Assert.Same(refusal, creating);
                    break;
            }
        }
    }

    // ---- KRL ---------------------------------------------------------------------------------

    /// <summary>A KRL read back field by field, as <c>PROTOCOL.krl</c> lays it out.</summary>
    private sealed record Krl(ulong Version, DateTimeOffset Generated, List<(SshPublicKey CaKey, List<ulong> Serials)> Sections);

    private static Krl ReadKrl(byte[] bytes)
    {
        var reader = new SshReader(bytes);
        Assert.Equal(SshKrl.Magic, reader.UInt64());
        Assert.Equal(SshKrl.FormatVersion, reader.UInt32());
        var version = reader.UInt64();
        var generated = DateTimeOffset.FromUnixTimeSeconds((long)reader.UInt64());
        Assert.Equal(0UL, reader.UInt64());
        Assert.Empty(reader.String());
        reader.Utf8String();

        var sections = new List<(SshPublicKey, List<ulong>)>();
        while (!reader.AtEnd)
        {
            Assert.Equal(1, reader.Byte());
            var section = new SshReader(reader.String());
            var caKey = SshPublicKey.FromBlob(section.String());
            Assert.Empty(section.String());
            var serials = new List<ulong>();
            while (!section.AtEnd)
            {
                Assert.Equal(0x20, section.Byte());
                var list = new SshReader(section.String());
                while (!list.AtEnd)
                    serials.Add(list.UInt64());
            }
            sections.Add((caKey, serials));
        }
        return new Krl(version, generated, sections);
    }

    /// <summary>
    /// A KRL needs the public key and the revoked serials, and nothing else: it is built for a
    /// key the signer does not hold, by a service whose signer fails any call, as on a host that
    /// only validates.
    /// </summary>
    [Fact]
    public async Task A_krl_with_nothing_revoked_is_a_valid_krl_with_no_entries_and_needs_no_signer()
    {
        using var node = new SshNode();
        var legacy = node.SeedLegacyCa();
        var signer = new UnaskedSigner();

        var krl = ReadKrl(await node.ServiceOver(signer).GenerateKrlAsync(legacy.Id));

        Assert.True(SshCaService.ServeKrlWithNoEntries);
        Assert.Empty(krl.Sections);
        Assert.Equal(0UL, krl.Version);
        Assert.InRange(krl.Generated, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal(0, signer.Calls);
        Assert.Empty(node.Audit.Entries);
    }

    [Fact]
    public async Task A_krl_lists_the_revoked_serials_of_its_own_ca_key_and_its_version_rises_with_each_revocation()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync("Fleet SSH");
        var other = await node.CreateCaAsync("Other SSH", "ecdsa", 256);
        var certs = new List<SshCertificateEntity>();
        for (var i = 0; i < 4; i++)
            certs.Add(await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, [$"user{i}"], 1, null, node.Actor));
        var elsewhere = await node.Service.SignUserKeyAsync(other.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor);
        var unasked = node.ServiceOver(new UnaskedSigner());

        Assert.True(await unasked.RevokeCertificateAsync(certs[0].Id, ca.Id, node.Actor));
        Assert.Equal(1UL, ReadKrl(await unasked.GenerateKrlAsync(ca.Id)).Version);
        Assert.True(await unasked.RevokeCertificateAsync(certs[2].Id, ca.Id, node.Actor));
        Assert.True(await unasked.RevokeCertificateAsync(elsewhere.Id, other.Id, node.Actor));
        Assert.False(await unasked.RevokeCertificateAsync(certs[3].Id, other.Id, node.Actor));

        var krl = ReadKrl(await unasked.GenerateKrlAsync(ca.Id));
        var (caKey, serials) = Assert.Single(krl.Sections);
        Assert.Equal(KeyOf(ca), caKey);
        Assert.Equal(new[] { (ulong)certs[0].SerialNumber, (ulong)certs[2].SerialNumber }.OrderBy(s => s), serials);
        Assert.Equal(2UL, krl.Version);

        var otherKrl = ReadKrl(await unasked.GenerateKrlAsync(other.Id));
        Assert.Equal(KeyOf(other), Assert.Single(otherKrl.Sections).CaKey);
        Assert.Equal(new[] { (ulong)elsewhere.SerialNumber }, otherKrl.Sections[0].Serials);

        // A revocation is what changes a KRL, and it is what the audit records; building one is not.
        Assert.Equal(new[] { certs[0].Id.ToString(), certs[2].Id.ToString(), elsewhere.Id.ToString() },
            node.Audit.Of(AuditActionType.SshCertRevoked).Select(a => a.TargetId).ToArray());
        await Assert.ThrowsAsync<InvalidOperationException>(() => unasked.GenerateKrlAsync(Guid.NewGuid()));
    }

    // ---- Disable -----------------------------------------------------------------------------

    [Fact]
    public async Task Disabling_an_ssh_ca_revokes_its_certificates_and_touches_no_key()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var legacy = node.SeedLegacyCa();
        await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor);
        await node.Service.SignHostKeyAsync(ca.Id, SshNode.SubjectKey(), ["host1"], 1, node.Actor);
        var signer = new UnaskedSigner();
        var service = node.ServiceOver(signer);
        var ceremony = Guid.NewGuid();

        await service.DisableAsync(ca.Id, node.Actor, ceremony);
        await service.DisableAsync(legacy.Id, node.Actor);

        Assert.Equal(0, signer.Calls);
        using (var db = node.Reopen())
        {
            Assert.All(db.SshCaKeys, k => Assert.False(k.IsEnabled));
            Assert.All(db.CertificateAuthorities, c => Assert.False(c.IsEnabled));
            Assert.Equal(2, db.SshCertificates.Count(c => c.IsRevoked));
            var old = db.SshCaKeys.Single(k => k.Id == legacy.Id);
            Assert.Equal(SshCaKeyStorage.LegacyFile, old.KeyStorage);
            Assert.Equal(legacy.PrivateKeyPath, old.PrivateKeyPath);
        }

        var audits = node.Audit.Of(AuditActionType.SshCaKeyDisabled);
        Assert.Equal(new[] { ca.Id.ToString(), legacy.Id.ToString() }, audits.Select(a => a.TargetId).ToArray());
        var details = JsonSerializer.Serialize(audits[0].Details);
        Assert.Contains("\"RevokedCertificates\":2", details);
        Assert.Contains(ceremony.ToString(), details);

        // The key is still in the signer, which signs nothing for a disabled row; the node refuses first.
        Assert.Single(node.Persistence.SshAppended);
        var refused = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor));
        Assert.Equal(ErrorCodes.IssuingCaDisabled, refused.Code);
        Assert.Equal(0, signer.Calls);
        Assert.Equal(2, ReadKrl(await service.GenerateKrlAsync(ca.Id)).Sections.Single().Serials.Count);
    }
}
