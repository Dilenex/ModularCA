using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Keystore;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Ssh;
using ModularCA.Tests.Ssh;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// A <see cref="FactAttribute"/> that runs only when <c>ssh-keygen</c> is on the path, and is
/// otherwise reported as skipped with the reason.
/// </summary>
public sealed class RequiresSshKeygenFactAttribute : FactAttribute
{
    /// <summary>The full path of <c>ssh-keygen</c>, or null when the path holds none.</summary>
    public static string? SshKeygenPath { get; } = Find();

    /// <summary>Skips the test unless <c>ssh-keygen</c> was found.</summary>
    public RequiresSshKeygenFactAttribute()
    {
        if (SshKeygenPath == null)
            Skip = "ssh-keygen is not on the path.";
    }

    private static string? Find()
    {
        var names = OperatingSystem.IsWindows() ? new[] { "ssh-keygen.exe" } : new[] { "ssh-keygen" };
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var name in names)
            {
                try
                {
                    var candidate = Path.Combine(directory.Trim(), name);
                    if (File.Exists(candidate))
                        return candidate;
                }
                catch (ArgumentException)
                {
                }
            }
        }
        return null;
    }
}

/// <summary>
/// What an SSH CA key signs (<c>docs/architecture/ssh-keystore.md</c>, "Signing: the signer builds
/// the certificate"): a certificate the signer builds from the request's fields, and only one
/// that every rule there allows. Each test runs on both bindings. A refusal is asserted with its
/// reason and, where two rules share a reason, with the words that tell them apart.
/// </summary>
public abstract partial class SigningServiceContractTests
{
    private const string SshSignOperation = "SignSsh";
    private const string SshUserKeyId = "kid-4711@signer.test";
    private const string SshHostKeyId = "hostkey-4712";
    private static readonly string[] SshUserPrincipals = ["alice-principal", "ops-principal"];
    private static readonly string[] SshHostPrincipals = ["host1.signer.test", "host1-alias"];

    /// <summary>The key the certificates below certify, as its OpenSSH public key blob.</summary>
    private static readonly byte[] SshSubject = SshSubjectBlob("Ed25519", "");

    private static byte[] SshSubjectBlob(string algorithm, string sizeOrCurve)
        => SshPublicKey.FromKeyParameter(KeyAlgorithmPolicy.GenerateKeyPair(algorithm, sizeOrCurve).Public).Blob;

    /// <summary>The context an SSH certificate is signed under: the certificate purpose, the instance, the SSH CA.</summary>
    private static SigningContext SshSigning(Guid? caId) => InstanceContext(SigningPurpose.SshCertificate, caId);

    private static long UnixNow() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    /// <summary>A user certificate every rule allows: valid for an hour from now, with two options and two extensions out of order.</summary>
    private static SshCertificateRequest UserRequest(KeyRef key, ulong serial = 4711)
    {
        var now = UnixNow();
        return new SshCertificateRequest(key, SshSubject, SshCertificateRequest.UserType, serial, SshUserKeyId, SshUserPrincipals, now, now + 3600,
            [new("source-address", "10.0.0.0/8,2001:db8::/32"), new("force-command", "/usr/bin/true")],
            [new("permit-pty"), new("permit-agent-forwarding")]);
    }

    /// <summary>A host certificate every rule allows, which carries no options.</summary>
    private static SshCertificateRequest HostRequest(KeyRef key, ulong serial = 4712)
    {
        var now = UnixNow();
        return new SshCertificateRequest(key, SshSubject, SshCertificateRequest.HostType, serial, SshHostKeyId, SshHostPrincipals, now, now + 3600);
    }

    /// <summary>Rewrites what a CA row says, soft-deleted or not, as a node with database write could.</summary>
    private static void AlterCa(SignerTestWorld world, Guid caId, Action<CertificateAuthorityEntity> change)
    {
        using var db = world.OpenDb();
        change(db.CertificateAuthorities.IgnoreQueryFilters().Single(c => c.Id == caId));
        db.SaveChanges();
    }

    /// <summary>Asserts a refusal by its reason and by words of its message, which cross the wire with it.</summary>
    private static async Task RefusedWithAsync(SigningRefusalReason expected, string words, Func<Task> operation, string what)
    {
        var ex = await Assert.ThrowsAsync<SigningRefusedException>(operation);
        Assert.True(expected == ex.Reason, $"{what}: expected {expected}, got {ex.Reason} ({ex.Message})");
        Assert.True(ex.Message.Contains(words, StringComparison.OrdinalIgnoreCase), $"{what}: the refusal does not say '{words}': {ex.Message}");
    }

    private static IEnumerable<(string Name, string Value)> SortedOptions(IReadOnlyList<SshCertificateOption>? options)
        => (options ?? []).OrderBy(o => o.Name, StringComparer.Ordinal).Select(o => (o.Name, o.Value));

    /// <summary>
    /// Asserts that <paramref name="blob"/> is a certificate for exactly what
    /// <paramref name="request"/> asked, signed by <paramref name="caKey"/> with the algorithm
    /// its type signs with: it parses, its signature verifies under the CA key (with the library
    /// and without it), and every field is the request's.
    /// </summary>
    private static SshCertificate AssertIssued(byte[] blob, SshCertificateRequest request, SshPublicKey caKey)
    {
        var certificate = SshCertificate.Parse(blob);
        Assert.Equal(blob, certificate.Blob);
        Assert.True(certificate.VerifySignature());
        Assert.Equal(caKey, certificate.SignatureKey);
        Assert.True(SshFixtures.IndependentVerify(caKey, certificate.ToBeSigned, certificate.SignatureBlob));
        Assert.Equal(SshSignatureAlgorithms.ForKeyType(caKey.KeyType), certificate.SignatureAlgorithm);
        Assert.Equal(SshCertificateEncoder.NonceLength, certificate.Nonce.Length);
        Assert.Empty(certificate.Reserved);

        var subject = SshPublicKey.FromBlob(request.SubjectPublicKey);
        var fields = certificate.Fields;
        Assert.Equal(SshKeyTypes.CertificateType(subject.KeyType), certificate.CertificateType);
        Assert.Equal(subject, fields.SubjectKey);
        Assert.Equal(request.CertType == SshCertificateRequest.UserType ? SshCertificateType.User : SshCertificateType.Host, fields.Type);
        Assert.Equal(request.Serial, fields.Serial);
        Assert.Equal(request.KeyId, fields.KeyId);
        Assert.Equal(request.Principals, fields.Principals);
        Assert.Equal((ulong)request.ValidAfter, fields.ValidAfter);
        Assert.Equal((ulong)request.ValidBefore, fields.ValidBefore);
        Assert.Equal(SortedOptions(request.CriticalOptions), fields.CriticalOptions.Select(o => (o.Name, o.Value)));
        Assert.Equal(SortedOptions(request.Extensions), fields.Extensions.Select(o => (o.Name, o.Value)));
        return certificate;
    }

    /// <summary>The audit rows of <c>SignSsh</c> decisions, oldest first.</summary>
    private async Task<List<SignerAuditEntity>> SshSignRowsAsync(SignerTestWorld world)
        => (await ReadAuditAsync(world)).Where(r => r.Operation == SshSignOperation).ToList();

    /// <summary>
    /// Reads a row's summary: it is there, fits its column, is one line of printable ASCII, and
    /// is one JSON object.
    /// </summary>
    private static JsonElement SummaryOf(SignerAuditEntity row)
    {
        Assert.NotNull(row.Summary);
        Assert.InRange(row.Summary!.Length, 2, SignerAuditEntity.SummaryMaxLength);
        Assert.All(row.Summary, c => Assert.InRange(c, ' ', '~'));
        var summary = JsonDocument.Parse(row.Summary).RootElement;
        Assert.Equal(JsonValueKind.Object, summary.ValueKind);
        return summary;
    }

    /// <summary>
    /// Asserts that a <c>SignSsh</c> row summarises <paramref name="request"/> and nothing more:
    /// the type, serial, key id, the number of principals and the validity window, and no
    /// principal's name anywhere on the row.
    /// </summary>
    private void AssertSshRow(SignerAuditEntity row, SshCertificateRequest request, SigningContext context, bool allowed, byte[]? certificate = null)
    {
        Assert.Equal(SshSignOperation, row.Operation);
        Assert.Equal(allowed ? SignerAuditEntity.AllowedOutcome : SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Equal(request.Key.Keystore, row.Keystore);
        Assert.Equal(request.Key.CertificateId, row.KeyCertificateId);
        Assert.Equal(context.Purpose.ToString(), row.Purpose);
        Assert.Equal(context.CaId, row.CaId);
        Assert.Equal(Caller, row.Caller);
        Assert.Equal(ExpectedPeerIdentity, row.PeerIdentity);
        Assert.Equal(certificate == null ? null : Convert.ToHexStringLower(SHA256.HashData(certificate)), row.DataHash);
        Assert.Equal(allowed, row.Reason == null);

        var summary = SummaryOf(row);
        Assert.Equal(new[] { "type", "serial", "key_id", "principals", "valid_after", "valid_before" }, summary.EnumerateObject().Select(p => p.Name));
        Assert.Equal(request.CertType, summary.GetProperty("type").GetString());
        Assert.Equal(request.Serial.ToString(System.Globalization.CultureInfo.InvariantCulture), summary.GetProperty("serial").GetString());
        Assert.Equal(request.KeyId, summary.GetProperty("key_id").GetString());
        Assert.Equal(request.Principals.Count, summary.GetProperty("principals").GetInt32());
        Assert.Equal(request.ValidAfter, summary.GetProperty("valid_after").GetInt64());
        Assert.Equal(request.ValidBefore, summary.GetProperty("valid_before").GetInt64());
        AssertNamesNoPrincipal(row, request.Principals);
    }

    /// <summary>No principal is named in the summary or in the reason of a row.</summary>
    private static void AssertNamesNoPrincipal(SignerAuditEntity row, IEnumerable<string> principals)
    {
        foreach (var principal in principals.Where(p => p.Length > 0))
        {
            Assert.DoesNotContain(principal, row.Summary ?? string.Empty);
            Assert.DoesNotContain(principal, row.Reason ?? string.Empty);
        }
    }

    // ---- Issuing ------------------------------------------------------------------------------

    /// <summary>
    /// The algorithm table of the design: each kind of CA key signs a user and a host
    /// certificate, with the signature algorithm of its type, and RSA with <c>rsa-sha2-512</c>.
    /// </summary>
    [Fact]
    public async Task An_ssh_certificate_is_issued_for_each_ca_key_type_as_a_user_and_as_a_host_certificate()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var cases = new (string Algorithm, string SizeOrCurve, string SignatureAlgorithm, string AuditAlgorithm, byte[] Subject)[]
        {
            ("Ed25519", "", "ssh-ed25519", "Ed25519", SshSubjectBlob("RSA", "2048")),
            ("ECDSA", "P-256", "ecdsa-sha2-nistp256", "SHA256withECDSA", SshSubjectBlob("Ed25519", "")),
            ("ECDSA", "P-384", "ecdsa-sha2-nistp384", "SHA384withECDSA", SshSubjectBlob("ECDSA", "P-521")),
            ("ECDSA", "P-521", "ecdsa-sha2-nistp521", "SHA512withECDSA", SshSubjectBlob("ECDSA", "P-256")),
            ("RSA", "2048", "rsa-sha2-512", "SHA512withRSA", SshSubjectBlob("ECDSA", "P-384")),
        };

        ulong serial = 100;
        foreach (var (algorithm, sizeOrCurve, signatureAlgorithm, auditAlgorithm, subject) in cases)
        {
            var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer, algorithm, sizeOrCurve);
            AlterSshKeyRow(world, keyId, row => row.IsHostCa = true);
            var caKey = SshKeyOf(generated.PublicKeyDer);
            var context = SshSigning(caId);
            var user = UserRequest(sshRef, serial++) with { SubjectPublicKey = subject };
            var host = HostRequest(sshRef, serial++) with { SubjectPublicKey = subject };

            var userBlob = await signer.SignSshCertificateAsync(user, context);
            var hostBlob = await signer.SignSshCertificateAsync(host, context);

            var userCertificate = AssertIssued(userBlob, user, caKey);
            var hostCertificate = AssertIssued(hostBlob, host, caKey);
            Assert.Equal(signatureAlgorithm, userCertificate.SignatureAlgorithm);
            Assert.Equal(signatureAlgorithm, hostCertificate.SignatureAlgorithm);
            Assert.Equal(SshCertificateType.User, userCertificate.Fields.Type);
            Assert.Equal(SshCertificateType.Host, hostCertificate.Fields.Type);

            // The same request again is another certificate: the nonce is the signer's and is fresh.
            var again = AssertIssued(await signer.SignSshCertificateAsync(user, context), user, caKey);
            Assert.NotEqual(userCertificate.Nonce, again.Nonce);
            Assert.NotEqual(userBlob, again.Blob);

            var rows = (await SshSignRowsAsync(world)).Where(r => r.KeyCertificateId == keyId).ToList();
            Assert.Equal(3, rows.Count);
            AssertSshRow(rows.Single(r => r.DataHash == Convert.ToHexStringLower(SHA256.HashData(userBlob))), user, context, allowed: true, userBlob);
            AssertSshRow(rows.Single(r => r.DataHash == Convert.ToHexStringLower(SHA256.HashData(hostBlob))), host, context, allowed: true, hostBlob);
            AssertSshRow(rows.Single(r => r.DataHash == Convert.ToHexStringLower(SHA256.HashData(again.Blob))), user, context, allowed: true, again.Blob);
            Assert.All(rows, r =>
            {
                Assert.Equal(auditAlgorithm, r.Algorithm);
                Assert.Equal(SignerAuditEntity.InstanceScope, r.EffectiveScope);
                Assert.Equal(KeyRef.SshKeystore, r.Keystore);
            });
        }
        // Signing wrote nothing to any keystore: the five commits are all there is.
        Assert.Equal(cases.Length, world.Persistence.SshAppended.Count);
        Assert.Empty(world.Persistence.Appended);
    }

    /// <summary>
    /// What OpenSSH itself makes of an issued certificate, for each kind of CA key:
    /// <c>ssh-keygen -L</c> reads it and prints the fields that were asked for.
    /// </summary>
    [RequiresSshKeygenFact]
    public async Task Ssh_keygen_reads_an_issued_certificate()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var directory = Path.Combine(Path.GetTempPath(), $"mca-ssh-cert-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            foreach (var (algorithm, sizeOrCurve) in new[] { ("Ed25519", ""), ("ECDSA", "P-256"), ("ECDSA", "P-384"), ("ECDSA", "P-521"), ("RSA", "2048") })
            {
                var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer, algorithm, sizeOrCurve);
                AlterSshKeyRow(world, keyId, row => row.IsHostCa = true);
                var caKey = SshKeyOf(generated.PublicKeyDer);
                foreach (var request in new[] { UserRequest(sshRef), HostRequest(sshRef) })
                {
                    var blob = await signer.SignSshCertificateAsync(request, SshSigning(caId));
                    var path = Path.Combine(directory, $"{algorithm}-{sizeOrCurve}-{request.CertType}-cert.pub");
                    await File.WriteAllTextAsync(path, SshCertificate.ToOpenSsh(blob, "signer-contract") + "\n");

                    var (exitCode, output) = await RunSshKeygenAsync("-L", "-f", path);

                    Assert.True(exitCode == 0, $"ssh-keygen -L refused the {algorithm} {sizeOrCurve} {request.CertType} certificate: {output}");
                    Assert.Contains($"{SshKeyTypes.CertificateType(SshPublicKey.FromBlob(request.SubjectPublicKey).KeyType)} {request.CertType} certificate", output);
                    Assert.Contains($"Serial: {request.Serial}", output);
                    Assert.Contains($"Key ID: \"{request.KeyId}\"", output);
                    Assert.Contains(caKey.Fingerprint, output);
                    Assert.Contains($"(using {SshSignatureAlgorithms.ForKeyType(caKey.KeyType)})", output);
                    Assert.All(request.Principals, principal => Assert.Contains(principal, output));
                    Assert.All(request.Extensions ?? [], extension => Assert.Contains(extension.Name, output));
                    Assert.All(request.CriticalOptions ?? [], option => Assert.Contains($"{option.Name} {option.Value}", output));
                }
            }
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }
    }

    /// <summary>Runs <c>ssh-keygen</c> with no input and returns its exit code and everything it wrote.</summary>
    private static async Task<(int ExitCode, string Output)> RunSshKeygenAsync(params string[] arguments)
    {
        var start = new ProcessStartInfo(RequiresSshKeygenFactAttribute.SshKeygenPath!)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("ssh-keygen did not finish within 30 seconds.");
        }
        return (process.ExitCode, await stdout + await stderr);
    }

    // ---- The context --------------------------------------------------------------------------

    [Fact]
    public async Task An_ssh_certificate_is_signed_under_the_ssh_certificate_purpose_and_no_other()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var approved = SeedCeremony(world, "Approved", null, operationType: "CreateSshCa");
        var (generated, caId, _, sshRef) = await CommitSshKeyAsync(world, signer);
        var request = UserRequest(sshRef);

        var others = Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.SshCertificate).ToList();
        foreach (var purpose in others)
            await RefusedWithAsync(SigningRefusalReason.PurposeNotPermitted, "only under an SshCertificate context",
                () => signer.SignSshCertificateAsync(request, InstanceContext(purpose, caId)), $"an SSH certificate under {purpose}");
        // A ceremony licenses a key, never a signature.
        await RefusedWithAsync(SigningRefusalReason.PurposeNotPermitted, "only under an SshCertificate context",
            () => signer.SignSshCertificateAsync(request, SshCeremony(caId, approved)), "an SSH certificate under an approved SSH CA ceremony");

        var rows = await SshSignRowsAsync(world);
        Assert.Equal(others.Count + 1, rows.Count);
        Assert.All(rows, r =>
        {
            Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome);
            Assert.Null(r.DataHash);
            Assert.Null(r.Algorithm);
            Assert.NotEqual(nameof(SigningPurpose.SshCertificate), r.Purpose);
            SummaryOf(r);
            AssertNamesNoPrincipal(r, request.Principals);
        });

        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, SshKeyOf(generated.PublicKeyDer));
    }

    [Fact]
    public async Task An_ssh_certificate_is_signed_only_for_the_instance_and_for_the_ssh_ca_the_context_names()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, _, sshRef) = await CommitSshKeyAsync(world, signer);
        var (_, otherCa, _, _) = await CommitSshKeyAsync(world, signer);
        var request = UserRequest(sshRef);
        Task Refused(SigningRefusalReason reason, string words, SigningContext context, string what)
            => RefusedWithAsync(reason, words, () => signer.SignSshCertificateAsync(request, context), what);

        await Refused(SigningRefusalReason.TenantMismatch, "the context names space", Context(SigningPurpose.SshCertificate, caId, world.SpaceA), "a context that names a space");
        await Refused(SigningRefusalReason.ContextRequired, "states no scope", Context(SigningPurpose.SshCertificate, caId, null), "a context that does not state the instance");
        await Refused(SigningRefusalReason.ContextRequired, "requires the context to name the SSH CA", SshSigning(null), "a context that names no CA");
        await Refused(SigningRefusalReason.CaMismatch, $"not CA {otherCa}", SshSigning(otherCa), "a context that names another SSH CA");
        await Refused(SigningRefusalReason.CaMismatch, $"not CA {world.CaRsaId}", SshSigning(world.CaRsaId), "a context that names an X.509 CA");

        var rows = await SshSignRowsAsync(world);
        Assert.Equal(5, rows.Count);
        Assert.All(rows, r => AssertSshRow(r, request, SshSigning(r.CaId), allowed: false));

        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, SshKeyOf(generated.PublicKeyDer));
    }

    // ---- The key ------------------------------------------------------------------------------

    /// <summary>
    /// Only a key bound to its row in the SSH keystore signs an SSH certificate: not an X.509 CA
    /// key under any name, not a key that is still pending, and not a row that merely carries
    /// the public key of a key the signer holds elsewhere.
    /// </summary>
    [Fact]
    public async Task An_ssh_certificate_is_signed_only_with_a_key_bound_to_its_row_in_the_ssh_keystore()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer);
        var pending = await signer.GenerateKeyAsync(SshSpec(), SshCeremony());
        var (pendingCa, pendingRow) = SeedSshCa(world, AuthorizedKey(pending));
        var x509 = world["ca-ec"];
        var (x509RowCa, x509Row) = SeedSshCa(world, AuthorizedKey(x509.PublicKey));
        Task Refused(SigningRefusalReason reason, string words, KeyRef key, Guid? ca, string what)
            => RefusedWithAsync(reason, words, () => signer.SignSshCertificateAsync(UserRequest(key), SshSigning(ca)), what);

        await Refused(SigningRefusalReason.PurposeNotPermitted, "is not an SSH CA key", new KeyRef(keyId), caId, "the row id named as a key of the certificate keystore");
        await Refused(SigningRefusalReason.PurposeNotPermitted, "is not an SSH CA key", new KeyRef(keyId, KeyRef.TrustKeystore), caId, "the row id named as a key of the trust keystore");
        await Refused(SigningRefusalReason.PurposeNotPermitted, "is not an SSH CA key", x509.Ref, world.CaEcId, "an X.509 CA key");
        await Refused(SigningRefusalReason.UnknownKey, "holds no SSH CA key", new KeyRef(x509.Ref.CertificateId, KeyRef.SshKeystore), world.CaEcId, "an X.509 CA key named as a key of the SSH keystore");
        await Refused(SigningRefusalReason.UnknownKey, "holds no SSH CA key", new KeyRef(x509Row, KeyRef.SshKeystore), x509RowCa, "a row that carries the public key of an X.509 CA key");
        await Refused(SigningRefusalReason.UnknownKey, "holds no SSH CA key", pending.Key, null, "a pending SSH key by its generated reference");
        await Refused(SigningRefusalReason.UnknownKey, "holds no SSH CA key", new KeyRef(pendingRow, KeyRef.SshKeystore), pendingCa, "the row a pending SSH key is not yet committed to");
        await Refused(SigningRefusalReason.UnknownKey, "holds no SSH CA key", new KeyRef(Guid.NewGuid(), KeyRef.SshKeystore), caId, "a row id the signer has never seen");
        await Refused(SigningRefusalReason.UnknownKey, "holds no SSH CA key", KeyRef.ForKeystore(KeyRef.SshKeystore), caId, "the keystore itself");

        Assert.All(await SshSignRowsAsync(world), r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
        // The X.509 key is what it was, and the SSH key signs.
        var tbs = Typed(world, "ca-ec", SigningPurpose.Certificate);
        Assert.True(Verify(world, "ca-ec", await signer.SignAsync(x509.Ref, AlgorithmFor(world, "ca-ec"), tbs, ContextFor(world, "ca-ec", SigningPurpose.Certificate)), data: tbs));
        var request = UserRequest(sshRef);
        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, SshKeyOf(generated.PublicKeyDer));
    }

    /// <summary>A key handle that stands for a key on a token: it cannot be exported, and it counts what it is asked to sign.</summary>
    private sealed class TokenKeyHandle : IPrivateKeyHandle
    {
        public int Signatures;
        public bool CanExport => false;
        public byte[]? ExportPrivateKeyDer() => throw new NotSupportedException("A token key does not leave its token.");

        public byte[] Sign(byte[] data, string algorithm)
        {
            Interlocked.Increment(ref Signatures);
            return new byte[64];
        }
    }

    /// <summary>
    /// SSH keys on a PKCS#11 token are a later stage. Until then a key that is not a software
    /// key signs no SSH certificate, whether its row says it is on a token or says the signer
    /// holds it.
    /// </summary>
    [Fact]
    public async Task An_ssh_key_that_is_not_a_software_key_signs_no_certificate()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var publicKey = SshPublicKey.FromKeyParameter(KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Public);
        var handle = new TokenKeyHandle();
        var (caId, keyId) = SeedSshCa(world, publicKey.ToAuthorizedKey(), storage: SshCaKeyStorage.Signer);
        world.Keystore.RegisterSshKey(new SshKeyBinding(keyId, publicKey, handle));
        var request = UserRequest(new KeyRef(keyId, KeyRef.SshKeystore));

        await RefusedWithAsync(SigningRefusalReason.OperationUnsupported, "backend that signs no SSH certificates",
            () => signer.SignSshCertificateAsync(request, SshSigning(caId)), "a token key whose row says the signer holds it");
        AlterSshKeyRow(world, keyId, row => row.KeyStorage = SshCaKeyStorage.Pkcs11);
        await RefusedWithAsync(SigningRefusalReason.OperationUnsupported, $"storage '{SshCaKeyStorage.Pkcs11}'",
            () => signer.SignSshCertificateAsync(request, SshSigning(caId)), "a token key whose row says it is on a token");

        Assert.Equal(0, handle.Signatures);
        var rows = await SshSignRowsAsync(world);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => AssertSshRow(r, request, SshSigning(caId), allowed: false));
    }

    /// <summary>
    /// The last check before a certificate leaves: its signature verifies under the public key
    /// written into it. A registry that holds the wrong private key for a row, which is what a
    /// swapped keystore entry or a token answering for another object would be, yields no
    /// certificate, and the refusal is recorded.
    /// </summary>
    [Fact]
    public async Task A_certificate_whose_signature_does_not_verify_under_the_ca_public_key_is_not_handed_out()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var named = KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "");
        var wrong = new (string What, Org.BouncyCastle.Crypto.AsymmetricKeyParameter PrivateKey)[]
        {
            ("another key of the same type", KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Private),
            ("a key of another type", KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Private),
        };

        foreach (var (what, privateKey) in wrong)
        {
            var publicKey = SshPublicKey.FromKeyParameter(named.Public);
            var (caId, keyId) = SeedSshCa(world, publicKey.ToAuthorizedKey());
            world.Keystore.RegisterSshKey(new SshKeyBinding(keyId, publicKey, new ModularCA.Keystore.Adapters.SoftwarePrivateKeyHandle(privateKey)));
            var request = UserRequest(new KeyRef(keyId, KeyRef.SshKeystore));

            await RefusedWithAsync(SigningRefusalReason.IntegrityFailure, "No certificate was issued",
                () => signer.SignSshCertificateAsync(request, SshSigning(caId)), what);

            AssertSshRow((await SshSignRowsAsync(world)).Single(r => r.KeyCertificateId == keyId), request, SshSigning(caId), allowed: false);
        }

        // The right private key behind the same public key signs.
        var rightPublic = SshPublicKey.FromKeyParameter(named.Public);
        var (rightCa, rightKey) = SeedSshCa(world, rightPublic.ToAuthorizedKey());
        world.Keystore.RegisterSshKey(new SshKeyBinding(rightKey, rightPublic, new ModularCA.Keystore.Adapters.SoftwarePrivateKeyHandle(named.Private)));
        var served = UserRequest(new KeyRef(rightKey, KeyRef.SshKeystore));
        AssertIssued(await signer.SignSshCertificateAsync(served, SshSigning(rightCa)), served, rightPublic);
    }

    // ---- The row, read at every use -----------------------------------------------------------

    /// <summary>
    /// The row is read for every signature. Re-pointed at another public key after the key was
    /// bound, it gets no signature from the key the signer holds for it, and none from the key
    /// it now names either; put back, it signs again.
    /// </summary>
    [Fact]
    public async Task A_row_re_pointed_at_another_public_key_after_the_key_was_bound_is_refused_at_use()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer);
        var (otherGenerated, otherCa, otherKeyId, otherRef) = await CommitSshKeyAsync(world, signer);
        var original = AuthorizedKey(generated);
        var request = UserRequest(sshRef);
        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, SshKeyOf(generated.PublicKeyDer));
        Task Refused(string what)
            => RefusedWithAsync(SigningRefusalReason.CertificateMismatch, "no longer carries the public key", () => signer.SignSshCertificateAsync(request, SshSigning(caId)), what);

        AlterSshKeyRow(world, keyId, row => row.PublicKey = AuthorizedKey(KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Public));
        await Refused("a row re-pointed at a key the signer does not hold");
        // The other key the signer holds does not come to sign for this row by the row naming it.
        AlterSshKeyRow(world, keyId, row => row.PublicKey = AuthorizedKey(otherGenerated));
        await Refused("a row re-pointed at another key the signer holds");
        AlterSshKeyRow(world, keyId, row => row.PublicKey = AuthorizedKey(world["ca-ec"].PublicKey));
        await Refused("a row re-pointed at an X.509 CA key");
        AlterSshKeyRow(world, keyId, row => row.PublicKey = "ssh-ed25519 AAAA");
        await RefusedWithAsync(SigningRefusalReason.CertificateMismatch, "does not carry a public key the signer can read",
            () => signer.SignSshCertificateAsync(request, SshSigning(caId)), "a row whose public key does not parse");

        // The same key under another comment and spacing is the same key: the blob is compared, not the text.
        AlterSshKeyRow(world, keyId, row => row.PublicKey = "  " + original.Split(' ')[0] + "\t" + original.Split(' ')[1] + "   renamed@elsewhere  ");
        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, SshKeyOf(generated.PublicKeyDer));

        // The other row was never touched and signs with its own key throughout.
        var otherRequest = UserRequest(otherRef);
        var otherCertificate = AssertIssued(await signer.SignSshCertificateAsync(otherRequest, SshSigning(otherCa)), otherRequest, SshKeyOf(otherGenerated.PublicKeyDer));
        Assert.NotEqual(SshKeyOf(generated.PublicKeyDer), otherCertificate.SignatureKey);

        using (var db = world.OpenDb())
        {
            db.SshCaKeys.Remove(db.SshCaKeys.Single(k => k.Id == keyId));
            db.SaveChanges();
        }
        await RefusedWithAsync(SigningRefusalReason.CertificateMismatch, "No SSH CA key row",
            () => signer.SignSshCertificateAsync(request, SshSigning(caId)), "a row that is gone");
        Assert.Equal(5, (await SshSignRowsAsync(world)).Count(r => r.KeyCertificateId == keyId && r.Outcome == SignerAuditEntity.RefusedOutcome));
        Assert.Equal(otherKeyId, Assert.Single(await ListedSshKeysAsync(signer)).Key);
    }

    [Fact]
    public async Task A_disabled_ssh_ca_key_row_signs_nothing_until_it_is_enabled_again()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer);
        var request = UserRequest(sshRef);
        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, SshKeyOf(generated.PublicKeyDer));

        AlterSshKeyRow(world, keyId, row => row.IsEnabled = false);
        await RefusedWithAsync(SigningRefusalReason.OperationUnsupported, $"SSH CA key row {keyId} is disabled",
            () => signer.SignSshCertificateAsync(request, SshSigning(caId)), "a disabled row");
        AssertSshRow((await SshSignRowsAsync(world)).Single(r => r.Outcome == SignerAuditEntity.RefusedOutcome), request, SshSigning(caId), allowed: false);

        AlterSshKeyRow(world, keyId, row => row.IsEnabled = true);
        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, SshKeyOf(generated.PublicKeyDer));
    }

    [Fact]
    public async Task A_disabled_or_deleted_ssh_ca_signs_nothing()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, _, sshRef) = await CommitSshKeyAsync(world, signer);
        var request = UserRequest(sshRef);
        Task Refused(SigningRefusalReason reason, string words, string what)
            => RefusedWithAsync(reason, words, () => signer.SignSshCertificateAsync(request, SshSigning(caId)), what);

        AlterCa(world, caId, ca => ca.IsEnabled = false);
        await Refused(SigningRefusalReason.OperationUnsupported, $"SSH CA {caId} is disabled", "a disabled CA");
        AlterCa(world, caId, ca => { ca.IsEnabled = true; ca.IsDeleted = true; });
        await Refused(SigningRefusalReason.OperationUnsupported, $"SSH CA {caId} is deleted", "a deleted CA");
        AlterCa(world, caId, ca => { ca.IsDeleted = false; ca.IsSshCa = false; });
        await Refused(SigningRefusalReason.PurposeNotPermitted, "is not an SSH CA", "a CA that is no longer an SSH CA");
        AlterCa(world, caId, ca => { ca.IsSshCa = true; ca.SpaceId = world.SpaceA; });
        await Refused(SigningRefusalReason.TenantMismatch, $"belongs to space {world.SpaceA}", "a CA moved into a space");
        // Stating that space does not help: an SSH certificate is signed for the instance only.
        await RefusedWithAsync(SigningRefusalReason.TenantMismatch, "the context names space",
            () => signer.SignSshCertificateAsync(request, Context(SigningPurpose.SshCertificate, caId, world.SpaceA)), "a CA moved into a space, with a context naming the space");
        AlterCa(world, caId, ca => ca.SpaceId = null);
        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, SshKeyOf(generated.PublicKeyDer));

        using (var db = world.OpenDb())
        {
            db.CertificateAuthorities.Remove(db.CertificateAuthorities.IgnoreQueryFilters().Single(c => c.Id == caId));
            db.SaveChanges();
        }
        await Refused(SigningRefusalReason.PurposeNotPermitted, "is not an SSH CA", "a CA row that is gone");
        Assert.Equal(6, (await SshSignRowsAsync(world)).Count(r => r.Outcome == SignerAuditEntity.RefusedOutcome));
    }

    /// <summary>
    /// A row whose key is still a file on the node is one whose migration has not finished: the
    /// signer may already hold the key, and still does not sign for the row until its storage
    /// says so.
    /// </summary>
    [Fact]
    public async Task A_row_whose_storage_is_not_the_signer_signs_nothing()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var file = SshFixtures.CaPrivate("ed25519");
        var (caId, keyId) = SeedSshCa(world, SshFixtures.Text("ca-ed25519.pub"), storage: SshCaKeyStorage.LegacyFile);
        var sshRef = await signer.ImportKeyAsync(new KeyMaterial(file.ToPkcs8(), KeyMaterial.Pkcs8, keyId, KeyRef.SshKeystore), SshMigration(caId));
        var request = UserRequest(sshRef);
        Task Refused(string words, string what)
            => RefusedWithAsync(SigningRefusalReason.OperationUnsupported, words, () => signer.SignSshCertificateAsync(request, SshSigning(caId)), what);

        await Refused("awaiting import into the signer", "an imported key whose row is still a legacy file");
        AlterSshKeyRow(world, keyId, row => row.KeyStorage = SshCaKeyStorage.Pkcs11);
        await Refused($"storage '{SshCaKeyStorage.Pkcs11}'", "a row that says its key is on a token");
        AlterSshKeyRow(world, keyId, row => row.KeyStorage = "signer");
        await Refused("storage 'signer'", "a storage the signer does not know");

        // The migration's last step marks the row, and from then on the key signs.
        AlterSshKeyRow(world, keyId, row => { row.KeyStorage = SshCaKeyStorage.Signer; row.PrivateKeyPath = null; });
        AssertIssued(await signer.SignSshCertificateAsync(request, SshSigning(caId)), request, file.PublicKey);
    }

    // ---- The limits of the row ----------------------------------------------------------------

    [Fact]
    public async Task An_ssh_certificate_is_of_a_type_the_row_permits()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer);
        var caKey = SshKeyOf(generated.PublicKeyDer);
        var context = SshSigning(caId);
        var user = UserRequest(sshRef);
        var host = HostRequest(sshRef);
        Task Refused(SshCertificateRequest request, string words, string what)
            => RefusedWithAsync(SigningRefusalReason.UntypedData, words, () => signer.SignSshCertificateAsync(request, context), what);

        // A row is a user CA and not a host CA unless it says otherwise.
        AssertIssued(await signer.SignSshCertificateAsync(user, context), user, caKey);
        await Refused(host, "does not sign host certificates", "a host certificate from a user-only key");

        AlterSshKeyRow(world, keyId, row => { row.IsUserCa = false; row.IsHostCa = true; });
        await Refused(user, "does not sign user certificates", "a user certificate from a host-only key");
        AssertIssued(await signer.SignSshCertificateAsync(host, context), host, caKey);

        AlterSshKeyRow(world, keyId, row => { row.IsUserCa = false; row.IsHostCa = false; });
        await Refused(user, "does not sign user certificates", "a user certificate from a key that signs neither");
        await Refused(host, "does not sign host certificates", "a host certificate from a key that signs neither");

        AlterSshKeyRow(world, keyId, row => { row.IsUserCa = true; row.IsHostCa = true; });
        AssertIssued(await signer.SignSshCertificateAsync(user, context), user, caKey);
        AssertIssued(await signer.SignSshCertificateAsync(host, context), host, caKey);

        var refused = (await SshSignRowsAsync(world)).Where(r => r.Outcome == SignerAuditEntity.RefusedOutcome).ToList();
        Assert.Equal(4, refused.Count);
        Assert.All(refused, r => AssertSshRow(r, SummaryOf(r).GetProperty("type").GetString() == SshCertificateRequest.UserType ? user : host, context, allowed: false));
    }

    [Fact]
    public async Task An_ssh_certificate_is_valid_for_no_longer_than_the_row_allows()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer);
        var caKey = SshKeyOf(generated.PublicKeyDer);
        var context = SshSigning(caId);
        SshCertificateRequest Lasting(long seconds)
        {
            var request = UserRequest(sshRef);
            return request with { ValidBefore = request.ValidAfter + seconds };
        }
        async Task Issued(long seconds)
        {
            var request = Lasting(seconds);
            AssertIssued(await signer.SignSshCertificateAsync(request, context), request, caKey);
        }
        Task Refused(long seconds, string what)
            => RefusedWithAsync(SigningRefusalReason.UntypedData, "exceeds this SSH CA key's maximum", () => signer.SignSshCertificateAsync(Lasting(seconds), context), what);

        // A row allows 24 hours unless it says otherwise.
        await Issued(24 * 3600);
        await Refused(24 * 3600 + 1, "a second more than the row's 24 hours");
        await Refused(365L * 24 * 3600, "a year from a 24-hour key");

        // The row is read at each use, so a lowered maximum holds from the next call.
        AlterSshKeyRow(world, keyId, row => row.MaxValidityHours = 1);
        await Issued(3600);
        await Refused(3601, "a second more than a lowered maximum");

        // A maximum that is not positive permits nothing, rather than everything.
        foreach (var hours in new[] { 0, -1, int.MinValue })
        {
            AlterSshKeyRow(world, keyId, row => row.MaxValidityHours = hours);
            await Refused(1, $"one second from a key whose maximum is {hours} hours");
        }

        // The largest number a row can hold is a long time and not an error.
        AlterSshKeyRow(world, keyId, row => row.MaxValidityHours = int.MaxValue);
        await Issued(20L * 365 * 24 * 3600);
    }

    /// <summary>
    /// The start of validity is held to the signer's own clock: at most ten minutes before it,
    /// for a node that backdates and runs behind, and at most five minutes after it. The exact
    /// bounds are tested against a fixed clock in <c>SshCertificateRulesTests</c>; here a minute
    /// either side of each is tried against the real one.
    /// </summary>
    [Fact]
    public async Task An_ssh_certificate_starts_within_the_signers_clock_skew_allowance()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, _, sshRef) = await CommitSshKeyAsync(world, signer);
        var caKey = SshKeyOf(generated.PublicKeyDer);
        var context = SshSigning(caId);
        SshCertificateRequest StartingIn(long seconds)
        {
            var now = UnixNow();
            return UserRequest(sshRef) with { ValidAfter = now + seconds, ValidBefore = now + seconds + 3600 };
        }
        async Task Issued(long seconds)
        {
            var request = StartingIn(seconds);
            AssertIssued(await signer.SignSshCertificateAsync(request, context), request, caKey);
        }
        Task Refused(long seconds, string words, string what)
            => RefusedWithAsync(SigningRefusalReason.UntypedData, words, () => signer.SignSshCertificateAsync(StartingIn(seconds), context), what);

        await Issued(0);
        await Issued(-5 * 60);
        await Issued(-9 * 60);
        await Refused(-11 * 60, "starts too far in the past", "a start eleven minutes ago");
        await Refused(-24 * 3600, "starts too far in the past", "a start a day ago");
        await Issued(4 * 60);
        await Refused(6 * 60, "starts too far in the future", "a start in six minutes");
        await Refused(24 * 3600, "starts too far in the future", "a start tomorrow");
        await RefusedWithAsync(SigningRefusalReason.UntypedData, "starts too far in the past",
            () => signer.SignSshCertificateAsync(UserRequest(sshRef) with { ValidAfter = 0, ValidBefore = 3600 }, context), "a start at the epoch");
    }

    // ---- The rules of the certificate ---------------------------------------------------------

    /// <summary>A DSA public key blob over a toy group: it parses as a key, and is of a type no certificate is issued for.</summary>
    private static byte[] DsaSubjectBlob() => new SshWriter().String(SshKeyTypes.Dss)
        .MPInt(BigInteger.ValueOf(23)).MPInt(BigInteger.ValueOf(11)).MPInt(BigInteger.ValueOf(4)).MPInt(BigInteger.ValueOf(18)).ToArray();

    /// <summary>
    /// The rules every certificate is held to, whatever the row allows. They are
    /// <see cref="SshCertificateRules"/>, which has its own tests; this asserts that each one
    /// reaches a caller of the signer as a refusal, with nothing signed.
    /// </summary>
    [Fact]
    public async Task An_ssh_certificate_that_breaks_a_rule_of_the_ca_key_is_refused()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer);
        AlterSshKeyRow(world, keyId, row => row.IsHostCa = true);
        var caKey = SshKeyOf(generated.PublicKeyDer);
        var context = SshSigning(caId);
        var user = UserRequest(sshRef);
        var host = HostRequest(sshRef);
        var weak = new RsaKeyPairGenerator();
        weak.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 1024, 80));

        var broken = new (string What, string Words, SshCertificateRequest Request)[]
        {
            ("no principals", "At least one principal is required", user with { Principals = [] }),
            ("no principals on a host certificate", "At least one principal is required", host with { Principals = [] }),
            ("an empty principal", "A principal is empty", user with { Principals = ["alice-principal", ""] }),
            ("a principal longer than 256 bytes", "longer than 256 bytes", user with { Principals = [new string('a', 257)] }),
            ("a principal with a line break", "control character", user with { Principals = ["alice-principal\nroot"] }),
            ("a principal twice", "A principal appears twice", user with { Principals = ["alice-principal", "ops-principal", "alice-principal"] }),
            ("more than 256 principals", "at most 256 principals", user with { Principals = Enumerable.Range(0, 257).Select(i => $"principal-{i}").ToList() }),
            ("serial zero", "serial must not be zero", user with { Serial = 0 }),
            ("an unknown critical option", "Unknown critical option 'permit-root'", user with { CriticalOptions = [new("permit-root", "yes")] }),
            ("an extension as a critical option", "Unknown critical option 'permit-pty'", user with { CriticalOptions = [new("permit-pty")] }),
            ("a critical option twice", "appears twice", user with { CriticalOptions = [new("force-command", "a"), new("force-command", "b")] }),
            ("force-command with no command", "force-command needs a command", user with { CriticalOptions = [new("force-command")] }),
            ("a source-address that is no address", "source-address entry", user with { CriticalOptions = [new("source-address", "example.test")] }),
            ("verify-required with a value", "verify-required takes no value", user with { CriticalOptions = [new("verify-required", "yes")] }),
            ("an unknown extension", "Unknown extension 'permit-everything'", user with { Extensions = [new("permit-everything")] }),
            ("an extension with a value", "takes no value", user with { Extensions = [new("permit-pty", "yes")] }),
            ("an extension twice", "appears twice", user with { Extensions = [new("permit-pty"), new("permit-pty")] }),
            ("an extension with no name", "Unknown extension ''", user with { Extensions = [new("")] }),
            ("a host certificate with an extension", "A host certificate carries no extensions", host with { Extensions = [new("permit-pty")] }),
            ("a host certificate with a critical option", "A host certificate carries no critical options", host with { CriticalOptions = [new("force-command", "/bin/true")] }),
            ("a DSA subject key", "ssh-dss keys cannot be certified", user with { SubjectPublicKey = DsaSubjectBlob() }),
            ("an RSA subject key below 2048 bits", "RSA keys must be at least 2048 bits", user with { SubjectPublicKey = SshPublicKey.FromKeyParameter(weak.GenerateKeyPair().Public).Blob }),
            ("the CA's own key as the subject", "The subject key is the CA's own key", user with { SubjectPublicKey = caKey.Blob }),
            ("a window that ends when it starts", "validity window is empty", user with { ValidBefore = user.ValidAfter }),
            ("a window that ends before it starts", "validity window is empty", user with { ValidBefore = user.ValidAfter - 1 }),
        };

        foreach (var (what, words, request) in broken)
            await RefusedWithAsync(SigningRefusalReason.UntypedData, words, () => signer.SignSshCertificateAsync(request, context), what);

        var rows = await SshSignRowsAsync(world);
        Assert.Equal(broken.Length, rows.Count);
        Assert.All(rows, r =>
        {
            Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome);
            Assert.Null(r.DataHash);
            SummaryOf(r);
            AssertNamesNoPrincipal(r, ["alice-principal", "ops-principal", "host1.signer.test", "host1-alias", "principal-0", "principal-256"]);
        });
        // The count of principals is recorded for a refusal too, and a count is all there is.
        Assert.Contains(rows, r => SummaryOf(r).GetProperty("principals").GetInt32() == 257);
        Assert.Contains(rows, r => SummaryOf(r).GetProperty("principals").GetInt32() == 0);

        // The same key signs what breaks nothing.
        AssertIssued(await signer.SignSshCertificateAsync(user, context), user, caKey);
        AssertIssued(await signer.SignSshCertificateAsync(host, context), host, caKey);
    }

    /// <summary>
    /// A request that is not a certificate at all, which is what the wire can carry: a type that
    /// is neither of the two, a subject key that is no key, a time before the epoch. Each is a
    /// refusal the signer records, never a failure of the call.
    /// </summary>
    [Fact]
    public async Task An_ssh_certificate_request_that_is_malformed_is_refused_and_recorded()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, _, sshRef) = await CommitSshKeyAsync(world, signer);
        var context = SshSigning(caId);
        var user = UserRequest(sshRef);
        var ed25519 = SshSubject;
        var evenModulus = new SshWriter().String(SshKeyTypes.Rsa).MPInt(BigInteger.ValueOf(65537)).MPInt(BigInteger.One.ShiftLeft(2047)).ToArray();

        var malformed = new (string What, string Words, SshCertificateRequest Request)[]
        {
            ("no type", "names neither", user with { CertType = "" }),
            ("a type in capitals", "names neither", user with { CertType = "USER" }),
            ("a type with a space", "names neither", user with { CertType = "user " }),
            ("a type that is the wire number", "names neither", user with { CertType = "1" }),
            ("a type that is neither", "names neither", user with { CertType = "admin" }),
            ("no subject key", "not an OpenSSH public key blob", user with { SubjectPublicKey = [] }),
            ("a subject key that is no blob", "not an OpenSSH public key blob", user with { SubjectPublicKey = [1, 2, 3, 4, 5] }),
            ("a truncated subject key", "not an OpenSSH public key blob", user with { SubjectPublicKey = ed25519[..^1] }),
            ("a subject key with trailing bytes", "not an OpenSSH public key blob", user with { SubjectPublicKey = [.. ed25519, 0] }),
            ("a certificate as the subject key", "not an OpenSSH public key blob", user with { SubjectPublicKey = SshCertificateBlob }),
            ("an RSA subject key with an even modulus", "not an OpenSSH public key blob", user with { SubjectPublicKey = evenModulus }),
            ("a start before the epoch", "before the epoch", user with { ValidAfter = -1 }),
            ("an end before the epoch", "before the epoch", user with { ValidBefore = -1 }),
            ("the lowest times there are", "before the epoch", user with { ValidAfter = long.MinValue, ValidBefore = long.MinValue }),
        };

        foreach (var (what, words, request) in malformed)
            await RefusedWithAsync(SigningRefusalReason.UntypedData, words, () => signer.SignSshCertificateAsync(request, context), what);

        var rows = await SshSignRowsAsync(world);
        Assert.Equal(malformed.Length, rows.Count);
        foreach (var (row, (_, _, request)) in rows.Zip(malformed))
            AssertSshRow(row, request, context, allowed: false);

        AssertIssued(await signer.SignSshCertificateAsync(user, context), user, SshKeyOf(generated.PublicKeyDer));
    }

    // ---- The audit summary --------------------------------------------------------------------

    /// <summary>
    /// The key id is the caller's text. In the certificate it is whole; in the audit summary it
    /// is cut to a fixed length and escaped, so it cannot add a member to the summary, end it
    /// early or outgrow the column, whatever it holds. A key id with a control character, or one
    /// longer than the rules allow, makes no certificate, and its refusal is summarised the same way.
    /// </summary>
    [Fact]
    public async Task The_key_id_cannot_break_or_outgrow_the_audit_summary()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, _, sshRef) = await CommitSshKeyAsync(world, signer);
        var caKey = SshKeyOf(generated.PublicKeyDer);
        var context = SshSigning(caId);
        const int shown = 96;
        const string pair = "\U0001F511";
        const string beyondAscii = "bjørn@åre.example 鍵 " + pair;
        var keyIds = new (string What, string KeyId, string Summarised, bool Issued)[]
        {
            ("an attempt to add members", "\",\"principals\":999,\"type\":\"host\",\"x\":\"", "\",\"principals\":999,\"type\":\"host\",\"x\":\"", true),
            ("an attempt to end the object", "kid\"}\n{\"type\":\"host\"", "kid\"}\n{\"type\":\"host\"", false),
            ("backslashes and quotes", "a\\\"b\\\\c\\u0022", "a\\\"b\\\\c\\u0022", true),
            ("no key id", "", "", true),
            ("text outside ASCII", beyondAscii, beyondAscii, true),
            ("a key id longer than is shown", new string('k', 200), new string('k', shown), true),
            ("a key id longer than the rules allow", new string('k', 300), new string('k', shown), false),
            ("a long key id of control characters", new string('\u0001', 300), new string('\u0001', shown), false),
            ("a long key id of characters that take two code units", string.Concat(Enumerable.Repeat(pair, 200)), string.Concat(Enumerable.Repeat(pair, shown / 2)), false),
            ("a pair of code units across the cut", new string('k', shown - 1) + pair + "tail", new string('k', shown - 1), true),
            ("exactly as long as is shown", new string('k', shown), new string('k', shown), true),
        };

        async Task<SignerAuditEntity> RowOfAsync(ulong ofSerial)
            => (await SshSignRowsAsync(world)).Single(r => SummaryOf(r).GetProperty("serial").GetString() == ofSerial.ToString());

        ulong serial = 9000;
        foreach (var (what, keyId, summarised, issued) in keyIds)
        {
            var request = UserRequest(sshRef, serial++) with { KeyId = keyId };
            if (issued)
            {
                var blob = await signer.SignSshCertificateAsync(request, context);
                // The certificate carries the key id whole.
                AssertIssued(blob, request, caKey);
                Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(blob)), (await RowOfAsync(request.Serial)).DataHash);
            }
            else
            {
                await RefusedAsync(SigningRefusalReason.UntypedData, () => signer.SignSshCertificateAsync(request, context), what);
            }

            var row = await RowOfAsync(request.Serial);
            Assert.Equal(issued ? SignerAuditEntity.AllowedOutcome : SignerAuditEntity.RefusedOutcome, row.Outcome);
            var summary = SummaryOf(row);
            Assert.True(summarised == summary.GetProperty("key_id").GetString(), $"{what}: the summary's key id is not the key id's first {shown} characters.");
            Assert.Equal(summarised.Length != keyId.Length, summary.TryGetProperty("key_id_truncated", out var truncated) && truncated.GetBoolean());
            Assert.Equal(SshCertificateRequest.UserType, summary.GetProperty("type").GetString());
            Assert.Equal(request.Serial.ToString(), summary.GetProperty("serial").GetString());
            Assert.Equal(SshUserPrincipals.Length, summary.GetProperty("principals").GetInt32());
            Assert.Equal(request.ValidAfter, summary.GetProperty("valid_after").GetInt64());
            Assert.Equal(request.ValidBefore, summary.GetProperty("valid_before").GetInt64());
            Assert.Equal(summarised.Length != keyId.Length ? 7 : 6, summary.EnumerateObject().Count());
            AssertNamesNoPrincipal(row, SshUserPrincipals);
        }

        // A type that is not one is the caller's text too, and is cut as well.
        var badType = UserRequest(sshRef, serial) with { CertType = new string('\u0001', 300), KeyId = new string('\u0001', 300) };
        await RefusedAsync(SigningRefusalReason.UntypedData, () => signer.SignSshCertificateAsync(badType, context), "a long type of control characters");
        var refused = await RowOfAsync(serial);
        Assert.Equal(new string('\u0001', 16), SummaryOf(refused).GetProperty("type").GetString());
        Assert.Equal(new string('\u0001', shown), SummaryOf(refused).GetProperty("key_id").GetString());
    }

    // ---- A restart ----------------------------------------------------------------------------

    /// <summary>
    /// The key signs from the file: a signer that restarted over the same keystore files and
    /// database issues certificates under the same CA key, and holds them to the row as before.
    /// </summary>
    [Fact]
    public async Task After_a_restart_the_ssh_key_loaded_from_the_ssh_keystore_still_signs_certificates()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer, "ECDSA", "P-384");
        var legacy = SshFixtures.CaPrivate("rsa");
        var (importedCa, importedKey) = SeedSshCa(world, SshFixtures.Text("ca-rsa.pub"), storage: SshCaKeyStorage.LegacyFile);
        var importedRef = await signer.ImportKeyAsync(new KeyMaterial(legacy.ToPkcs8(), KeyMaterial.Pkcs8, importedKey, KeyRef.SshKeystore), SshMigration(importedCa));
        AlterSshKeyRow(world, importedKey, row => { row.KeyStorage = SshCaKeyStorage.Signer; row.PrivateKeyPath = null; row.IsHostCa = true; });
        var caKey = SshKeyOf(generated.PublicKeyDer);
        var before = UserRequest(sshRef, 1);
        AssertIssued(await signer.SignSshCertificateAsync(before, SshSigning(caId)), before, caKey);
        var sshFile = File.ReadAllBytes(world.Files!.Path(KeyRef.SshKeystore));

        var restarted = await CreateSignerAsync(world.Restart());

        var after = UserRequest(sshRef, 2);
        var certificate = AssertIssued(await restarted.SignSshCertificateAsync(after, SshSigning(caId)), after, caKey);
        Assert.Equal("ecdsa-sha2-nistp384", certificate.SignatureAlgorithm);
        var host = HostRequest(importedRef, 3);
        Assert.Equal("rsa-sha2-512", AssertIssued(await restarted.SignSshCertificateAsync(host, SshSigning(importedCa)), host, legacy.PublicKey).SignatureAlgorithm);

        // Still held to the row, read at each use, and still no raw signature.
        AlterSshKeyRow(world, keyId, row => row.IsEnabled = false);
        await RefusedWithAsync(SigningRefusalReason.OperationUnsupported, "is disabled", () => restarted.SignSshCertificateAsync(after, SshSigning(caId)), "a disabled row after a restart");
        await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
            () => restarted.SignAsync(importedRef, SignatureAlgorithm.FromName("SHA512withRSA"), Tbs, SshSigning(importedCa)), "a raw signature under the certificate purpose after a restart");
        // Signing wrote nothing to the file.
        Assert.Equal(sshFile, File.ReadAllBytes(world.Files!.Path(KeyRef.SshKeystore)));
    }
}
