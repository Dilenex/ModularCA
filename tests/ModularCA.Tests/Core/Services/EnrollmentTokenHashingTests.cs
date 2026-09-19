using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins the one property that makes an enrollment token a credential rather than a database
/// row: what is stored is not what is issued.
/// <para>
/// These tokens are SCEP's challenge password and the bearer value the public enrollment
/// controller accepts, so a readable <c>EnrollmentTokens.Token</c> column was enrolment rights
/// against every certificate authority it covered, for as long as the rows lived. The column now
/// holds a SHA-256 hash and every lookup hashes the presented value first — the same scheme
/// <c>JwtTokenService.HashRefreshToken</c> has always used for refresh tokens.
/// </para>
/// </summary>
public class EnrollmentTokenHashingTests
{
    private static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

    [Fact]
    public async Task A_created_token_is_returned_once_and_the_row_holds_only_its_hash()
    {
        var dbName = $"test-{Guid.NewGuid():N}";
        string issued;
        using (var db = InMemoryDbContextFactory.Create(dbName))
        {
            issued = await new EnrollmentTokenService(db).GenerateTokenAsync(
                Guid.NewGuid(), TimeSpan.FromHours(1));
        }

        Assert.False(string.IsNullOrWhiteSpace(issued));

        // A fresh context, so this reads the store rather than the change tracker.
        using var reader = InMemoryDbContextFactory.Create(dbName);
        var row = await reader.EnrollmentTokens.AsNoTracking().SingleAsync();

        // The value stored is not the value issued.
        Assert.NotEqual(issued, row.Token);
        Assert.Equal(Sha256Hex(issued), row.Token);

        // And the plaintext is nowhere in the row at all — not under another column.
        Assert.DoesNotContain(issued, new[]
        {
            row.Token, row.SubjectRestriction, row.SANRestriction, row.Protocol,
            row.CmpReferenceValue, row.CmpSecretHashBase64, row.CmpSecretWrapped,
        }.Where(v => v != null)!);
    }

    [Fact]
    public async Task The_issued_token_validates_against_the_stored_hash()
    {
        using var db = InMemoryDbContextFactory.Create();
        var service = new EnrollmentTokenService(db);

        // Unlimited uses: the consume step issues an ExecuteUpdate the in-memory provider cannot
        // run, and what is under test here is the hashed lookup, not the decrement.
        var issued = await service.GenerateTokenAsync(Guid.NewGuid(), TimeSpan.FromHours(1), maxUses: 0);

        var (ok, error) = await service.ValidateAndConsumeAsync(issued, "CN=host.example.com", "SCEP");

        Assert.True(ok, error);
        Assert.NotNull(await service.GetByTokenAsync(issued));
    }

    [Fact]
    public async Task A_spent_token_no_longer_validates_even_though_its_hash_still_matches()
    {
        // The consume itself is a single `UPDATE ... WHERE UsesRemaining > 0` issued through
        // ExecuteUpdateAsync, which the in-memory provider does not implement — the coverage
        // limit already stated on EnrollmentTokenConsumeTests. What is checked here is the half
        // that hashing touches: once the uses are gone, the hash still matches the presented
        // token and the token is refused anyway, so a correct hash is not by itself authority.
        using var db = InMemoryDbContextFactory.Create();
        var service = new EnrollmentTokenService(db);

        var issued = await service.GenerateTokenAsync(Guid.NewGuid(), TimeSpan.FromHours(1), maxUses: 1);
        var row = await db.EnrollmentTokens.SingleAsync();
        Assert.Equal(Sha256Hex(issued), row.Token);

        row.UsesRemaining = 0;
        await db.SaveChangesAsync();

        Assert.Null(await service.GetByTokenAsync(issued));

        var (ok, error) = await service.ValidateAndConsumeAsync(issued, "CN=x", "SCEP");
        Assert.False(ok);
        Assert.Contains("maximum number of times", error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_invalid_token_is_refused()
    {
        using var db = InMemoryDbContextFactory.Create();
        var service = new EnrollmentTokenService(db);
        await service.GenerateTokenAsync(Guid.NewGuid(), TimeSpan.FromHours(1), maxUses: 0);

        var (ok, error) = await service.ValidateAndConsumeAsync("not-a-token", "CN=x", "SCEP");

        Assert.False(ok);
        Assert.Contains("Invalid", error!, StringComparison.OrdinalIgnoreCase);
        Assert.Null(await service.GetByTokenAsync("not-a-token"));
    }

    [Fact]
    public async Task The_stored_value_cannot_be_replayed_as_a_token()
    {
        // The point of the change: someone who reads the table gets the hash, and the hash is
        // not a credential. Presenting it is presenting the hash of the hash.
        using var db = InMemoryDbContextFactory.Create();
        var service = new EnrollmentTokenService(db);
        await service.GenerateTokenAsync(Guid.NewGuid(), TimeSpan.FromHours(1), maxUses: 0);

        var stored = (await db.EnrollmentTokens.AsNoTracking().SingleAsync()).Token;

        var (ok, _) = await service.ValidateAndConsumeAsync(stored, "CN=x", "SCEP");

        Assert.False(ok);
        Assert.Null(await service.GetByTokenAsync(stored));
    }

    [Fact]
    public async Task A_cmp_credential_hashes_its_token_column_and_keeps_the_pbmac_secret_wrapped()
    {
        // PBMAC has to recompute a MAC, so the secret itself must survive somewhere. It survives
        // wrapped by the signer, under a key derived from the keystore: the row holds a blob the
        // node cannot open on its own, and the hashed lookup column stays a hash.
        using var db = InMemoryDbContextFactory.Create();
        var world = ModularCA.Tests.Signer.SignerTestWorld.Create();
        var signer = NewSigner(world);
        var service = new EnrollmentTokenService(db, signer);

        var (entity, plaintext) = await service.GenerateCmpSharedSecretAsync(
            Guid.NewGuid(), "printer-fleet", TimeSpan.FromHours(1), 0, null, null);

        Assert.Equal(Sha256Hex(plaintext), entity.Token);
        Assert.NotEqual(plaintext, entity.Token);

        Assert.NotNull(entity.CmpSecretWrapped);
        Assert.DoesNotContain(plaintext, entity.CmpSecretWrapped);
        Assert.Equal(plaintext[^4..], entity.CmpSecretLastFour);

        // And the signer, and only the signer, gives it back.
        var recovered = await signer.UnwrapSecretAsync(
            Convert.FromBase64String(entity.CmpSecretWrapped!),
            new ModularCA.Shared.Signing.SigningContext(
                "test", ModularCA.Shared.Signing.SigningPurpose.Cmp, null, null));
        Assert.Equal(plaintext, Encoding.UTF8.GetString(recovered));
    }

    [Fact]
    public async Task A_cmp_credential_is_not_provisioned_at_all_without_the_signer()
    {
        // The alternative to wrapping would be storing the secret in the clear, which is what
        // this replaced; there is no fallback to it.
        using var db = InMemoryDbContextFactory.Create();
        var service = new EnrollmentTokenService(db);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.GenerateCmpSharedSecretAsync(Guid.NewGuid(), "printer-fleet", TimeSpan.FromHours(1), 0, null, null));
        Assert.Empty(db.EnrollmentTokens);
    }

    /// <summary>An in-process signer over a throwaway keystore world, for the wrap the CMP credential needs.</summary>
    private static ModularCA.Shared.Signing.ISigningService NewSigner(ModularCA.Tests.Signer.SignerTestWorld world)
        => new ModularCA.Keystore.Signing.InProcessSigningService(
            world.Keystore,
            world.Scopes,
            new ModularCA.Keystore.Signing.DatabaseSignerAuditSink(world.Scopes),
            world.Persistence,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Keystore.Signing.InProcessSigningService>.Instance,
            unlocked: true);
}
