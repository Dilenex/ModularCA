using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using ModularCA.Auth.Services;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth.Services;

/// <summary>
/// Pins the freshness and single-use rules of <see cref="DpopProofService"/>: a proof dated beyond
/// the clock-skew allowance is refused, a consumed jti is remembered for as long as the proof could
/// still be accepted, and concurrent presentations of one proof admit exactly one.
/// </summary>
public sealed class DpopProofServiceTests
{
    private const string Path = "/auth/refresh";
    private static readonly DateTimeOffset Start = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);

    private static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Builds a signed ES256 DPoP proof for POST <see cref="Path"/>.</summary>
    private static string Proof(ECDsa key, long iat, string? jti = null)
    {
        var p = key.ExportParameters(false);
        var header = JsonSerializer.Serialize(new
        {
            typ = "dpop+jwt", alg = "ES256",
            jwk = new { kty = "EC", crv = "P-256", x = B64Url(p.Q.X!), y = B64Url(p.Q.Y!) },
        });
        var payload = JsonSerializer.Serialize(new
        {
            htm = "POST", htu = "https://ca.example.test" + Path, iat, jti = jti ?? Guid.NewGuid().ToString("N"),
        });
        var signingInput = B64Url(Encoding.UTF8.GetBytes(header)) + "." + B64Url(Encoding.UTF8.GetBytes(payload));
        var signature = key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return signingInput + "." + B64Url(signature);
    }

    private static HttpContext Request(string proof)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = Path;
        context.Request.Headers["DPoP"] = proof;
        return context;
    }

    private static (DpopProofService Service, FixedTimeProvider Clock) Build()
    {
        var clock = new FixedTimeProvider(Start);
        return (new DpopProofService(new InProcessReplayGuard(clock), clock), clock);
    }

    [Fact]
    public async Task A_fresh_proof_is_accepted_once()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (service, _) = Build();
        var proof = Proof(key, Start.ToUnixTimeSeconds());

        Assert.NotNull(await service.GetValidatedJktAsync(Request(proof)));
        Assert.Null(await service.GetValidatedJktAsync(Request(proof)));
    }

    [Fact]
    public async Task A_proof_issued_too_far_in_the_future_is_refused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (service, _) = Build();

        // Two minutes ahead is past the one-minute skew allowance. Accepting it stretches the
        // proof's usable life past the replay entry that is meant to make it single-use.
        Assert.Null(await service.GetValidatedJktAsync(Request(Proof(key, Start.ToUnixTimeSeconds() + 120))));
    }

    [Fact]
    public async Task A_proof_within_the_clock_skew_allowance_is_accepted()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (service, _) = Build();

        Assert.NotNull(await service.GetValidatedJktAsync(
            Request(Proof(key, Start.ToUnixTimeSeconds() + (long)DpopProofService.MaxFutureSkew.TotalSeconds))));
    }

    [Fact]
    public async Task A_proof_older_than_the_window_is_refused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (service, _) = Build();

        Assert.Null(await service.GetValidatedJktAsync(
            Request(Proof(key, Start.ToUnixTimeSeconds() - (long)DpopProofService.ProofMaxAge.TotalSeconds - 1))));
    }

    [Fact]
    public async Task A_replay_is_refused_for_as_long_as_the_proof_is_still_fresh()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (service, clock) = Build();

        // Dated at the edge of the skew allowance, so it stays fresh until iat + ProofMaxAge,
        // which is MaxFutureSkew + ProofMaxAge after its first use.
        var iat = Start.ToUnixTimeSeconds() + (long)DpopProofService.MaxFutureSkew.TotalSeconds;
        var proof = Proof(key, iat);
        Assert.NotNull(await service.GetValidatedJktAsync(Request(proof)));

        // One second before the proof goes stale: the replay entry must still be there.
        clock.Now = DateTimeOffset.FromUnixTimeSeconds(iat) + DpopProofService.ProofMaxAge - TimeSpan.FromSeconds(1);
        Assert.Null(await service.GetValidatedJktAsync(Request(proof)));
    }

    [Fact]
    public async Task Concurrent_requests_with_one_proof_admit_only_one()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (service, _) = Build();
        var proof = Proof(key, Start.ToUnixTimeSeconds());

        using var gate = new ManualResetEventSlim(false);
        var tasks = Enumerable.Range(0, 16)
            .Select(_ => Task.Run(() => { gate.Wait(); return service.GetValidatedJktAsync(Request(proof)); }))
            .ToArray();
        gate.Set();
        var results = await Task.WhenAll(tasks);

        Assert.Single(results, r => r != null);
    }

    [Fact]
    public async Task The_replay_guard_admits_one_concurrent_claim_and_frees_the_key_after_its_lifetime()
    {
        var clock = new FixedTimeProvider(Start);
        var guard = new InProcessReplayGuard(clock);

        using var gate = new ManualResetEventSlim(false);
        var tasks = Enumerable.Range(0, 32)
            .Select(_ => Task.Run(() => { gate.Wait(); return guard.TryClaimAsync("k", TimeSpan.FromSeconds(10)); }))
            .ToArray();
        gate.Set();
        Assert.Single(await Task.WhenAll(tasks), claimed => claimed);

        clock.Now = Start + TimeSpan.FromSeconds(9);
        Assert.False(await guard.TryClaimAsync("k", TimeSpan.FromSeconds(10)));

        clock.Now = Start + TimeSpan.FromSeconds(10);
        Assert.True(await guard.TryClaimAsync("k", TimeSpan.FromSeconds(10)));
    }
}
