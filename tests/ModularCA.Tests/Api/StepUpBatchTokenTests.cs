using System.Reflection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Shared.Enums;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// One verification can cover a named list of targets, so a bulk action prompts once. Each
/// target's token is still bound to the operation and to that target, and is spent by its
/// first use: a list never becomes "any target".
/// </summary>
public class StepUpBatchTokenTests
{
    private static readonly Type Controller = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Auth.MfaStepUpController");
    private static readonly Guid User = Guid.NewGuid();
    private const string Session = "session-1";
    private const string Token = "ABCDEF";

    private static IDistributedCache NewCache() => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static Task StoreAsync(IDistributedCache cache, string operation, string? targetId, List<string>? targetIds)
        => (Task)Controller.GetMethod("StoreStepUpTokenAsync", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [cache, User, Session, operation, targetId, targetIds, Token, 90])!;

    private static Task<bool> SpendAsync(IDistributedCache cache, string operation, string? targetId, string token = Token, string session = Session)
        => (Task<bool>)Controller.GetMethod("ValidateStepUpTokenAsync",
                [typeof(IDistributedCache), typeof(Guid), typeof(string), typeof(string), typeof(string), typeof(string)])!
            .Invoke(null, [cache, User, session, token, operation, targetId])!;

    private static string? ListError(string? targetId, List<string>? targetIds)
        => (string?)Controller.GetMethod("TargetListError", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [targetId, targetIds]);

    [Fact]
    public async Task Each_listed_target_can_be_used_once()
    {
        var cache = NewCache();
        await StoreAsync(cache, StepUpOps.ApproveRequest, null, ["a", "b", "c"]);

        Assert.True(await SpendAsync(cache, StepUpOps.ApproveRequest, "a"));
        Assert.True(await SpendAsync(cache, StepUpOps.ApproveRequest, "b"));
        Assert.True(await SpendAsync(cache, StepUpOps.ApproveRequest, "c"));
        Assert.False(await SpendAsync(cache, StepUpOps.ApproveRequest, "a"));
    }

    [Fact]
    public async Task A_target_that_was_not_listed_is_refused()
    {
        var cache = NewCache();
        await StoreAsync(cache, StepUpOps.ApproveRequest, null, ["a", "b"]);

        Assert.False(await SpendAsync(cache, StepUpOps.ApproveRequest, "z"));
        Assert.False(await SpendAsync(cache, StepUpOps.ApproveRequest, null));
    }

    [Fact]
    public async Task A_listed_target_is_good_for_that_operation_session_and_token_only()
    {
        var cache = NewCache();
        await StoreAsync(cache, StepUpOps.ApproveRequest, null, ["a"]);

        Assert.False(await SpendAsync(cache, StepUpOps.RejectRequest, "a"));
        Assert.False(await SpendAsync(cache, StepUpOps.ApproveRequest, "a", session: "session-2"));
        Assert.False(await SpendAsync(cache, StepUpOps.ApproveRequest, "a", token: "000000"));
        Assert.True(await SpendAsync(cache, StepUpOps.ApproveRequest, "a"));
    }

    [Fact]
    public async Task A_single_target_still_works_as_before()
    {
        var cache = NewCache();
        await StoreAsync(cache, StepUpOps.RevokeSshCert, "one", null);

        Assert.False(await SpendAsync(cache, StepUpOps.RevokeSshCert, "two"));
        Assert.True(await SpendAsync(cache, StepUpOps.RevokeSshCert, "one"));
        Assert.False(await SpendAsync(cache, StepUpOps.RevokeSshCert, "one"));
    }

    [Fact]
    public void A_list_is_refused_when_it_is_empty_too_long_blank_or_sent_with_a_single_target()
    {
        Assert.Null(ListError("one", null));
        Assert.Null(ListError(null, null));
        Assert.Null(ListError(null, ["a", "b"]));
        Assert.Null(ListError(null, Enumerable.Range(0, 100).Select(i => $"t{i}").ToList()));

        Assert.NotNull(ListError(null, []));
        Assert.NotNull(ListError(null, ["a", " "]));
        Assert.NotNull(ListError("one", ["a"]));
        Assert.NotNull(ListError(null, Enumerable.Range(0, 101).Select(i => $"t{i}").ToList()));
    }

    [Fact]
    public void Every_operation_gated_in_rc_1_4_can_be_asked_for()
    {
        string[] added =
        [
            StepUpOps.RestartAuditChain, StepUpOps.ManageTrustAnchor, StepUpOps.RevokeSshCert,
            StepUpOps.CreateEnrollmentSecret, StepUpOps.CreateEabKey, StepUpOps.ManageUserBadge,
            StepUpOps.CreateSpace, StepUpOps.CreateCertProfile, StepUpOps.CreateRequestProfile,
            StepUpOps.CreateSigningProfile, StepUpOps.ManageSshTemplate, StepUpOps.ApproveRequest, StepUpOps.RejectRequest,
        ];

        Assert.All(added, op => Assert.Contains(op, StepUpOps.All));
        Assert.All(added, op => Assert.DoesNotContain(op, StepUpOps.AllowedViaMtls));
    }
}
