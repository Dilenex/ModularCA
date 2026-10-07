using ModularCA.Migrate;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// That the command this tool documents actually runs.
/// <para>
/// The helper was reworked so that a deployment needs to say nothing: the source comes from its
/// own db.yaml, the destination defaults to the same host, and the administrative role is
/// borrowed. What survived that rework was an argument check written when everything was
/// required, which treated an empty argument list as "you forgot something" and printed the usage
/// instead. So <c>sudo modularca-migrate</c> — the invocation named in its own help text, in the
/// documentation, and in the node's refusal to start against MariaDB — did nothing but describe
/// itself, and the only way to run a migration was to pass an option that was not needed.
/// </para>
/// </summary>
public class CommandInvocationTests
{
    [Fact]
    public void No_arguments_is_a_real_invocation_not_a_request_for_help()
    {
        // The regression. Everything else in this file is the boundary around it.
        Assert.False(CommandLine.WantsUsage([]));
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    public void Usage_is_printed_only_when_it_is_asked_for(string flag)
    {
        Assert.True(CommandLine.WantsUsage([flag]));
    }

    [Fact]
    public void A_help_flag_anywhere_still_counts()
    {
        // An operator who has assembled most of a command and wants to check an option name
        // should not have it run instead.
        Assert.True(CommandLine.WantsUsage(["--dry-run", "--help"]));
    }

    [Theory]
    [InlineData("--dry-run")]
    [InlineData("--keep-on-failure")]
    public void An_ordinary_flag_is_not_a_help_request(string flag)
    {
        Assert.False(CommandLine.WantsUsage([flag]));
    }
}
