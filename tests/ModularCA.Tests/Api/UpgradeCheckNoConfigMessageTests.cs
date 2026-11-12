using System.Reflection;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// <c>--upgrade-check</c> run as an account that may not read the config directory said
/// <c>db.yaml</c> was not found. The two cases are told apart, and the unreadable one names the
/// account and the command to use.
/// </summary>
public sealed class UpgradeCheckNoConfigMessageTests
{
    private static readonly Type Command = ApiAssembly.TypeNamed("ModularCA.API.Startup.UpgradeCheckCommand");

    private static string Message(string path, bool unreadable, string user)
        => (string)Command.GetMethod("NoDbYamlMessage", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [path, unreadable, user])!;

    [Fact]
    public void An_unreadable_file_names_the_account_and_the_command()
    {
        var message = Message("/opt/modularca/config/db.yaml", true, "edward");

        Assert.Contains("cannot be read by 'edward'", message);
        Assert.Contains("sudo -u modularca", message);
        Assert.DoesNotContain("not found", message);
    }

    [Fact]
    public void An_absent_file_is_still_not_found()
    {
        var message = Message("/opt/modularca/config/db.yaml", false, "modularca");

        Assert.Contains("not found: nothing to check", message);
        Assert.DoesNotContain("sudo", message);
    }

    /// <summary>A file that is absent, in a directory that can be read, is not "unreadable".</summary>
    [Fact]
    public void A_missing_file_in_a_readable_directory_is_not_unreadable()
    {
        var dir = Directory.CreateTempSubdirectory("uc-msg-");
        try
        {
            var unreadable = (bool)Command.GetMethod("IsUnreadable", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [Path.Combine(dir.FullName, "db.yaml")])!;
            Assert.False(unreadable);
        }
        finally
        {
            dir.Delete(true);
        }
    }
}
