using ModularCA.Core.Services;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins the allowed-extension rule that now applies to self-service SSH signing as well as the
/// admin path.
/// </summary>
public class SshExtensionPolicyTests
{
    private const string Allowed = "[\"permit-pty\",\"permit-port-forwarding\",\"source-address\"]";

    [Fact]
    public void Extensions_on_the_list_are_permitted_by_name_or_by_exact_entry()
    {
        Assert.Null(SshExtensionPolicy.Validate(["permit-pty"], Allowed));
        // A bare entry permits any value for that name.
        Assert.Null(SshExtensionPolicy.Validate(["source-address=10.0.0.0/8"], Allowed));
    }

    [Fact]
    public void An_extension_the_profile_does_not_list_is_refused_by_name()
    {
        // The self-service defect: force-command was never on this profile's list, and the user
        // path never asked.
        var error = SshExtensionPolicy.Validate(["permit-pty", "force-command=/bin/sh"], Allowed);
        Assert.NotNull(error);
        Assert.Contains("force-command=/bin/sh", error);
    }

    [Fact]
    public void An_empty_allowed_list_places_no_restriction()
    {
        Assert.Null(SshExtensionPolicy.Validate(["force-command=/usr/bin/backup"], "[]"));
        Assert.Null(SshExtensionPolicy.Validate(["anything"], null));
    }

    [Fact]
    public void Nothing_requested_is_always_fine()
    {
        Assert.Null(SshExtensionPolicy.Validate(null, Allowed));
        Assert.Null(SshExtensionPolicy.Validate([], Allowed));
    }

    [Fact]
    public void An_unreadable_allowed_list_permits_nothing_the_caller_asked_for()
    {
        // Fail closed. A corrupt profile row must not become "no restriction".
        Assert.NotNull(SshExtensionPolicy.Validate(["permit-pty"], "not json"));
        Assert.Null(SshExtensionPolicy.Validate([], "not json"));
    }

    [Fact]
    public void An_empty_extension_string_is_refused()
    {
        Assert.NotNull(SshExtensionPolicy.Validate([""], Allowed));
    }
}
