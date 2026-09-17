using System.Reflection;
using Xunit;

namespace ModularCA.Tests.Roles;

/// <summary>
/// The role parser: the command line wins, <c>Roles</c> in the configuration is the fallback,
/// and neither means every role; a name that is not a role is refused with the list of names.
/// </summary>
public sealed class ProcessRolesParseTests
{
    private static object Parse(string[] args, string? configured)
    {
        var parser = ApiAssembly.TypeNamed("ModularCA.API.Startup.ProcessRoles");
        var method = parser.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;
        try
        {
            return method.Invoke(null, new object?[] { args, configured })!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }

    private static object Role(string names) => NodeRoleConventionTests.RoleValue(names);

    [Fact]
    public void No_flag_and_no_configuration_is_every_role()
        => Assert.Equal(Role("All"), Parse(new[] { "--other", "x" }, null));

    [Fact]
    public void The_configuration_is_the_fallback()
        => Assert.Equal(Role("Enrollment,Validation"), Parse(Array.Empty<string>(), "enrollment, validation"));

    [Fact]
    public void The_command_line_wins_over_the_configuration()
        => Assert.Equal(Role("Control"), Parse(new[] { "--role", "control" }, "enrollment,validation"));

    [Fact]
    public void Node_is_the_three_node_roles()
        => Assert.Equal(Role("Enrollment,Validation,Control"), Parse(new[] { "--role", "node" }, null));

    [Fact]
    public void Repeated_flags_accumulate()
        => Assert.Equal(Role("Enrollment,Validation"), Parse(new[] { "--role", "enrollment", "--role", "validation" }, null));

    [Fact]
    public void A_blank_configuration_is_every_role()
        => Assert.Equal(Role("All"), Parse(Array.Empty<string>(), "  "));

    [Fact]
    public void A_name_that_is_not_a_role_is_refused_with_the_names()
    {
        var ex = Assert.Throws<ArgumentException>(() => Parse(new[] { "--role", "ingress" }, null));
        Assert.Contains("ingress", ex.Message);
        Assert.Contains("validation", ex.Message);
    }

    [Fact]
    public void A_bad_configured_name_is_refused_naming_the_configuration()
    {
        var ex = Assert.Throws<ArgumentException>(() => Parse(Array.Empty<string>(), "controll"));
        Assert.Contains("config.yaml", ex.Message);
    }

    [Fact]
    public void A_flag_without_a_value_is_refused()
        => Assert.Throws<ArgumentException>(() => Parse(new[] { "--role" }, null));
}
