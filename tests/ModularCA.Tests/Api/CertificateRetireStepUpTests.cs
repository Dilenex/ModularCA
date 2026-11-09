using System.Reflection;
using ModularCA.Shared.Enums;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Retiring a certificate stops every renewal path from it, so retiring and undoing it ask for
/// step-up MFA, each under its own operation and for the serial in the route (owner, 2026-10-22).
/// Dismissing and restoring an expiry warning change only a warning and ask for none.
/// </summary>
public class CertificateRetireStepUpTests
{
    private const string FilterName = "ModularCA.API.Filters.RequireStepUpAttribute";
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminCertificateController";

    private static Attribute? FilterOn(string action)
        => ApiAssembly.TypeNamed(ControllerName).GetMethod(action)!
            .GetCustomAttributes().SingleOrDefault(a => a.GetType().FullName == FilterName);

    private static string? Field(object filter, string name)
        => (string?)filter.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(filter);

    [Theory]
    [InlineData("RetireCertificate", StepUpOps.RetireCert)]
    [InlineData("UndoRetireCertificate", StepUpOps.UndoRetireCert)]
    public void Retiring_and_undoing_it_ask_for_step_up_for_the_serial(string action, string operation)
    {
        var filter = FilterOn(action);

        Assert.NotNull(filter);
        Assert.Equal(operation, Field(filter!, "_operation"));
        Assert.Equal("serial", Field(filter!, "_targetRouteParam"));
        Assert.Contains(operation, StepUpOps.All);
    }

    [Theory]
    [InlineData("DismissExpiryWarning")]
    [InlineData("RestoreExpiryWarning")]
    public void Dismissing_and_restoring_a_warning_ask_for_none(string action)
        => Assert.Null(FilterOn(action));
}
