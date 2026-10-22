using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Every admin route that changes something asks for step-up MFA, or is named here with the
/// reason it does not. Step-up was added route by route, so a route added later, or a second
/// route to the same change, could be left without it: four routes that change a certificate's
/// access list were, beside two gated ones that do the same.
/// </summary>
public class StepUpGuardTests
{
    private const string Filter = "RequireStepUpAttribute";

    private const string ChangesNothing = "changes nothing: it validates, tests or reports";
    private const string RoutineIssuance = "routine issuance: left open when approving and rejecting were gated (owner, 2026-10-06)";

    /// <summary>Admin mutations that deliberately ask for no step-up, as Controller.Action → why.</summary>
    private static readonly Dictionary<string, string> DeliberatelyOpen = new(StringComparer.Ordinal)
    {
        ["AdminCertProfileController.ValidateInheritance"] = ChangesNothing,
        ["AdminRequestProfileController.ValidateInheritance"] = ChangesNothing,
        ["AdminCertSignRequestController.ParseCsr"] = ChangesNothing,
        ["AdminCertSignRequestController.ValidateAgainstProfile"] = ChangesNothing,
        ["AdminPolicyController.CheckPolicy"] = ChangesNothing,
        ["AdminComplianceController.ExportCsv"] = ChangesNothing,
        ["AdminComplianceController.GenerateReport"] = ChangesNothing,
        ["AdminLdapPublishersController.TestConnection"] = ChangesNothing,
        ["AdminNotificationController.SendTestEmail"] = "sends a test message to the configured address",
        ["AdminNotificationController.TestWebhook"] = "sends a test message to the configured webhook",

        ["AdminCertSignRequestController.Generate"] = "creates a request, which is no certificate until it is approved",
        ["AdminCertSignRequestController.UploadCsrRequest"] = "creates a request, which is no certificate until it is approved",
        ["AdminCertSignRequestController.Cancel"] = "withdraws a pending request (owner, 2026-10-06)",
        ["AdminIssuanceController.IssueCertificate"] = "follows through on an approval, which is gated (owner, 2026-10-06)",
        ["AdminIssuanceController.IssueWithServerKey"] = RoutineIssuance,
        ["AdminCertificateController.RenewCertificate"] = RoutineIssuance,

        ["AdminEnrollmentTokenController.RevokeToken"] = "takes an enrollment credential away",
        ["AdminCertificateController.AddCertificateTag"] = "a label on a certificate; trust is unchanged",
        ["AdminCertificateController.RemoveCertificateTag"] = "a label on a certificate; trust is unchanged",
        ["AdminCertificateController.RetireCertificate"] = "stops renewals from a certificate and its expiry warning; trust is unchanged",
        ["AdminCertificateController.UndoRetireCertificate"] = "lets a certificate be renewed again; trust is unchanged",
        ["AdminCertificateController.DismissExpiryWarning"] = "silences an expiry warning; trust is unchanged",
        ["AdminCertificateController.RestoreExpiryWarning"] = "brings an expiry warning back; trust is unchanged",
        ["AdminComplianceController.Resolve"] = "marks a compliance finding resolved",
        ["AdminLdapController.SyncAll"] = "re-reads the directory; grants nothing the directory does not",
        ["AdminLdapController.SyncUser"] = "re-reads the directory; grants nothing the directory does not",
        ["AdminNotificationController.UpdatePreference"] = "who is told about an event",
        ["AdminQuotaController.UpdateQuota"] = "a group's issuance quota",
        ["AdminSshController.SetReviewBy"] = "moves an SSH CA key's advisory review date: a reminder that signs, refuses and revokes nothing (owner, 2026-10-08)",
    };

    /// <summary>Admin mutations with neither the step-up filter nor a step-up check in their body, as Controller.Action → route.</summary>
    private static SortedDictionary<string, string> UngatedMutations()
    {
        var found = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var controller in ApiAssembly.ControllerTypes())
        {
            var classAttributes = controller.GetCustomAttributes(true);
            var classRoute = classAttributes.OfType<RouteAttribute>().FirstOrDefault()?.Template ?? string.Empty;
            if (!classRoute.StartsWith("api/v1/admin", StringComparison.OrdinalIgnoreCase))
                continue;

            string? source = null;
            foreach (var action in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            {
                var actionAttributes = action.GetCustomAttributes(true);
                var verbs = actionAttributes.OfType<HttpMethodAttribute>().Where(a => a is not HttpGetAttribute and not HttpHeadAttribute).ToList();
                if (verbs.Count == 0 || classAttributes.Concat(actionAttributes).OfType<IAllowAnonymous>().Any())
                    continue;
                if (actionAttributes.Any(a => a.GetType().Name == Filter))
                    continue;

                source ??= SourceOf(controller);
                if (BodyOf(source, action.Name).Contains("ValidateStepUpTokenAsync", StringComparison.Ordinal))
                    continue;

                found[$"{controller.Name}.{action.Name}"] = (classRoute + "/" + (verbs[0].Template ?? string.Empty)).TrimEnd('/');
            }
        }
        return found;
    }

    private static string SourceOf(Type controller)
    {
        var files = Directory.GetFiles(Path.Combine(RepoRoot(), "ModularCA.API", "Controllers"), controller.Name + ".cs", SearchOption.AllDirectories);
        Assert.True(files.Length == 1, $"{controller.Name}: expected one source file, found {files.Length}");
        return File.ReadAllText(files[0]);
    }

    /// <summary>The text of every overload of an action, each from its signature to the next action's verb attribute.</summary>
    private static string BodyOf(string source, string action)
    {
        var bodies = new List<string>();
        foreach (Match signature in Regex.Matches(source, @"public\s+[^\r\n(]*\b" + Regex.Escape(action) + @"\s*\("))
        {
            var next = Regex.Match(source[signature.Index..], @"^\s*\[Http\w+", RegexOptions.Multiline);
            bodies.Add(next.Success ? source.Substring(signature.Index, next.Index) : source[signature.Index..]);
        }
        Assert.True(bodies.Count > 0, $"No source found for action {action}");
        return string.Join("\n", bodies);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    [Fact]
    public void Every_admin_mutation_asks_for_step_up_or_says_why_not()
    {
        var ungated = UngatedMutations();

        var missing = ungated.Where(e => !DeliberatelyOpen.ContainsKey(e.Key)).Select(e => $"{e.Key}  ({e.Value})").ToList();
        Assert.True(missing.Count == 0,
            "Admin routes that change something with no step-up and no declared reason. Add [RequireStepUp], or name the route in DeliberatelyOpen:\n"
            + string.Join("\n", missing));

        var stale = DeliberatelyOpen.Keys.Where(k => !ungated.ContainsKey(k)).ToList();
        Assert.True(stale.Count == 0, "Listed as open, but gated or gone:\n" + string.Join("\n", stale));
    }
}
