using System.Reflection;
using System.Text.RegularExpressions;
using ModularCA.Core.Services;
using ModularCA.Shared.Errors;
using Xunit;

namespace ModularCA.Tests.Shared.Errors;

/// <summary>
/// Guards the properties that make an error code worth printing: it is well-formed, it is
/// unique, every refusal has one, and it does not move.
/// </summary>
/// <remarks>
/// A code only earns its place if someone can paste it into a ticket, grep a log for it, or key
/// a runbook on it a year from now. All four of those break silently if the catalog drifts —
/// a duplicated constant sends two unrelated failures to the same runbook entry, and a
/// renumbered one sends a support engineer to the wrong page with no error to tell them so.
/// </remarks>
public class ErrorCodeCatalogTests
{
    private static readonly Regex CodeShape = new(@"^MCA-[A-Z]{3}-\d{3}$", RegexOptions.Compiled);

    [Fact]
    public void Every_code_matches_the_documented_shape()
    {
        Assert.NotEmpty(ErrorCodes.All);

        foreach (var code in ErrorCodes.All)
            Assert.True(CodeShape.IsMatch(code),
                $"'{code}' does not match MCA-AREA-NNN. The shape is parsed by humans under "
                + "pressure and by log filters; both need it uniform.");
    }

    [Fact]
    public void No_two_failure_classes_share_a_code()
    {
        var duplicates = ErrorCodes.All
            .GroupBy(c => c, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        Assert.True(duplicates.Count == 0,
            "these codes are declared more than once, so two unrelated failures resolve to one "
            + "runbook entry: " + string.Join(", ", duplicates));
    }

    [Fact]
    public void Every_area_has_an_unclassified_member()
    {
        // The -000 member is what lets a new guard get a real code immediately instead of
        // waiting for someone to mint one. Without it the pressure is to leave the code blank.
        var areas = ErrorCodes.All.Select(c => c.Split('-')[1]).Distinct(StringComparer.Ordinal);

        foreach (var area in areas)
            Assert.Contains($"MCA-{area}-000", ErrorCodes.All);
    }

    [Fact]
    public void Every_member_of_the_exception_family_carries_a_code()
    {
        // Code is abstract precisely so this cannot regress, but the assertion also covers the
        // case where a subtype returns null or empty from an overridden getter.
        var subtypes = typeof(RequestValidationException).Assembly
            .GetTypes()
            .Where(t => !t.IsAbstract && typeof(RequestValidationException).IsAssignableFrom(t))
            .ToList();

        Assert.NotEmpty(subtypes);

        foreach (var type in subtypes)
        {
            var instance = (RequestValidationException)
                System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(type);

            // Two subtypes read Code from constructor-captured state, so an uninitialized
            // instance legitimately reads null; construct those for real.
            var code =
                type == typeof(ResourceNotFoundException) ? new ResourceNotFoundException("Tenant", "gone").Code
                : type == typeof(LicensingException) ? new LicensingException("x", ErrorCodes.LicenseRefused).Code
                : instance.Code;

            Assert.False(string.IsNullOrWhiteSpace(code), $"{type.Name} has no error code.");
            Assert.True(CodeShape.IsMatch(code), $"{type.Name} returned malformed code '{code}'.");
            Assert.Contains(code, ErrorCodes.All);
        }
    }

    [Fact]
    public void A_supplied_code_overrides_the_type_default()
    {
        Assert.Equal(ErrorCodes.ConfigurationRefused, new ConfigurationValidationException("x").Code);
        Assert.Equal(ErrorCodes.IssuingCaRevoked,
            new ConfigurationValidationException("x", ErrorCodes.IssuingCaRevoked).Code);

        Assert.Equal(ErrorCodes.ResourceNotFound, new ResourceNotFoundException("CSR", "x").Code);
        Assert.Equal(ErrorCodes.QuotaExceeded,
            new ResourceConflictException("x", ErrorCodes.QuotaExceeded).Code);
    }

    [Fact]
    public void Remediation_is_absent_unless_supplied()
    {
        // Null rather than empty: the client renders remediation by appending it to the message,
        // and an empty string would append a stray space to every toast.
        Assert.Null(new ConfigurationValidationException("x").Remediation);
        Assert.Equal("Widen the signing profile.",
            new ConfigurationValidationException("x", null, "Widen the signing profile.").Remediation);
    }

    [Fact]
    public void The_catalog_is_append_only()
    {
        // Pinned deliberately, and the only test here that needs editing when the catalog grows.
        // Adding a line is expected. CHANGING one means an existing code was renumbered or
        // repointed, which breaks every runbook, saved search and alert rule keyed on it — if
        // this test fails on a line you did not add, that is the bug, not the test.
        string[] pinned =
        [
            "MCA-CFG-000", "MCA-CFG-001", "MCA-CFG-002", "MCA-CFG-003", "MCA-CFG-004",
            "MCA-CFG-005", "MCA-CFG-006", "MCA-CFG-007", "MCA-CFG-008", "MCA-CFG-009",
            "MCA-CFG-010", "MCA-CFG-011", "MCA-CFG-012", "MCA-CFG-013",
            "MCA-ISS-000", "MCA-ISS-001", "MCA-ISS-002", "MCA-ISS-003",
            "MCA-LIC-000", "MCA-LIC-001", "MCA-LIC-002", "MCA-LIC-003",
            "MCA-POL-000", "MCA-POL-001",
            "MCA-PRF-000",
            "MCA-REQ-000", "MCA-REQ-001", "MCA-REQ-002", "MCA-REQ-003", "MCA-REQ-004",
            "MCA-RES-000", "MCA-RES-001", "MCA-RES-002", "MCA-RES-003", "MCA-RES-004",
            "MCA-RES-005",
        ];

        var missing = pinned.Except(ErrorCodes.All, StringComparer.Ordinal).ToList();

        Assert.True(missing.Count == 0,
            "these codes were removed or renumbered, which silently repoints anything keyed on "
            + "them: " + string.Join(", ", missing));
    }

    [Fact]
    public void The_catalog_property_cannot_drift_from_the_declarations()
    {
        // ErrorCodes.All is built by reflection so it cannot fall behind a newly added constant.
        // This pins that it is still reflection-derived rather than a hand-maintained array that
        // someone "simplified" into place.
        var declared = typeof(ErrorCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Count(f => f is { IsLiteral: true, IsInitOnly: false } && f.FieldType == typeof(string));

        Assert.Equal(declared, ErrorCodes.All.Count);
    }
}
