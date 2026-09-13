using System.Text.RegularExpressions;
using ModularCA.Core.Services;
using Xunit;
using ModularCA.Shared.Errors;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins that request-caused issuance failures are reportable as 4xx.
/// <para>
/// Profile and policy rejections used to throw bare <c>Exception</c> / <c>InvalidOperationException</c>
/// out of the service layer, so "this profile does not allow RSA-PSS" and "this key is below the
/// minimum size" both arrived as HTTP 500 with a full stack trace — in the journal, indistinguishable
/// from the CA actually being broken.
/// </para>
/// </summary>
public class RequestValidationExceptionTests
{
    [Fact]
    public void A_profile_rejection_is_catchable_as_a_request_validation_failure()
    {
        // RequestValidationMiddleware catches the base type. If a subclass stops deriving from
        // it, the failure silently reverts to a 500 — this is the assertion that prevents that.
        var ex = new ProfileValidationException(
            "Signature algorithm", "SHA256withRSAandMGF1",
            ["SHA256withRSA", "SHA384withRSA"], "certificate profile");

        Assert.IsAssignableFrom<RequestValidationException>(ex);
    }

    [Fact]
    public void A_policy_violation_is_catchable_as_a_request_validation_failure()
    {
        var ex = new CertificatePolicyViolationException(
            ["[MinRsaKeySize] RSA key size of 1024 bits is below the minimum allowed 2048 bits."]);

        Assert.IsAssignableFrom<RequestValidationException>(ex);
    }

    [Fact]
    public void A_profile_rejection_says_what_is_allowed_not_just_what_failed()
    {
        // The old message was "Signature algorithm X not found in certificate profile" — true,
        // and useless: it never said which values would have worked.
        var ex = new ProfileValidationException(
            "Signature algorithm", "SHA256withRSAandMGF1",
            ["SHA256withRSA", "SHA384withRSA"], "certificate profile");

        Assert.Contains("SHA256withRSAandMGF1", ex.Message, StringComparison.Ordinal);
        Assert.Contains("SHA256withRSA, SHA384withRSA", ex.Message, StringComparison.Ordinal);
        Assert.Contains("certificate profile", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_allow_list_reads_as_none_configured_rather_than_blank()
    {
        var ex = new ProfileValidationException("Key size", "4096", [], "certificate profile");

        Assert.Contains("(none configured)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_policy_violation_lists_every_rule_that_tripped()
    {
        var ex = new CertificatePolicyViolationException(["[RequireSans] no SANs supplied", "[MinRsaKeySize] too small"]);

        Assert.Equal(2, ex.Violations.Count);
        Assert.Contains("[RequireSans] no SANs supplied", ex.Message, StringComparison.Ordinal);
        Assert.Contains("[MinRsaKeySize] too small", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_family_answers_400_unless_a_subtype_says_otherwise()
    {
        // The default is what the whole family relied on before Status existed. If it drifts,
        // every unmigrated subtype changes status at once.
        Assert.Equal(400, new ProfileValidationException("Key size", "1024", ["2048"], "signing profile").Status);
        Assert.Equal(400, new CertificatePolicyViolationException(["[Rule] nope"]).Status);
        Assert.Equal(400, new ConfigurationValidationException("nope").Status);
    }

    [Fact]
    public void A_missing_resource_answers_404_so_the_client_can_tell_it_from_a_refusal()
    {
        // The admin UI branches on status. While every member of this family answered 400, a
        // "you named a CA that does not exist" was indistinguishable from "this CA refuses the
        // operation", and the two need different handling on screen.
        var ex = new ResourceNotFoundException(
            "Certificate authority", "Certificate authority not found.", "9f2e");

        Assert.Equal(404, ex.Status);
        Assert.Equal("Certificate authority", ex.ResourceKind);
        Assert.Equal("9f2e", ex.Identifier);
        Assert.IsAssignableFrom<RequestValidationException>(ex);
    }

    [Fact]
    public void A_collision_answers_409_because_the_same_request_will_work_once_it_is_resolved()
    {
        var ex = new ResourceConflictException("A CA with label 'issuing-01' already exists in this tenant.");

        Assert.Equal(409, ex.Status);
        Assert.IsAssignableFrom<RequestValidationException>(ex);
    }

    [Fact]
    public void A_configuration_refusal_keeps_the_sentence_the_guard_wrote()
    {
        // The entire point of the migration: these guards name the rule, the consequence and the
        // fix, and the catch-all used to replace all of it with "Please try again."
        const string written =
            "This CA's signing profile does not permit ocspSigning, so a reissued certificate "
            + "would be issued without that extended key usage and would not work.";

        var ex = new ConfigurationValidationException(written);

        Assert.Equal(written, ex.Message);
        Assert.IsAssignableFrom<RequestValidationException>(ex);
    }

    [Fact]
    public void Every_member_of_the_family_is_a_4xx()
    {
        // The family's contract is "the request was at fault". A subtype answering 5xx would
        // tell the caller their request was wrong when it was not, and would also route a
        // server-state failure through a middleware that does not sanitize the message. The
        // tempting future mistake is a ServerConfigurationException added here for convenience;
        // this is the assertion that stops it.
        var subtypes = typeof(RequestValidationException).Assembly
            .GetTypes()
            .Where(t => !t.IsAbstract && typeof(RequestValidationException).IsAssignableFrom(t))
            .ToList();

        Assert.NotEmpty(subtypes);

        foreach (var type in subtypes)
        {
            // Allocated without running a constructor so the check does not need to know each
            // subtype's parameters; Status getters are constants and do not read instance state.
            var instance = (RequestValidationException)
                System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(type);
            Assert.True(instance.Status is >= 400 and < 500,
                $"{type.Name}.Status is {instance.Status}; every RequestValidationException must be a 4xx "
                + "because the family means the request was at fault. Server-state failures belong "
                + "outside this family, on the sanitized 500 path.");
        }
    }
}

/// <summary>
/// Guards the signature-algorithm vocabulary shared between the server and the admin UI.
/// <para>
/// <c>CertPolicy.RsaSignaturePadding</c> defaults to <c>"PSS"</c>, so RSA requests are signed as
/// <c>SHA-n-withRSAandMGF1</c>. The bootstrap seeder has always allowed those, but the admin
/// UI's picker offered only the PKCS#1 v1.5 names — so a certificate profile created through the
/// UI could never permit the signatures the server actually produces, and every RSA issuance
/// against such a profile failed. Nothing connected the two lists, so nothing caught it.
/// </para>
/// </summary>
public class SignatureAlgorithmVocabularyTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string ReadRepoFile(string relativePath)
    {
        var path = Path.Combine(RepoRoot(), relativePath);
        Assert.True(File.Exists(path), $"expected source file at {path}");
        return File.ReadAllText(path);
    }

    /// <summary>Extracts the quoted strings from a named C# or TS list literal.</summary>
    private static List<string> ListLiteral(string source, string marker, char open, char close)
    {
        var start = source.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, $"could not find '{marker}' — the declaration was renamed and this guard went blind");

        var openIndex = source.IndexOf(open, start);
        Assert.True(openIndex >= 0, $"no '{open}' after '{marker}'");
        var closeIndex = source.IndexOf(close, openIndex);
        Assert.True(closeIndex > openIndex, $"no '{close}' after '{marker}'");

        var body = source[(openIndex + 1)..closeIndex];
        var values = Regex.Matches(body, "['\"]([^'\"]+)['\"]").Select(m => m.Groups[1].Value).ToList();
        Assert.NotEmpty(values);
        return values;
    }

    [Fact]
    public void The_admin_ui_offers_every_signature_algorithm_the_bootstrap_seeds()
    {
        var seeded = ListLiteral(
            ReadRepoFile(Path.Combine("ModularCA.Bootstrap", "BootstrapModularCA.cs")),
            "var SignatureAlgorithms = new List<string>", '{', '}');

        var offered = ListLiteral(
            ReadRepoFile(Path.Combine("modularca.adminui", "src", "pages", "profileHelpers.tsx")),
            "export const ALLOWED_SIGNATURE_ALGORITHM_OPTIONS", '[', ']');

        var missing = seeded.Except(offered, StringComparer.Ordinal).ToList();

        Assert.True(missing.Count == 0,
            "the admin UI's signature-algorithm picker cannot express algorithms the server seeds, "
            + "so a profile authored in the UI will reject issuance that a seeded profile accepts. Missing: "
            + string.Join(", ", missing));
    }

    [Fact]
    public void The_rsa_pss_algorithms_are_offered_because_pss_is_the_default_padding()
    {
        // Called out separately from the parity test above: this is the specific pairing that
        // broke, and it stays broken-in-spirit if someone "tidies" the picker down to v1.5.
        var offered = ListLiteral(
            ReadRepoFile(Path.Combine("modularca.adminui", "src", "pages", "profileHelpers.tsx")),
            "export const ALLOWED_SIGNATURE_ALGORITHM_OPTIONS", '[', ']');

        foreach (var pss in new[] { "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1" })
            Assert.Contains(pss, offered);
    }
}
