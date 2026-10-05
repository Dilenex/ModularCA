using ModularCA.Core.Services.SchedulerJobs;
using Xunit;

namespace ModularCA.Tests.Core.Services.SchedulerJobs;

/// <summary>
/// Covers <see cref="ComplianceScanJob.MatchesDeprecatedAlgorithm"/>. BouncyCastle names SHA-1
/// signatures <c>SHA-1withRSA</c>, so the plain substring test missed the shipped default
/// <c>SHA1WithRSA</c> and every SHA-1 certificate went unflagged.
/// </summary>
public class ComplianceDeprecatedAlgorithmTests
{
    [Theory]
    [InlineData("SHA-1withRSA", "SHA1WithRSA")]
    [InlineData("SHA-1withRSA", "SHA1")]
    [InlineData("SHA-1withECDSA", "sha-1")]
    [InlineData("MD5withRSA", "MD5WithRSA")]
    public void Flags_names_that_differ_only_in_case_or_hyphens(string sigAlgName, string deprecated)
        => Assert.True(ComplianceScanJob.MatchesDeprecatedAlgorithm(sigAlgName, new[] { deprecated }));

    [Theory]
    [InlineData("SHA-256withRSA", "SHA1")]
    [InlineData("SHA-256withECDSA", "MD5")]
    [InlineData("SHA-256withRSA", "")]
    [InlineData("SHA-256withRSA", "  ")]
    public void Leaves_other_algorithms_and_blank_entries_alone(string sigAlgName, string deprecated)
        => Assert.False(ComplianceScanJob.MatchesDeprecatedAlgorithm(sigAlgName, new[] { deprecated }));
}
