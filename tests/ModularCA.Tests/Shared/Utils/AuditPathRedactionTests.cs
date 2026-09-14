using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins that enrollment tokens never reach the network audit table by way of the request path.
/// </summary>
public class AuditPathRedactionTests
{
    [Theory]
    [InlineData("/api/v1/public/enroll/Xn8-F45yevBt8Wzr4IjU6Qb2RoIKdwsX_GsEQfVAF4s", "/api/v1/public/enroll/{token}")]
    [InlineData("/api/v1/public/enroll/Xn8-F45yevBt8Wzr4IjU6Qb2RoIKdwsX_GsEQfVAF4s/page", "/api/v1/public/enroll/{token}/page")]
    [InlineData("/public/enroll/abc123", "/public/enroll/{token}")]
    [InlineData("/public/enroll/abc123/page", "/public/enroll/{token}/page")]
    public void The_token_segment_is_replaced_and_the_rest_of_the_path_is_kept(string path, string expected)
    {
        Assert.Equal(expected, AuditPathRedaction.Redact(path));
    }

    [Fact]
    public void Matching_is_case_insensitive_on_the_prefix()
    {
        Assert.Equal("/API/v1/public/enroll/{token}", AuditPathRedaction.Redact("/API/v1/public/enroll/SECRET"));
    }

    [Theory]
    [InlineData("/api/v1/public/enroll")]
    [InlineData("/api/v1/public/enroll/")]
    [InlineData("/api/v1/public/info")]
    [InlineData("/api/v1/public/enrollment/abc")]
    [InlineData("/est/my-ca/simpleenroll")]
    [InlineData("/")]
    public void Paths_that_carry_no_credential_are_unchanged(string path)
    {
        Assert.Equal(path, AuditPathRedaction.Redact(path));
    }

    [Fact]
    public void Null_and_empty_are_tolerated()
    {
        Assert.Equal(string.Empty, AuditPathRedaction.Redact(null));
        Assert.Equal(string.Empty, AuditPathRedaction.Redact(string.Empty));
    }
}
