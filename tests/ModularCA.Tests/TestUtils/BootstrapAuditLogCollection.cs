using Xunit;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// xUnit collection for tests that point <c>BootstrapAuditLog.LogDirectory</c>, a process-wide
/// static, at a directory of their own. xUnit serializes within a collection, so one class cannot
/// redirect or reset it while another is writing.
/// </summary>
[CollectionDefinition(Name)]
public class BootstrapAuditLogCollection
{
    public const string Name = "BootstrapAuditLog";
}
