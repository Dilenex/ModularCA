using ModularCA.Shared.Enums;
using Xunit;

namespace ModularCA.Tests.Shared;

/// <summary>
/// The console's audit Action filter lists every action the server can record. It used to list
/// only the actions on the pages already viewed, so a rare action could not be filtered for.
/// </summary>
public class AuditActionTypeListTests
{
    [Fact]
    public void The_list_holds_every_declared_action_once_in_order()
    {
        var all = AuditActionType.All;

        Assert.Contains(AuditActionType.CertificateIssued, all);
        Assert.Contains(AuditActionType.CertificateRevoked, all);
        Assert.Contains(AuditActionType.CrlNumbersRaisedOnRestore, all);
        Assert.Equal(all.Distinct().Count(), all.Count);
        Assert.Equal(all.OrderBy(n => n, StringComparer.Ordinal), all);
        Assert.True(all.Count > 100);
    }
}
