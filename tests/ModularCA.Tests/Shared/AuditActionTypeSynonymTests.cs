using ModularCA.Shared.Enums;
using Xunit;

namespace ModularCA.Tests.Shared;

/// <summary>
/// New space events have Space* names and recorded rows keep the retired Tenant* names, so an
/// audit search for either finds both.
/// </summary>
public class AuditActionTypeSynonymTests
{
    [Theory]
    [InlineData(AuditActionType.SpaceCreated, AuditActionType.TenantCreated)]
    [InlineData(AuditActionType.SpaceUpdated, AuditActionType.TenantUpdated)]
    [InlineData(AuditActionType.SpaceDisabled, AuditActionType.TenantDisabled)]
    [InlineData(AuditActionType.SpacePolicyChangeApplied, AuditActionType.TenantPolicyChangeApplied)]
    public void A_space_event_and_its_retired_name_are_synonyms(string current, string retired)
    {
        Assert.Equal([current, retired], AuditActionType.Synonyms(current));
        Assert.Equal([retired, current], AuditActionType.Synonyms(retired));
    }

    [Fact]
    public void Other_action_types_match_only_themselves()
    {
        Assert.Equal([AuditActionType.CertificateIssued], AuditActionType.Synonyms(AuditActionType.CertificateIssued));
        Assert.Equal([AuditActionType.TenantHostnameCreated], AuditActionType.Synonyms(AuditActionType.TenantHostnameCreated));
    }
}
