using System.Text.Json;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;

namespace ModularCA.Tests.Shared;

/// <summary>
/// Every shape of <c>KeyCeremonies.ParametersJson</c>, as literals. The top-level constants are
/// what 0.4.0 writes (<see cref="Writers"/> rebuilds each with the production serializer and
/// settings). <see cref="Legacy"/> holds the same shapes as written before the S6 rename: what
/// open ceremonies in an upgraded database hold, and the input the RenameTenantToSpace migration
/// must carry across with their space ids intact.
/// </summary>
internal static class CeremonyParametersFixtures
{
    public static readonly Guid SpaceA = Guid.Parse("6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60");
    public static readonly Guid SpaceB = Guid.Parse("7e2a4d3b-5c6f-4071-9b82-1c3d4e5f6071");
    public static readonly Guid CaA = Guid.Parse("8f3b5e4c-6d70-4182-ac93-2d4e5f607182");
    public static readonly Guid InstanceCa = Guid.Parse("90c46f5d-7e81-4293-bda4-3e5f60718293");
    public static readonly Guid ParentCa = Guid.Parse("a1d5706e-8f92-43a4-8eb5-4f60718293a4");
    public static readonly Guid Profile = Guid.Parse("b2e6817f-90a3-44b5-9fc6-506172839405");
    public static readonly Guid User = Guid.Parse("c3f79280-a1b4-45c6-a0d7-617283940516");
    public static readonly Guid Admin = Guid.Parse("d4080391-b2c5-46d7-b1e8-728394051627");
    public static readonly Guid SshKey = Guid.Parse("e51914a2-c3d6-47e8-82f9-839405162738");
    public static readonly Guid Certificate = Guid.Parse("f62a25b3-d4e7-48f9-9300-940516273849");

    /// <summary>A ControlledUserChange ceremony: PascalCase, <c>SpaceId</c> and <c>MintedTierSpaceId</c>.</summary>
    public const string ControlledUserChange = """{"ChangeType":"GrantCapability","TargetUserId":"c3f79280-a1b4-45c6-a0d7-617283940516","TargetUsername":"bob","Capability":"ca.manage","SpaceId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","CertificateAuthorityId":"8f3b5e4c-6d70-4182-ac93-2d4e5f607182","ResourceType":null,"ResourceId":null,"RecordId":null,"RoleId":null,"GroupId":null,"Identity":null,"CredentialSnapshots":[{"UserId":"c3f79280-a1b4-45c6-a0d7-617283940516","SecurityStamp":"stamp-1","MfaMarker":"mfa-1"}],"RecentCredentialResets":[{"UserId":"c3f79280-a1b4-45c6-a0d7-617283940516","Username":"bob","What":"password","ActorUserId":"d4080391-b2c5-46d7-b1e8-728394051627","ActorUsername":"carol","At":"2026-09-28T10:00:00Z"}],"RecentResetsUnchecked":false,"MintedTierLevel":6,"MintedTierCaId":null,"MintedTierSpaceId":"7e2a4d3b-5c6f-4071-9b82-1c3d4e5f6071"}""";

    /// <summary>A CreateRootCA or CreateIntermediateCA ceremony: PascalCase, <c>SpaceId</c>.</summary>
    public const string KeyCeremony = """{"SubjectCN":"Acme Issuing CA","SubjectO":"Acme","SubjectOU":null,"SubjectL":null,"SubjectST":null,"SubjectC":"GB","KeyAlgorithm":"ECDSA","KeySize":384,"ValidityYears":5,"SpaceId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","Scope":null,"ParentCaId":"a1d5706e-8f92-43a4-8eb5-4f60718293a4","Label":"acme-issuing","PublicBaseUrl":"https://pki.acme.example","CertProfileId":"b2e6817f-90a3-44b5-9fc6-506172839405","NameConstraintsPermitted":["acme.example"],"NameConstraintsExcluded":[]}""";

    /// <summary>A CreateSshCa or DeleteSshCa ceremony: PascalCase, <c>SpaceId</c>, and a null <c>KeySize</c>.</summary>
    public const string SshKeyCeremony = """{"Name":"ops-ssh","KeyType":"ed25519","KeySize":null,"IsUserCa":false,"IsHostCa":false,"MaxValidityHours":720,"SpaceId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","SshCaKeyId":"e51914a2-c3d6-47e8-82f9-839405162738"}""";

    /// <summary>A RevokeCa ceremony: camelCase, <c>spaceId</c>.</summary>
    public const string RevokeCa = """{"certificateId":"f62a25b3-d4e7-48f9-9300-940516273849","serialNumber":"4F2A9C01","reason":"KeyCompromise","spaceId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60"}""";

    /// <summary>A SpacePolicyChange ceremony: camelCase, <c>spaceId</c>, with a CA quorum change.</summary>
    public const string SpacePolicyChange = """{"spaceId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","currentRequireKeyCeremony":true,"currentCeremonyRequiredApprovals":3,"proposedRequireKeyCeremony":false,"proposedCeremonyRequiredApprovals":2,"userQuorumIncluded":true,"currentUserQuorum":2,"proposedUserQuorum":null,"caUserQuorums":[{"caId":"8f3b5e4c-6d70-4182-ac93-2d4e5f607182","currentQuorum":3,"proposedQuorum":1}]}""";

    /// <summary>An InstancePolicyChange ceremony: camelCase, a null <c>spaceId</c>.</summary>
    public const string InstancePolicyChange = """{"spaceId":null,"currentRequireKeyCeremony":true,"currentCeremonyRequiredApprovals":3,"proposedRequireKeyCeremony":null,"proposedCeremonyRequiredApprovals":2,"userQuorumIncluded":false,"currentUserQuorum":null,"proposedUserQuorum":null,"caUserQuorums":[{"caId":"90c46f5d-7e81-4293-bda4-3e5f60718293","currentQuorum":null,"proposedQuorum":2}]}""";

    /// <summary>A per-CA quorum change on a space's CA: camelCase, <c>spaceId</c>, only CA quorum entries.</summary>
    public const string CaUserQuorumChange = """{"spaceId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","currentRequireKeyCeremony":false,"currentCeremonyRequiredApprovals":2,"proposedRequireKeyCeremony":null,"proposedCeremonyRequiredApprovals":null,"userQuorumIncluded":false,"currentUserQuorum":null,"proposedUserQuorum":null,"caUserQuorums":[{"caId":"8f3b5e4c-6d70-4182-ac93-2d4e5f607182","currentQuorum":null,"proposedQuorum":2}]}""";

    /// <summary>
    /// The same shapes as written before 0.4.0, with <c>TenantId</c>, <c>MintedTierTenantId</c> and
    /// <c>tenantId</c>: the RenameTenantToSpace migration's input. Reading one fails closed.
    /// </summary>
    public static class Legacy
    {
        /// <summary>A ControlledUserChange ceremony: PascalCase, <c>TenantId</c> and <c>MintedTierTenantId</c>.</summary>
        public const string ControlledUserChange = """{"ChangeType":"GrantCapability","TargetUserId":"c3f79280-a1b4-45c6-a0d7-617283940516","TargetUsername":"bob","Capability":"ca.manage","TenantId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","CertificateAuthorityId":"8f3b5e4c-6d70-4182-ac93-2d4e5f607182","ResourceType":null,"ResourceId":null,"RecordId":null,"RoleId":null,"GroupId":null,"Identity":null,"CredentialSnapshots":[{"UserId":"c3f79280-a1b4-45c6-a0d7-617283940516","SecurityStamp":"stamp-1","MfaMarker":"mfa-1"}],"RecentCredentialResets":[{"UserId":"c3f79280-a1b4-45c6-a0d7-617283940516","Username":"bob","What":"password","ActorUserId":"d4080391-b2c5-46d7-b1e8-728394051627","ActorUsername":"carol","At":"2026-09-28T10:00:00Z"}],"RecentResetsUnchecked":false,"MintedTierLevel":6,"MintedTierCaId":null,"MintedTierTenantId":"7e2a4d3b-5c6f-4071-9b82-1c3d4e5f6071"}""";

        /// <summary>A CreateRootCA or CreateIntermediateCA ceremony: PascalCase, <c>TenantId</c>.</summary>
        public const string KeyCeremony = """{"SubjectCN":"Acme Issuing CA","SubjectO":"Acme","SubjectOU":null,"SubjectL":null,"SubjectST":null,"SubjectC":"GB","KeyAlgorithm":"ECDSA","KeySize":384,"ValidityYears":5,"TenantId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","Scope":null,"ParentCaId":"a1d5706e-8f92-43a4-8eb5-4f60718293a4","Label":"acme-issuing","PublicBaseUrl":"https://pki.acme.example","CertProfileId":"b2e6817f-90a3-44b5-9fc6-506172839405","NameConstraintsPermitted":["acme.example"],"NameConstraintsExcluded":[]}""";

        /// <summary>A CreateSshCa or DeleteSshCa ceremony: PascalCase, <c>TenantId</c>.</summary>
        public const string SshKeyCeremony = """{"Name":"ops-ssh","KeyType":"ed25519","KeySize":null,"IsUserCa":false,"IsHostCa":false,"MaxValidityHours":720,"TenantId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","SshCaKeyId":"e51914a2-c3d6-47e8-82f9-839405162738"}""";

        /// <summary>A RevokeCa ceremony: camelCase, <c>tenantId</c>.</summary>
        public const string RevokeCa = """{"certificateId":"f62a25b3-d4e7-48f9-9300-940516273849","serialNumber":"4F2A9C01","reason":"KeyCompromise","tenantId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60"}""";

        /// <summary>A TenantPolicyChange ceremony: camelCase, <c>tenantId</c>, with a CA quorum change.</summary>
        public const string TenantPolicyChange = """{"tenantId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","currentRequireKeyCeremony":true,"currentCeremonyRequiredApprovals":3,"proposedRequireKeyCeremony":false,"proposedCeremonyRequiredApprovals":2,"userQuorumIncluded":true,"currentUserQuorum":2,"proposedUserQuorum":null,"caUserQuorums":[{"caId":"8f3b5e4c-6d70-4182-ac93-2d4e5f607182","currentQuorum":3,"proposedQuorum":1}]}""";

        /// <summary>An InstancePolicyChange ceremony: camelCase, a null <c>tenantId</c>.</summary>
        public const string InstancePolicyChange = """{"tenantId":null,"currentRequireKeyCeremony":true,"currentCeremonyRequiredApprovals":3,"proposedRequireKeyCeremony":null,"proposedCeremonyRequiredApprovals":2,"userQuorumIncluded":false,"currentUserQuorum":null,"proposedUserQuorum":null,"caUserQuorums":[{"caId":"90c46f5d-7e81-4293-bda4-3e5f60718293","currentQuorum":null,"proposedQuorum":2}]}""";

        /// <summary>A per-CA quorum change on a tenant's CA: camelCase, <c>tenantId</c>, only CA quorum entries.</summary>
        public const string CaUserQuorumChange = """{"tenantId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","currentRequireKeyCeremony":false,"currentCeremonyRequiredApprovals":2,"proposedRequireKeyCeremony":null,"proposedCeremonyRequiredApprovals":null,"userQuorumIncluded":false,"currentUserQuorum":null,"proposedUserQuorum":null,"caUserQuorums":[{"caId":"8f3b5e4c-6d70-4182-ac93-2d4e5f607182","currentQuorum":null,"proposedQuorum":2}]}""";
    }

    /// <summary>Each legacy shape and the 0.4.0 shape the migration's key rename makes of it.</summary>
    public static Xunit.TheoryData<string, string> LegacyAndCurrent() => new()
    {
        { Legacy.ControlledUserChange, ControlledUserChange },
        { Legacy.KeyCeremony, KeyCeremony },
        { Legacy.SshKeyCeremony, SshKeyCeremony },
        { Legacy.RevokeCa, RevokeCa },
        { Legacy.TenantPolicyChange, SpacePolicyChange },
        { Legacy.InstancePolicyChange, InstancePolicyChange },
        { Legacy.CaUserQuorumChange, CaUserQuorumChange },
    };

    /// <summary>The production writers, each with the serializer settings its call site uses.</summary>
    public static class Writers
    {
        /// <summary>ControlledUserCeremonyService.InitiateChangeAsync: a bare serializer, PascalCase.</summary>
        public static string ControlledUserChange() => JsonSerializer.Serialize(new ControlledUserChangeParameters
        {
            ChangeType = "GrantCapability",
            TargetUserId = User,
            TargetUsername = "bob",
            Capability = "ca.manage",
            SpaceId = SpaceA,
            CertificateAuthorityId = CaA,
            CredentialSnapshots = [new ControlledCredentialSnapshot(User, "stamp-1", "mfa-1")],
            RecentCredentialResets = [new ControlledCredentialReset(User, "bob", ControlledCredentialReset.Password, Admin, "carol",
                new DateTime(2026, 9, 28, 10, 0, 0, DateTimeKind.Utc))],
            MintedTierLevel = 6,
            MintedTierSpaceId = SpaceB,
        });

        /// <summary>AdminCaController and AdminKeyCeremonyController: a bare serializer, PascalCase.</summary>
        public static string KeyCeremony() => JsonSerializer.Serialize(new KeyCeremonyParameters
        {
            SubjectCN = "Acme Issuing CA",
            SubjectO = "Acme",
            SubjectC = "GB",
            KeyAlgorithm = "ECDSA",
            KeySize = 384,
            ValidityYears = 5,
            SpaceId = SpaceA,
            ParentCaId = ParentCa,
            Label = "acme-issuing",
            PublicBaseUrl = "https://pki.acme.example",
            CertProfileId = Profile,
            NameConstraintsPermitted = ["acme.example"],
            NameConstraintsExcluded = [],
        });

        /// <summary>AdminSshController's DeleteSshCa: a bare serializer, PascalCase.</summary>
        public static string SshKeyCeremony() => JsonSerializer.Serialize(new SshKeyCeremonyParameters
        {
            SshCaKeyId = SshKey,
            Name = "ops-ssh",
            SpaceId = SpaceA,
        });

        /// <summary>AdminRevocationController's anonymous object, through <see cref="SafeJsonOptions.Stored"/>: camelCase.</summary>
        public static string RevokeCa() => JsonSerializer.Serialize(new
        {
            CertificateId = Certificate,
            SerialNumber = "4F2A9C01",
            Reason = ModularCA.Shared.Enums.RevocationReason.KeyCompromise.ToString(),
            SpaceId = (Guid?)SpaceA,
        }, SafeJsonOptions.Stored);

        /// <summary>SpacePolicyChangeService for a space, through <see cref="SafeJsonOptions.Stored"/>: camelCase.</summary>
        public static string SpacePolicyChange() => JsonSerializer.Serialize(new SpacePolicyChangeCeremonyParameters
        {
            SpaceId = SpaceA,
            CurrentRequireKeyCeremony = true,
            CurrentCeremonyRequiredApprovals = 3,
            ProposedRequireKeyCeremony = false,
            ProposedCeremonyRequiredApprovals = 2,
            UserQuorumIncluded = true,
            CurrentUserQuorum = 2,
            ProposedUserQuorum = null,
            CaUserQuorums = [new CaUserQuorumChange { CaId = CaA, CurrentQuorum = 3, ProposedQuorum = 1 }],
        }, SafeJsonOptions.Stored);

        /// <summary>SpacePolicyChangeService for the instance: the same type with no space.</summary>
        public static string InstancePolicyChange() => JsonSerializer.Serialize(new SpacePolicyChangeCeremonyParameters
        {
            SpaceId = null,
            CurrentRequireKeyCeremony = true,
            CurrentCeremonyRequiredApprovals = 3,
            ProposedRequireKeyCeremony = null,
            ProposedCeremonyRequiredApprovals = 2,
            CaUserQuorums = [new CaUserQuorumChange { CaId = InstanceCa, CurrentQuorum = null, ProposedQuorum = 2 }],
        }, SafeJsonOptions.Stored);

        /// <summary>AdminUserQuorumController's per-CA quorum change on a space's CA: only <see cref="CaUserQuorumChange"/> entries.</summary>
        public static string CaUserQuorumChange() => JsonSerializer.Serialize(new SpacePolicyChangeCeremonyParameters
        {
            SpaceId = SpaceA,
            CurrentRequireKeyCeremony = false,
            CurrentCeremonyRequiredApprovals = 2,
            CaUserQuorums = [new CaUserQuorumChange { CaId = CaA, CurrentQuorum = null, ProposedQuorum = 2 }],
        }, SafeJsonOptions.Stored);
    }
}
