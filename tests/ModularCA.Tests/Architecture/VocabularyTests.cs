using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Architecture;

/// <summary>
/// The delegation scope was renamed from tenant to space in 0.4.0 (S6). Fails on "tenant", in any
/// case, anywhere in source outside <see cref="Allowlist"/>: code, raw SQL string literals in code,
/// the consoles, docs, configuration examples, the proto and the scripts.
/// </summary>
public sealed class VocabularyTests
{
    /// <summary>Why an entry may say tenant.</summary>
    public enum Reason
    {
        /// <summary>A migration up to RenameTenantToSpace, the tool that copies the 0.3.0 schema, or a test of them.</summary>
        Migration,
        /// <summary>The audit database, which keeps its TenantId, and the hash chain over it.</summary>
        Audit,
        /// <summary>A persisted or wire string that must not change.</summary>
        Pinned,
        /// <summary>A reader or test of a pre-0.4.0 name: config keys, stored keys, redirects, refused bodies.</summary>
        Legacy,
        /// <summary>Another product's own word.</summary>
        External,
        /// <summary>A dated record or a note about what was true before 0.4.0.</summary>
        History,
        /// <summary>Upgrade instructions, which name what the operator's current build has.</summary>
        Upgrade,
        /// <summary>The committed rename tool and its maps.</summary>
        Tool,
        /// <summary>This test.</summary>
        Self,
    }

    /// <summary>
    /// An allowed use in the files matching <see cref="Path"/> (repository-relative; <c>*</c> within a
    /// segment, <c>**</c> across segments, a trailing <c>/</c> for a folder): the whole file, or only
    /// <see cref="Text"/> wherever it is on a line, or every line under the markdown heading that
    /// contains <see cref="Section"/>, down to the next heading of its level or above.
    /// </summary>
    public sealed record Allowed(string Path, Reason Reason, string? Text = null, string? Section = null);

    /// <summary>A line that says tenant outside the allowlist.</summary>
    public sealed record Hit(string Path, int Line, string Text)
    {
        /// <inheritdoc />
        public override string ToString() => $"{Path}:{Line}: {Text.Trim()}";
    }

    private const string Word = "tenant";

    private static readonly string[] Extensions =
        [".cs", ".ts", ".tsx", ".js", ".mjs", ".md", ".yaml", ".yml", ".example", ".proto", ".json", ".sql", ".py", ".sh", ".ps1", ".psm1"];

    private static readonly HashSet<string> SkippedDirectories = new(StringComparer.OrdinalIgnoreCase)
        { "bin", "obj", "node_modules", "dist", "wwwroot", "generated", "TestResults", "__pycache__", ".git", ".vs", ".vscode", ".idea", ".claude", "References" };

    private static readonly HashSet<string> SkippedFiles = new(StringComparer.OrdinalIgnoreCase) { "package-lock.json" };

    private const string Admin = "ModularCA.API/Controllers/v1/Admin/";
    private const string Migrations = "ModularCA.Database/Migrations/";
    private const string Tests = "tests/ModularCA.Tests/";

    /// <summary>Everything in source that may still say tenant, and why.</summary>
    public static readonly Allowed[] Allowlist =
    [
        new(Migrations + "20260919181506_InitialCreate*.cs", Reason.Migration),
        new(Migrations + "20260928221118_RetireTenantHostnames*.cs", Reason.Migration),
        new(Migrations + "20260929051025_FoldSystemTenant*.cs", Reason.Migration),
        new(Migrations + "20261002063527_InstanceUniqueCaNames*.cs", Reason.Migration),
        new(Migrations + "20261003072435_RenameTenantToSpace*.cs", Reason.Migration),
        new("ModularCA.Migrate/", Reason.Migration),
        new(Tests + "Database/FoldSystemTenantMigrationTests.cs", Reason.Migration),
        new(Tests + "Database/InstanceUniqueCaNamesMigrationTests.cs", Reason.Migration),
        new(Tests + "Database/RenameTenantToSpaceMigrationTests.cs", Reason.Migration),
        new(Tests + "Database/RetireTenantHostnamesMigrationTests.cs", Reason.Migration),
        new(Tests + "Database/PostgresUpgradeHarnessTests.cs", Reason.Migration),
        new(Tests + "Database/PostgresOwnershipHarnessTests.cs", Reason.Migration),
        new(Tests + "Database/FrozenBaselineTests.cs", Reason.Migration),
        new("ModularCA.Database/MigrationCheckLabels.cs", Reason.Migration),
        new(Tests + "Database/DryRunCollectorTests.cs", Reason.Migration),
        new(Tests + "Database/MigrationLintTests.cs", Reason.Migration, Text: "\\\"Tenants\\\""),
        new(Tests + "Database/MigrationLintTests.cs", Reason.Migration, Text: "Table = \"Tenants\""),
        new(Tests + "Database/SchemaVersionGateTests.cs", Reason.Migration, Text: "\\\"Tenants\\\""),
        new(Tests + "Database/SchemaVersionGateTests.cs", Reason.Migration, Text: "Tenant's count"),
        new(Tests + "Database/SchemaVersionGateTests.cs", Reason.Migration, Text: "Tenant''s count"),
        new(Tests + "Migrate/", Reason.Migration),
        new(Tests + "Docs/UpgradePrecheckTests.cs", Reason.Migration),
        new("ModularCA.Core/Services/LdapGroupSyncService.cs", Reason.Migration, Text: "RenameTenantToSpace"),
        new("ModularCA.Shared/Enums/CeremonyType.cs", Reason.Migration, Text: "RenameTenantToSpace"),
        new("ModularCA.Shared/Models/CeremonyParametersJson.cs", Reason.Migration, Text: "RenameTenantToSpace"),
        new(Tests + "Core/Services/LdapSpaceGroupRenameTests.cs", Reason.Migration, Text: "RenameTenantToSpace"),

        new(Migrations + "Audit/", Reason.Audit),
        new("ModularCA.Database/AuditDbContext.cs", Reason.Audit),
        new("ModularCA.Shared/Entities/Audit*Entity.cs", Reason.Audit),
        new("ModularCA.Core/Services/AuditHashChainService.cs", Reason.Audit),
        new("ModularCA.Core/Services/AuditService.cs", Reason.Audit, Text: "TenantId = null"),
        new("ModularCA.Core/Services/ProtocolAuditService.cs", Reason.Audit, Text: "TenantId = spaceId"),
        new("ModularCA.Core/Services/SchedulerJobs/AuditRetentionJob.cs", Reason.Audit, Text: "a.TenantId"),
        new("ModularCA.Core/Services/SchedulerJobs/AuditRetentionJob.cs", Reason.Audit, Text: "\\\"TenantId\\\""),
        new(Admin + "AdminAuditController.cs", Reason.Audit, Text: "a.TenantId"),
        new(Admin + "AdminAuditController.cs", Reason.Audit, Text: "marker.TenantId"),
        new(Admin + "AdminAuditController.cs", Reason.Audit, Text: "database keeps its pre-0.4.0 <c>TenantId</c>"),
        new(Admin + "AdminAuditController.cs", Reason.Audit, Text: "Remove(\"tenantId\""),
        new(Tests + "Core/AuditChain*Tests.cs", Reason.Audit),
        new(Tests + "Core/Services/SchedulerJobs/AuditRetentionMarkerTests.cs", Reason.Audit, Text: "TenantId"),
        new(Tests + "Api/SpaceBindingTests.cs", Reason.Audit, Text: "keeps its TenantId column"),

        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "TenantPolicyChangeApplied"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "TenantCreated"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "TenantUpdated"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "TenantDisabled"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "TenantHostname"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "tenant hostname"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "added to a tenant"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "per-tenant audit chain"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.Pinned, Text: "retired tenant"),
        new("ModularCA.Shared/Licensing/License.cs", Reason.Pinned, Text: "maxTenants"),
        new("ModularCA.Shared/Signing/SigningRefusedException.cs", Reason.Pinned, Text: "TenantMismatch"),
        new("ModularCA.Keystore/Signing/InProcessSigningService.cs", Reason.Pinned, Text: "TenantMismatch"),
        new("ModularCA.Keystore/Signing/InProcessSigningService.SshKeys.cs", Reason.Pinned, Text: "TenantMismatch"),
        new("ModularCA.Shared/Entities/SignerAuditEntity.cs", Reason.Pinned, Text: "TenantScope = \"tenant\""),
        new("ModularCA.Shared/Entities/SignerAuditEntity.cs", Reason.Pinned, Text: "TenantScope"),
        new(Tests + "Core/AuditHashGoldenVectorTests.cs", Reason.Pinned),
        new(Tests + "Shared/AuditActionTypeSynonymTests.cs", Reason.Pinned),
        new(Tests + "Shared/Licensing/EntitlementTests.cs", Reason.Pinned, Text: "MaxTenants"),
        new(Tests + "Signer/SigningServiceContractTests.cs", Reason.Pinned, Text: "TenantMismatch"),
        new(Tests + "Signer/SigningServiceContractTests.cs", Reason.Pinned, Text: "TenantScope"),
        new(Tests + "Signer/SigningServiceContractTests.Ssh.cs", Reason.Pinned, Text: "TenantMismatch"),

        new("ModularCA.Shared/Utils/YamlConfigLoader.cs", Reason.Legacy, Text: "\"TenantId\""),
        new("ModularCA.Shared/Models/CeremonyParametersJson.cs", Reason.Legacy, Text: "TenantId"),
        new("ModularCA.Shared/Interfaces/IKeyCeremonyService.cs", Reason.Legacy, Text: "pre-0.4.0 <c>TenantId</c>"),
        new("ModularCA.Shared/Enums/CeremonyType.cs", Reason.Legacy, Text: "<c>TenantPolicyChange</c>"),
        new("ModularCA.Shared/Models/KeyCeremonyParameters.cs", Reason.Legacy, Text: "<c>tenantId</c>"),
        new(Admin + "*Controller.cs", Reason.Legacy, Text: "pre-0.4.0 <c>tenantId</c>"),
        new(Admin + "*Controller.cs", Reason.Legacy, Text: "[RefuseQueryKey(\"tenantId\""),
        new(Admin + "AdminRoleAssignmentController.cs", Reason.Legacy, Text: "<c>tenantId</c>) is refused"),
        new(Admin + "AdminUserGrantController.cs", Reason.Legacy, Text: "<c>tenantId</c>) is refused"),
        new(Admin + "AdminAuditController.cs", Reason.Legacy, Text: "RetiredSpaceTarget = \"Tenant\""),
        new("modularca.adminui/src/App.tsx", Reason.Legacy, Text: "/tenants"),
        new("modularca.adminui/src/legacyPaths.ts", Reason.Legacy, Text: "/tenants"),
        new("modularca.adminui/src/legacyPaths.ts", Reason.Legacy, Text: "?tenant="),
        new("modularca.adminui/src/context/ScopeContext.tsx", Reason.Legacy, Text: "?tenant="),
        new("modularca.adminui/src/scope.ts", Reason.Legacy, Text: "LEGACY_SCOPE_SPACE_PARAM = 'tenant'"),
        new("modularca.adminui/src/scope.ts", Reason.Legacy, Text: "tenant=<slug>"),
        new("modularca.adminui/src/pages/CaManagement.tsx", Reason.Legacy, Text: "RENAMED_CA_COLUMNS = { tenant: 'space' }"),
        new("modularca.adminui/src/pages/CaManagement.tsx", Reason.Legacy, Text: "keyed 'tenant'"),
        new("modularca.adminui/src/pages/msaeRefusals.ts", Reason.Legacy, Text: "'WrongTenant'"),
        new("modularca.docsui/src/App.tsx", Reason.Legacy, Text: "/architecture/tenant-model"),
        new("modularca.docsui/src/pages/AdminUiGuide.tsx", Reason.Legacy, Text: "old /admin/tenants paths"),
        new("modularca.docsui/src/data/endpoints/admin/audit/audit.ts", Reason.Legacy, Text: "Replaces tenantId, which is refused with 400"),
        new("modularca.docsui/src/data/endpoints/admin/ca-and-certs/certificates.ts", Reason.Legacy, Text: "The pre-0.4.0 tenantId is refused (400)"),
        new(Tests + "Shared/CeremonyParametersFixtures.cs", Reason.Legacy),
        new(Tests + "Shared/CeremonyParametersFixtureTests.cs", Reason.Legacy),
        new(Tests + "Shared/Config/LegacyConfigKeyTests.cs", Reason.Legacy),
        new("ModularCA.API/Startup/SchemaStartup.FoldedScope.cs", Reason.Legacy),
        new(Tests + "Api/IntegrationSpaceScopeTests.cs", Reason.Legacy),
        new(Tests + "Api/StaleTenantBodyTests.cs", Reason.Legacy),
        new(Tests + "Api/StaleTenantQueryTests.cs", Reason.Legacy),
        new(Tests + "Api/SpaceRouteTests.cs", Reason.Legacy),
        new(Tests + "Api/SpaceBindingTests.cs", Reason.Legacy, Text: "DoesNotContain(\"tenantId\""),
        new(Tests + "Api/SpaceIsolationMatrixTests.cs", Reason.Legacy, Text: "DoesNotContain(\"tenant\""),
        new(Tests + "Api/SpaceIsolationMatrixTests.cs", Reason.Legacy, Text: "says_nothing_of_a_tenant"),
        new(Tests + "Api/SpaceIsolationMatrixTests.cs", Reason.Legacy, Text: "nothing in it says tenant"),
        new(Tests + "Api/CeremonyEndpointPipelineTests.cs", Reason.Legacy, Text: "[InlineData(\"TenantPolicyChange\")]"),
        new(Tests + "Core/Services/Hostnames/TlsServerCertificateSelectorTests.cs", Reason.Legacy, Text: "DoesNotContain(\"TenantHostname\""),
        new(Tests + "Core/Services/LdapSpaceGroupRenameTests.cs", Reason.Legacy, Text: "\"tenant-a-user\""),
        new(Tests + "Docs/DocumentedApiPathTests.cs", Reason.Legacy, Text: "pre-0.4.0 tenant routes"),
        new(Tests + "Docs/DocumentedApiPathTests.cs", Reason.Legacy, Text: "\"/admin/tenants\""),
        new("tests/modularca.web.tests/src/adminui/scope.test.ts", Reason.Legacy),
        new("tests/modularca.web.tests/src/adminui/spaces.test.ts", Reason.Legacy),
        new("tests/modularca.web.tests/src/common/tablePrefsKeys.test.ts", Reason.Legacy),

        new("modularca.adminui/src/pages/Settings.tsx", Reason.External, Text: "login.microsoftonline.com/{tenant}"),
        new("config/config.yaml.example", Reason.External, Text: "login.microsoftonline.com/{tenant}"),
        new("config/config.yaml.example", Reason.External, Text: "login.microsoftonline.com/your-tenant-id"),

        new("CHANGELOG.md", Reason.History),
        new("docs/architecture/instance-tenancy.md", Reason.History),
        new("docs/architecture/postgresql-migration.md", Reason.History),
        new("docs/architecture/signer-separation.md", Reason.History),
        new("scripts/lab/containers/", Reason.History),
        new("ModularCA.Shared/Entities/SpaceEntity.cs", Reason.History, Text: "<c>Tenants</c> before 0.4.0"),
        new("ModularCA.Shared/Enums/AuditActionType.cs", Reason.History, Text: "Tenant hostnames, retired in 0.4.0"),
        new(Admin + "AdminAuditController.cs", Reason.History, Text: "target type <c>Tenant</c>"),
        new(Admin + "AdminUserQuorumController.cs", Reason.History, Text: "the system tenant"),
        new("ModularCA.Auth/Authorization/CaGroupAuthorizationHandler.cs", Reason.History, Text: "former system tenant"),
        new("ModularCA.Auth/Authorization/ControlledUserCeremonyService.cs", Reason.History, Text: "the system tenant"),
        new("ModularCA.Auth/Authorization/ScopeCapabilityExtensions.cs", Reason.History, Text: "former system tenant"),
        new("ModularCA.Auth/Authorization/ServiceIdentityService.cs", Reason.History, Text: "the system tenant"),
        new("ModularCA.Bootstrap/BootstrapProfileSeeder.cs", Reason.History, Text: "the system tenant"),
        new("ModularCA.Core/Services/LdapGroupSyncService.cs", Reason.History, Text: "the system tenant"),
        new("ModularCA.Core/Services/IntegrationScopeCheck.cs", Reason.History, Text: "the system tenant"),
        new("modularca.docsui/src/pages/SpaceModelDiagram.tsx", Reason.History, Text: "Spaces were called tenants before 0.4.0"),
        new("modularca.docsui/src/pages/SpaceModelDiagram.tsx", Reason.History, Text: "tenant into the instance, and renames tenants to spaces"),
        new(Tests + "Api/InstanceCeremonyEndpointTests.cs", Reason.History, Text: "former system tenant"),
        new(Tests + "Auth/InstanceScopeTests.cs", Reason.History, Text: "a system tenant group"),
        new(Tests + "Auth/ServiceIdentityTests.cs", Reason.History, Text: "the system tenant"),

        new("packaging/README-DEPLOY.md", Reason.Upgrade, Section: "### Upgrading to 0.4.0"),

        new("scripts/s6-rename/", Reason.Tool),

        new(Tests + "Architecture/VocabularyTests.cs", Reason.Self),
    ];

    private static readonly Lazy<(List<Hit> Hits, HashSet<Allowed> Used)> RepositoryScan = new(() =>
    {
        var used = new HashSet<Allowed>();
        return (Scan(RepoRoot(), Allowlist, used), used);
    });

    [Fact]
    public void Nothing_in_source_says_tenant_outside_the_allowlist()
    {
        var hits = RepositoryScan.Value.Hits;
        Assert.True(hits.Count == 0, FailureMessage(hits));
    }

    [Fact]
    public void Every_allowlist_entry_still_covers_a_line()
    {
        var stale = Allowlist.Where(a => !RepositoryScan.Value.Used.Contains(a)).ToList();
        Assert.True(stale.Count == 0, "Allowlist entries that no longer cover any line; remove them:\n" + string.Join("\n", stale));
    }

    [Fact]
    public void Every_allowlist_entry_is_well_formed()
    {
        Assert.All(Allowlist, a =>
        {
            Assert.False(a.Text != null && a.Section != null, $"{a} names both a text and a section");
            Assert.True(a.Text is null || a.Text.Contains(Word, StringComparison.OrdinalIgnoreCase), $"{a} allows text that does not say {Word}");
            Assert.DoesNotContain('\\', a.Path);
        });
        Assert.Equal(Allowlist.Length, Allowlist.Distinct().Count());
    }

    [Fact]
    public void The_scan_reports_each_unexpected_line_with_its_file_and_text_and_skips_build_output()
    {
        var root = Directory.CreateTempSubdirectory("vocabulary-").FullName;
        try
        {
            Write(root, "src/Service.cs", "namespace X;", "var sql = \"SELECT \\\"TenantId\\\" FROM \\\"CaGroups\\\"\";", "var space = 1;");
            Write(root, "web/src/Page.tsx", "export const Page = () => <p>Tenants</p>;");
            Write(root, "docs/guide.md", "# Guide", "", "A TENANT admin.");
            Write(root, "config/x.yaml.example", "IntegrationApi:", "  TenantId: \"\"");
            Write(root, "scripts/run.sh", "echo tenant");
            Write(root, "web/node_modules/pkg/index.ts", "tenant");
            Write(root, "src/bin/Debug/Gen.cs", "tenant");
            Write(root, "web/package-lock.json", "{\"tenant\": 1}");
            Write(root, "notes.txt", "tenant");

            var hits = Scan(root, []);

            Assert.Equal(
            [
                new Hit("config/x.yaml.example", 2, "  TenantId: \"\""),
                new Hit("docs/guide.md", 3, "A TENANT admin."),
                new Hit("scripts/run.sh", 1, "echo tenant"),
                new Hit("src/Service.cs", 2, "var sql = \"SELECT \\\"TenantId\\\" FROM \\\"CaGroups\\\"\";"),
                new Hit("web/src/Page.tsx", 1, "export const Page = () => <p>Tenants</p>;"),
            ], hits);
            Assert.Contains("src/Service.cs:2: var sql = \"SELECT \\\"TenantId\\\" FROM \\\"CaGroups\\\"\";", FailureMessage(hits));
            Assert.Contains("docs/guide.md:3: A TENANT admin.", FailureMessage(hits));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void The_real_allowlist_fails_a_new_tenant_and_passes_the_kept_ones()
    {
        Assert.Equal([new Hit("ModularCA.Core/Services/NewService.cs", 1, "public Guid? TenantId { get; set; }")],
            Unexpected("ModularCA.Core/Services/NewService.cs", ["public Guid? TenantId { get; set; }"], Allowlist));

        Assert.Equal([new Hit("ModularCA.Core/Services/ProtocolAuditService.cs", 2, "var tenant = spaceId;")],
            Unexpected("ModularCA.Core/Services/ProtocolAuditService.cs", ["TenantId = spaceId,", "var tenant = spaceId;"], Allowlist));

        Assert.Equal([new Hit("packaging/README-DEPLOY.md", 1, "Each tenant has a console.")],
            Unexpected("packaging/README-DEPLOY.md", ["Each tenant has a console.", "### Upgrading to 0.4.0", "SELECT \"TenantId\" FROM \"Tenants\";"], Allowlist));
    }

    [Fact]
    public void A_line_entry_allows_only_its_own_text_in_its_own_files()
    {
        Allowed[] allowlist = [new("src/Signer*.cs", Reason.Pinned, Text: "TenantMismatch")];

        var hits = Unexpected("src/SignerA.cs",
            ["Reason.TenantMismatch,", "Reason.tenantmismatch,", "Reason.TenantMismatch, // a tenant too", "var tenant = 1;"], allowlist);

        Assert.Equal([3, 4], hits.Select(h => h.Line));
        Assert.Single(Unexpected("src/Other.cs", ["Reason.TenantMismatch,"], allowlist));
        Assert.Single(Unexpected("src/nested/SignerA.cs", ["Reason.TenantMismatch,"], allowlist));
    }

    [Fact]
    public void A_whole_file_entry_allows_every_line_of_the_files_it_matches()
    {
        Allowed[] allowlist = [new("db/Migrations/2026*_Old*.cs", Reason.Migration), new("refs/", Reason.History), new("deep/**/x.md", Reason.History)];

        Assert.Empty(Unexpected("db/Migrations/20260101_OldTenant.Designer.cs", ["Tenants", "TenantId"], allowlist));
        Assert.Empty(Unexpected("refs/a/b.md", ["tenant"], allowlist));
        Assert.Empty(Unexpected("deep/a/b/x.md", ["tenant"], allowlist));
        Assert.Single(Unexpected("db/Migrations/20270101_New.cs", ["Tenants"], allowlist));
        Assert.Single(Unexpected("refs.md", ["tenant"], allowlist));
    }

    [Fact]
    public void A_section_entry_allows_its_heading_down_to_the_next_at_its_level()
    {
        Allowed[] allowlist = [new("README.md", Reason.Upgrade, Section: "### Upgrading")];
        string[] lines =
        [
            "## Install", "tenant 2",
            "### Upgrading to 1.0", "tenant 4",
            "#### Checklist", "tenant 6",
            "```bash", "# tenant 8, a comment in a fence", "```",
            "##### Deeper", "tenant 11",
            "### Firewall", "tenant 13",
            "### Upgrading to 2.0", "tenant 15",
            "## Next", "tenant 17",
        ];

        Assert.Equal([2, 13, 17], Unexpected("README.md", lines, allowlist).Select(h => h.Line));
    }

    /// <summary>
    /// The lines of <paramref name="path"/> that say tenant outside <paramref name="allowlist"/>.
    /// Entries that cover a line are added to <paramref name="used"/>.
    /// </summary>
    internal static List<Hit> Unexpected(string path, IReadOnlyList<string> lines, IReadOnlyList<Allowed> allowlist, ISet<Allowed>? used = null)
    {
        var hits = new List<Hit>();
        var entries = allowlist.Where(a => Matches(a.Path, path)).ToList();
        var texts = entries.Where(a => a.Text != null).OrderByDescending(a => a.Text!.Length).ToList();
        var sections = entries.Where(a => a.Section != null).ToList();
        var whole = entries.FirstOrDefault(a => a.Text is null && a.Section is null);

        Allowed? section = null;
        var sectionLevel = 0;
        var fenced = false;
        for (var i = 0; i < lines.Count; i++)
        {
            var line = lines[i];
            if (line.TrimStart().StartsWith("```", StringComparison.Ordinal))
                fenced = !fenced;
            else if (!fenced && HeadingLevel(line) is > 0 and var level)
            {
                if (section != null && level <= sectionLevel)
                    section = null;
                if (section == null && sections.FirstOrDefault(s => line.Contains(s.Section!, StringComparison.Ordinal)) is { } opened)
                    (section, sectionLevel) = (opened, level);
            }

            if (!Says(line))
                continue;
            if ((whole ?? section) is { } covering)
            {
                used?.Add(covering);
                continue;
            }

            var rest = line;
            foreach (var entry in texts.Where(t => rest.Contains(t.Text!, StringComparison.OrdinalIgnoreCase)))
            {
                used?.Add(entry);
                rest = rest.Replace(entry.Text!, "", StringComparison.OrdinalIgnoreCase);
            }
            if (Says(rest))
                hits.Add(new Hit(path, i + 1, line));
        }
        return hits;
    }

    /// <summary>Every unexpected line in the source files under <paramref name="root"/>, by path then line.</summary>
    internal static List<Hit> Scan(string root, IReadOnlyList<Allowed> allowlist, ISet<Allowed>? used = null)
    {
        var hits = new List<Hit>();
        foreach (var file in SourceFiles(new DirectoryInfo(root)))
        {
            var text = File.ReadAllText(file.FullName);
            if (!Says(text))
                continue;
            var path = Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
            hits.AddRange(Unexpected(path, text.Split('\n').Select(l => l.TrimEnd('\r')).ToList(), allowlist, used));
        }
        return hits.OrderBy(h => h.Path, StringComparer.Ordinal).ThenBy(h => h.Line).ToList();
    }

    private static IEnumerable<FileInfo> SourceFiles(DirectoryInfo directory)
    {
        foreach (var file in directory.EnumerateFiles())
            if (!SkippedFiles.Contains(file.Name) && Extensions.Contains(file.Extension, StringComparer.OrdinalIgnoreCase))
                yield return file;
        foreach (var child in directory.EnumerateDirectories())
            if (!SkippedDirectories.Contains(child.Name))
                foreach (var file in SourceFiles(child))
                    yield return file;
    }

    private static string FailureMessage(IReadOnlyCollection<Hit> hits) =>
        $"{hits.Count} line(s) say \"{Word}\" outside the allowlist in VocabularyTests. Say space (the delegation scope) or "
        + "instance (the installation), or add an allowlist entry with its reason:\n" + string.Join("\n", hits);

    private static bool Says(string text) => text.Contains(Word, StringComparison.OrdinalIgnoreCase);

    private static int HeadingLevel(string line)
    {
        var level = 0;
        while (level < line.Length && line[level] == '#')
            level++;
        return level is >= 1 and <= 6 && level < line.Length && line[level] == ' ' ? level : 0;
    }

    private static readonly ConcurrentDictionary<string, Regex> Globs = new();

    private static bool Matches(string pattern, string path) =>
        Globs.GetOrAdd(pattern, p => new Regex(
            "^" + Regex.Escape(p).Replace(@"\*\*", ".*").Replace(@"\*", "[^/]*") + (p.EndsWith('/') ? "" : "$"),
            RegexOptions.CultureInvariant)).IsMatch(path);

    private static void Write(string root, string path, params string[] lines)
    {
        var full = Path.Combine(root, path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllLines(full, lines);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("ModularCA.sln not found above " + AppContext.BaseDirectory);
    }
}
