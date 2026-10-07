using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The reflection guard behind <see cref="SpaceIsolationMatrixTests"/>. A read that is not
/// anonymous, carries no instance-rank policy and whose route names no CA is authorized as
/// "holds the capability on any CA" (a CA-scoped policy) or as "is signed in" (plain
/// [Authorize]), so whatever it returns must be fenced by the action itself: there is no query
/// filter behind it since 0.4.0 S4. Reads are every GET plus the POSTs that only query
/// (<see cref="QueryPosts"/>). Every such endpoint must be listed here with the fence it applies,
/// so a new one cannot ship without someone deciding what it shows to another space.
/// </summary>
public sealed class SpaceFenceGuardTests
{
    /// <summary>Instance-rank policies: an endpoint that also carries one is not reachable from a space.</summary>
    private static readonly string[] InstancePolicies =
        ModularCA.Auth.Authorization.PolicyDefinitions.All.Where(p => p.Value.SystemOnly).Select(p => p.Key).ToArray();

    /// <summary>POST endpoints that change nothing and answer about rows: reads for this guard.</summary>
    private static readonly string[] QueryPosts =
    [
        "AdminCertProfileController.ValidateInheritance", "AdminRequestProfileController.ValidateInheritance",
        "AdminCertSignRequestController.ValidateAgainstProfile", "UserCertSignRequestController.ValidateAgainstProfile",
        "AdminCertSignRequestController.ParseCsr", "UserCertSignRequestController.ParseCsr",
        "AdminPolicyController.CheckPolicy",
    ];

    /// <summary>Route values the policy handler always resolves to the CA it then checks.</summary>
    private static readonly string[] CaRouteValues = ["caId", "caKeyId", "label", "caCertificateId"];

    /// <summary><c>{id}</c> under these paths always resolves to a CA (an SSH CA key, or a template's key).</summary>
    private static readonly string[] CaBoundIdPaths = ["ssh/ca-keys/", "ssh/templates/"];

    /// <summary>Controller.Action → the fence the action applies.</summary>
    internal static readonly IReadOnlyDictionary<string, string> Allowlist = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["AccountBadgesController.Get"] = "own rows: the caller's badges",
        ["AccountBadgesController.List"] = "own rows: the caller's badges",
        ["AccountBadgesController.Sources"] = "own rows: the caller's grant sources",
        ["AccountManagerController.GetMfaStatus"] = "own rows: the caller's account",
        ["AccountManagerController.GetUserInfo"] = "own rows: the caller's account",
        ["AdminCertProfileController.ValidateInheritance"] = "SpaceFence.AllowsProfile (cert.view), else 404",
        ["AdminCertSignRequestController.ParseCsr"] = "no rows: parses the posted CSR",
        ["AdminCertSignRequestController.ValidateAgainstProfile"] = "SpaceFence.AllowsRequestProfileAsync (cert.view), else 404",
        ["AdminKerberosRealmController.Get"] = "DenyAsync: ca.manage across the route's space (HasScopeCapabilityAsync)",
        ["AdminKerberosRealmController.List"] = "DenyAsync: ca.manage across the route's space (HasScopeCapabilityAsync)",
        ["AdminKerberosRealmController.SetupScript"] = "DenyAsync: ca.manage across the route's space (HasScopeCapabilityAsync)",
        ["AdminKeyCeremonyController.Approvers"] = "capability: ca.manage across the scope (HasScopeCapabilityAsync); returns counts only",
        ["AdminKeyCeremonyController.GetById"] ="CanAccessCeremonyAsync: ca.manage across the ceremony's scope, or a tier that can approve it",
        ["AdminKeyCeremonyController.List"] = "ListBySpacesAsync over the caller's ceremony spaces and tiers, then CanAccessCeremonyAsync",
        ["AdminPolicyController.CheckPolicy"] = "no rows: evaluates the posted parameters against the instance policy rules",
        ["AdminRequestProfileController.ValidateInheritance"] = "InFenceAsync: SpaceFence.Allows on the bound CA (cert.view), else 404",
        ["AdminServiceIdentityController.Get"] = "ServiceIdentityService.MayManageAsync on the identity's scope, else 404",
        ["AdminServiceIdentityController.List"] = "ServiceIdentityService.ListAsync: scopes the caller holds ca.manage on",
        ["MeController.GetEffectivePermissions"] = "own rows: the caller's grants",
        ["MeController.GetMe"] = "own rows: the caller's account and capabilities",
        ["MeController.GetPreferences"] = "own rows: the caller's preferences",
        ["MtlsController.GetAllowedCas"] = "own rows: the mTLS signing CAs of the caller's groups",
        ["MtlsController.ListCredentials"] = "own rows: the caller's credentials",
        ["UserCertSignRequestController.ParseCsr"] = "no rows: parses the posted CSR",
        ["UserCertSignRequestController.ValidateAgainstProfile"] = "SpaceFence.AllowsRequestProfileAsync (cert.request), else 404",
        ["VersionController.Get"] = "no rows: the build version",
        ["WebAuthnController.ListCredentials"] = "own rows: the caller's credentials",
        ["AdminAcmeEabController.ListEabKeys"] = "instance credential: empty unless the cert.revoke fence is instance-wide",
        ["AdminAuditController.GetActionTypes"] = "no rows: the action names the build declares",
        ["AdminAuditController.GetAcmeAudit"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetAcmeAuditById"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetAuditLogById"] = "capability: GetAccessibleCaIdsAsync(audit.view), system rows need system scope",
        ["AdminAuditController.GetAuditLogs"] = "capability: GetAccessibleCaIdsAsync(audit.view), system rows need system scope",
        ["AdminAuditController.GetCmpAudit"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetCmpAuditById"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetEstAudit"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetEstAuditById"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetMsaeAudit"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetMsaeAuditById"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetNetworkAudit"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetNetworkAuditById"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetScepAudit"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminAuditController.GetScepAuditById"] = "capability: CA ids (a legacy row's label) from GetAccessibleCaIdsAsync(audit.view)",
        ["AdminCaController.GetAllCaCertificates"] = "SpaceFence.Predicate over the owning CA",
        ["AdminCaController.GetCertificateAuthorities"] = "SpaceFence.Predicate",
        ["AdminCaController.GetCertificateFile"] = "CallerCanSeeCaCertAsync: SpaceFence.Allows on the owning CA",
        ["AdminCaController.GetCertificateInfo"] = "CallerCanSeeCaCertAsync: SpaceFence.Allows on the owning CA",
        ["AdminCaController.GetHierarchy"] = "SpaceFence.Predicate",
        ["AdminCaController.GetSystemCaCertificates"] = "public: the system signing CA's certificate, shown to every CA auditor",
        ["AdminCaServiceUrlController.GetAll"] = "SpaceFence.Predicate over the owning CA",
        ["AdminCertPermissionManagerController.GetBySerial"] = "SpaceFence.Allows on the certificate's CA; no CA needs instance-wide",
        ["AdminCertProfileController.GetAll"] = "SpaceFence.ProfilePredicate, then profile.* grants",
        ["AdminCertProfileController.GetById"] = "SpaceFence.AllowsProfile (N1)",
        ["AdminCertProfileController.GetResolved"] = "SpaceFence.AllowsProfile (N1)",
        ["AdminCtLogOptionsController.GetOptions"] = "instance-wide CT log catalog with no space binding; id, name, URL and enabled only; writes are SystemOperator",
        ["AdminCertSignRequestController.GetApprovals"] = "EnforceSpaceFenceAsync: SpaceFence.Allows on the CSR's CA",
        ["AdminCertSignRequestController.RetrievePendingRequests"] = "capability: GetAccessibleCaIdsAsync(cert.view)",
        ["AdminCertificateController.ExpiryHistogram"] = "capability: BuildAccessibleCertificatesQueryAsync",
        ["AdminCertificateController.GetCertificate"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["AdminCertificateController.GetCertificateChain"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["AdminCertificateController.GetCertificateExtensions"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["AdminCertificateController.GetCertificateHealth"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["AdminCertificateController.GetCertificateImpact"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["AdminCertificateController.GetCertificateInfo"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["AdminCertificateController.GetCertificateTags"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["AdminCertificateController.GetHealthSummary"] = "capability: BuildAccessibleCertificatesQueryAsync",
        ["AdminCertificateController.GetLifecycleSummary"] = "capability: BuildAccessibleCertificatesQueryAsync",
        ["AdminCertificateController.ListCertificates"] = "capability: BuildAccessibleCertificatesQueryAsync",
        ["AdminCertificateController.SearchCertificatesByTag"] = "capability: CertificateAccessEvaluator.CanViewCertificate per row",
        ["AdminCrlController.GetCrlByCaSerial"] = "public: the CA's published CRL, served anonymously at its CDP",
        ["AdminCrlScheduleController.GetAll"] = "SpaceFence.Predicate over the owning CA",
        ["AdminCrlScheduleController.GetById"] = "ResolveAndFenceScheduleAsync: SpaceFence.Allows",
        ["AdminEnrollmentTokenController.GetActiveTokens"] = "MayManageToken: SpaceFence.Allows; unbound tokens need instance-wide",
        ["AdminGroupController.GetAll"] = "SpaceFence.Predicate",
        ["AdminGroupController.GetById"] = "SpaceFence.Allows",
        ["AdminIssuanceController.GetValidityCeiling"] = "EnforceSpaceFence on the signing profile's CA, then profile.use",
        ["AdminRequestProfileController.GetAll"] = "SpaceFence.Allows on the bound CA; unbound are instance-wide",
        ["AdminRequestProfileController.GetById"] = "SpaceFence.Allows on the bound CA; unbound are instance-wide",
        ["AdminRequestProfileController.GetResolved"] = "SpaceFence.Allows on the bound CA; unbound are instance-wide",
        ["AdminSigningProfileController.GetAll"] = "SpaceFence.Allows on the issuing CA, then profile.* grants",
        ["AdminSigningProfileController.GetAllowedCertProfiles"] = "SpaceFence.Allows on the issuing CA",
        ["AdminSigningProfileController.GetById"] = "SpaceFence.Allows on the issuing CA",
        ["AdminSshController.DownloadCertificate"] = "SpaceFence.Allows on the SSH CA",
        ["AdminSshController.GetCaKeys"] = "SpaceFence.Allows on the SSH CA",
        ["AdminSshController.GetPlaintextNotice"] = "SpaceFence.Allows(null): SSH CAs are instance CAs, so instance scope (cert.revoke), else 404",
        ["AdminSshLoginNameController.FindCertificates"] = "KeysWithAsync: GetAccessibleCaIdsAsync(cert.view), then SpaceFence.Allows on each SSH CA",
        ["AdminSshLoginNameController.GetCertificate"] = "KeysWithAsync: GetAccessibleCaIdsAsync(cert.view), then SpaceFence.Allows on the SSH CA, else 404",
        ["AdminSshLoginNameController.GetGroupLoginNames"] = "SpaceFence.Allows on the group (cert.view), else 404; grants only of KeysWithAsync(cert.view)",
        ["AdminSshLoginNameController.GetUserCertificates"] = "VisibleUserAsync: SpaceFence.Allows over the user's scopes (user.manage), else 404; certificates only of KeysWithAsync(cert.view)",
        ["AdminSshLoginNameController.GetUserLoginNames"] = "VisibleUserAsync: SpaceFence.Allows over the user's scopes (user.manage), else 404; names only of KeysWithAsync(cert.view)",
        ["AdminSshProfileController.GetCertProfile"] = "instance-wide SSH cert-profile catalog with no space binding; writes are system-admin only",
        ["AdminSshProfileController.GetCertProfiles"] = "instance-wide SSH cert-profile catalog with no space binding; writes are system-admin only",
        ["AdminSshProfileController.GetRequestProfile"] = "IsRequestProfileAccessibleAsync: SpaceFence.Allows",
        ["AdminSshProfileController.GetRequestProfiles"] = "SpaceFence.Predicate over the bound CA",
        ["AdminSshProfileController.GetSigningProfile"] = "ResolveAndFenceBySshCaKeyAsync: SpaceFence.Allows",
        ["AdminSshProfileController.GetSigningProfiles"] = "SpaceFence.Predicate over the key's CA",
        ["AdminSshTemplateController.GetAll"] = "SpaceFence.Predicate over the key's CA",
        ["AdminUserManagerController.GetUserByEmail"] = "ScopeToCallerAsync: SpaceFence.Predicate over the user's groups",
        ["AdminUserManagerController.GetUserById"] = "ScopeToCallerAsync: SpaceFence.Predicate over the user's groups",
        ["AdminUserManagerController.GetUserByUsername"] = "ScopeToCallerAsync: SpaceFence.Predicate over the user's groups",
        ["AdminUserManagerController.GetUsers"] = "ScopeToCallerAsync: SpaceFence.Predicate over the user's groups",
        ["AdminWhitelistController.GetAll"] = "SpaceFence.Allows on the CA; global rules need instance scope",
        ["AdminWhitelistController.GetById"] = "SpaceFence.Allows on the CA; global rules need instance scope",
        ["UserCaController.GetCaChain"] = "CallerCanSeeCaCertAsync and SpaceFence.Allows per parent",
        ["UserCaController.GetCaCrl"] = "public: redirects to the anonymous CDP",
        ["UserCaController.GetCertificate"] = "CallerCanSeeCaCertAsync: SpaceFence.Allows",
        ["UserCaController.GetCertificateInfo"] = "CallerCanSeeCaCertAsync: SpaceFence.Allows",
        ["UserCaController.GetValidCaCertificates"] = "SpaceFence.Predicate over the owning CA",
        ["UserCertSignRequestController.GetMyRequests"] = "own rows: RequestorUserId",
        ["UserGroupController.GetMyGroups"] = "own rows: the caller's memberships",
        ["UserRequestProfileController.GetAccessibleRequestProfiles"] = "own rows: CAs of the caller's groups, plus unbound profiles",
        ["UserSigningProfileController.GetSigningProfiles"] = "SpaceFence.Predicate over the issuing CA, then profile.* grants",
        ["UserSshController.DownloadCertificate"] = "own rows: SubjectUserId, or IssuedByUserId for a row from before login names",
        ["UserSshController.GetCaKeys"] = "capability: GetAccessibleCaIdsAsync(cert.request)",
        ["UserSshController.GetCertificates"] = "own rows: SubjectUserId, or IssuedByUserId for a row from before login names",
        ["UserSshController.GetRequestOptions"] = "own rows: the caller's login names; keys by GetAccessibleCaIdsAsync(cert.request)",
        ["UserCertificateController.GetCertificate"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["UserCertificateController.GetCertificateChain"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["UserCertificateController.GetCertificateInfo"] = "capability: CertificateAccessEvaluator.CanViewCertificate",
        ["UserCertificateController.ListCertificates"] = "SpaceFence.Predicate, then CanViewCertificate",
    };

    /// <summary>
    /// Every non-anonymous read (a GET, or a POST in <see cref="QueryPosts"/>) with no instance-rank
    /// policy whose route names no CA, as Controller.Action → route.
    /// </summary>
    internal static IReadOnlyDictionary<string, string> UnfencedReads()
    {
        var found = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var controller in ApiAssembly.ControllerTypes())
        {
            var classAttributes = controller.GetCustomAttributes(true);
            var classRoute = classAttributes.OfType<RouteAttribute>().FirstOrDefault()?.Template ?? string.Empty;
            foreach (var action in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            {
                var actionAttributes = action.GetCustomAttributes(true);
                var key = $"{controller.Name}.{action.Name}";
                var reads = actionAttributes.OfType<HttpMethodAttribute>()
                    .Where(a => a is HttpGetAttribute || (a is HttpPostAttribute && QueryPosts.Contains(key)))
                    .ToList();
                if (reads.Count == 0 || classAttributes.Concat(actionAttributes).OfType<IAllowAnonymous>().Any())
                    continue;
                var policies = classAttributes.Concat(actionAttributes).OfType<IAuthorizeData>().Select(a => a.Policy).ToList();
                if (policies.Any(p => p != null && InstancePolicies.Contains(p)))
                    continue;
                foreach (var read in reads)
                {
                    var route = (classRoute + "/" + (read.Template ?? string.Empty)).TrimEnd('/');
                    if (!NamesCa(route))
                        found[key] = route;
                }
            }
        }
        return found;
    }

    private static bool NamesCa(string route)
    {
        var values = Regex.Matches(route, @"\{(\w+)").Select(m => m.Groups[1].Value).ToList();
        if (values.Any(v => CaRouteValues.Contains(v, StringComparer.OrdinalIgnoreCase)))
            return true;
        return values.Contains("id") && CaBoundIdPaths.Any(p => route.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Every_read_that_names_no_ca_declares_its_fence()
    {
        var unresolved = UnfencedReads();
        var missing = unresolved.Keys.Where(k => !Allowlist.ContainsKey(k)).Select(k => $"{k} ({unresolved[k]})").ToList();
        Assert.True(missing.Count == 0, "Reads with no CA in the route, no instance-rank policy and no declared fence:\n" + string.Join("\n", missing));
        var stale = Allowlist.Keys.Where(k => !unresolved.ContainsKey(k)).ToList();
        Assert.True(stale.Count == 0, "Allowlisted endpoints that no longer exist, name a CA or carry an instance-rank policy:\n" + string.Join("\n", stale));
        var unknownPosts = QueryPosts.Where(k => !unresolved.ContainsKey(k)).ToList();
        Assert.True(unknownPosts.Count == 0, "Query POSTs that no longer exist:\n" + string.Join("\n", unknownPosts));
    }
}
