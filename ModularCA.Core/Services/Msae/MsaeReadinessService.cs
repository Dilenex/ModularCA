using DnsClient;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Msae;

namespace ModularCA.Core.Services.Msae;

/// <summary>Looks a hostname up the way a Windows client's SSPI does before it builds a service principal name.</summary>
public interface IHostNameProbe
{
    /// <summary>
    /// The canonical name the resolver returns for <paramref name="host"/>, or null when it does
    /// not resolve. When the canonical name differs from the host, the host is an alias.
    /// </summary>
    Task<string?> CanonicalNameAsync(string host, CancellationToken cancellation = default);
}

/// <summary>
/// Asks DNS what a Windows client's resolver would be told, rather than what this host's own
/// resolver says.
/// </summary>
/// <remarks>
/// The CA host resolves its own name through its hosts file and whatever resolver it was given,
/// which is not what a domain member sees; the first live check failed on a host that enrolled
/// perfectly because its hosts file spelled its name differently. A client only ever sees DNS,
/// so this probe queries the name and reads the answer: a CNAME record for the name means the
/// name is an alias of the record's target, an address record means it is canonical, and no
/// answer means it does not resolve from here, which is a warning rather than a verdict.
/// </remarks>
public sealed class DnsHostNameProbe : IHostNameProbe
{
    private readonly DnsClient.LookupClient _lookup = new(new DnsClient.LookupClientOptions { UseCache = false, ThrowDnsErrors = false, Retries = 1, Timeout = TimeSpan.FromSeconds(3) });

    /// <inheritdoc />
    public async Task<string?> CanonicalNameAsync(string host, CancellationToken cancellation = default)
    {
        var name = host.TrimEnd('.');
        try
        {
            var answers = new List<DnsClient.Protocol.DnsResourceRecord>();
            foreach (var type in new[] { DnsClient.QueryType.A, DnsClient.QueryType.AAAA })
            {
                var response = await _lookup.QueryAsync(name, type, cancellationToken: cancellation);
                if (response.HasError) continue;
                answers.AddRange(response.Answers);
            }
            var cname = answers.CnameRecords().FirstOrDefault(r => string.Equals(r.DomainName.Value.TrimEnd('.'), name, StringComparison.OrdinalIgnoreCase));
            if (cname != null) return cname.CanonicalName.Value.TrimEnd('.');
            var hasAddress = answers.ARecords().Any() || answers.AaaaRecords().Any();
            return hasAddress ? name : null;
        }
        catch (Exception ex) when (ex is DnsClient.DnsResponseException or System.Net.Sockets.SocketException or ArgumentException or OperationCanceledException or InvalidOperationException)
        {
            return null;
        }
    }
}

/// <summary>
/// Evaluates every precondition of Windows autoenrollment for one CA, in dependency order, and
/// says where each failing one is fixed.
/// </summary>
/// <remarks>
/// The preconditions live on four console pages with no visible order between them: the CA's
/// protocol card, the tenant's realm bindings and keys, the enrollment identity under Users, and
/// the templates. Each refuses a step out of order with its own message, so an operator learns
/// the order by hitting every refusal. This service answers all of them at once, from the same
/// data the runtime uses, so a checklist built on it is true rather than decorative. Nothing here
/// changes state.
/// </remarks>
public sealed class MsaeReadinessService(
    ModularCADbContext db,
    SystemConfig config,
    IEnrollmentPrincipalAuthorizer principals,
    IProfileResolutionService profiles,
    IHostNameProbe hostNames,
    IPublicNameResolver names,
    ModularCA.Shared.Signing.ISigningService signer)
{
    /// <summary>Evaluates the CA identified by <paramref name="caId"/>, or returns null when there is no such CA.</summary>
    public async Task<MsaeReadiness?> EvaluateAsync(Guid caId, CancellationToken cancellation = default)
    {
        var ca = await db.CertificateAuthorities.AsNoTracking().Include(c => c.Tenant).FirstOrDefaultAsync(c => c.Id == caId, cancellation);
        if (ca == null) return null;

        var hasTenant = ca.TenantId != Guid.Empty;
        // The console's scope parser resolves ?tenant= by slug and ?ca= by label; an id there is
        // silently dropped and the linked page opens unscoped.
        var scope = hasTenant && !string.IsNullOrWhiteSpace(ca.Tenant?.Slug)
            ? $"?tenant={Uri.EscapeDataString(ca.Tenant!.Slug)}&ca={Uri.EscapeDataString(ca.Label)}"
            : $"?ca={Uri.EscapeDataString(ca.Label)}";
        var baseUrl = config.Https.GetPublicHttpsBaseUrl();
        var result = new MsaeReadiness
        {
            CaId = ca.Id,
            CaLabel = ca.Label,
            TenantId = hasTenant ? ca.TenantId : null,
            CepUrl = $"{baseUrl}/msae/{ca.Label}/cep",
            PolicyId = $"{{{ca.Id.ToString().ToUpperInvariant()}}}",
            EvaluatedAt = DateTime.UtcNow,
        };
        var steps = result.Steps;

        // 0. The signer. Every step below assumes a CA that can sign; a locked signer holds no
        // usable key, and the enrollment endpoints refuse until it is unlocked.
        var signerHealth = await signer.HealthAsync(cancellation);
        steps.Add(new MsaeReadinessStep
        {
            Key = "signer", Title = "The signer is unlocked",
            State = signerHealth.Unlocked ? MsaeReadinessState.Pass : MsaeReadinessState.Fail,
            Detail = signerHealth.Unlocked
                ? $"The signer holds {signerHealth.KeyCount} key(s) on the {signerHealth.Backend} backend."
                : "The signer has not unlocked its keystore; nothing can be issued and the enrollment endpoints answer 503 until it does. Check the node's startup log for the keystore load.",
        });

        // 1. The protocol card.
        var msae = await db.CaProtocolConfigs.AsNoTracking()
            .FirstOrDefaultAsync(p => p.CaId == ca.Id && p.Protocol == MsaeEnrollmentService.Protocol, cancellation);
        var protocolFix = new MsaeReadinessFix { Label = "Open Protocol Config", Path = $"/authorities/protocols{scope}" };
        if (msae == null || !msae.IsEnabled)
        {
            steps.Add(new MsaeReadinessStep
            {
                Key = "msae-enabled", Title = "Windows autoenrollment enabled on the CA", State = MsaeReadinessState.Fail,
                Detail = msae == null ? "The CA has no MSAE protocol configuration yet." : "MSAE is turned off for this CA.",
                Fix = protocolFix,
            });
        }
        else
        {
            steps.Add(new MsaeReadinessStep { Key = "msae-enabled", Title = "Windows autoenrollment enabled on the CA", State = MsaeReadinessState.Pass, Detail = "MSAE is enabled." });
        }

        // 2. Profiles the CA issues with when a request names no template.
        var missing = new List<string>();
        if (msae?.SigningProfileId == null) missing.Add("signing profile");
        if (msae?.CertProfileId == null) missing.Add("certificate profile");
        steps.Add(new MsaeReadinessStep
        {
            Key = "profiles", Title = "Signing and certificate profiles assigned",
            State = missing.Count == 0 ? MsaeReadinessState.Pass : MsaeReadinessState.Fail,
            Detail = missing.Count == 0
                ? "Requests that name no template issue with the CA's MSAE profiles."
                : $"The MSAE card has no {string.Join(" and no ", missing)}; enrollment fails at issuance without them.",
            Fix = missing.Count == 0 ? null : protocolFix,
        });

        // 3. Authentication modes.
        var kerberos = msae?.MsaeAllowKerberos == true;
        var username = msae?.MsaeAllowUsernameToken ?? true;
        steps.Add(new MsaeReadinessStep
        {
            Key = "auth-modes", Title = "Windows integrated authentication allowed",
            State = kerberos ? MsaeReadinessState.Pass : (username ? MsaeReadinessState.Warn : MsaeReadinessState.Fail),
            Detail = kerberos
                ? "Domain members authenticate with their own Kerberos tickets; no credential is configured on clients."
                : username
                    ? "Only username authentication is on. Group Policy autoenrollment cannot supply a username, so machines will not enroll on their own until Kerberos is allowed."
                    : "Neither authentication mode is on; no client can enroll.",
            Fix = kerberos ? null : protocolFix,
        });

        // 4. Realm bindings on the tenant.
        var realms = hasTenant
            ? await db.KerberosRealms.AsNoTracking().Include(r => r.Keys).Include(r => r.EnrollmentUser)
                .Where(r => r.TenantId == ca.TenantId).OrderBy(r => r.Realm).ToListAsync(cancellation)
            : new List<Shared.Entities.KerberosRealmEntity>();
        var enabledRealms = realms.Where(r => r.IsEnabled).ToList();
        result.Realms = enabledRealms.Select(r => new MsaeReadinessRealm { Id = r.Id, Realm = r.Realm, DnsDomain = r.DnsDomain, ServicePrincipal = r.ServicePrincipal }).ToList();

        // The URL a forest's clients are pointed at is built from the name in its binding's service
        // principal when that is a name this service is known by for the tenant, else the public
        // domain. The first enabled binding's URL is the headline; others are listed when they differ.
        var advertised = new Dictionary<Guid, string>();
        foreach (var realm in enabledRealms)
            advertised[realm.Id] = $"{await names.BaseUrlForServicePrincipalAsync(realm.ServicePrincipal, ca.TenantId, cancellation)}/msae/{ca.Label}/cep";
        if (enabledRealms.Count > 0)
            result.CepUrl = advertised[enabledRealms[0].Id];
        var realmFix = hasTenant
            ? new MsaeReadinessFix { Label = "Open the tenant's Kerberos realms", Path = $"/tenants/{ca.TenantId}?tab=kerberos" }
            : new MsaeReadinessFix { Label = "Open Tenants", Path = "/tenants" };
        steps.Add(new MsaeReadinessStep
        {
            Key = "realms", Title = "An Active Directory forest is bound to the tenant",
            State = !hasTenant ? MsaeReadinessState.Fail : enabledRealms.Count > 0 ? MsaeReadinessState.Pass : MsaeReadinessState.Fail,
            Detail = !hasTenant
                ? "This CA belongs to no tenant, and realm bindings are owned by tenants."
                : enabledRealms.Count > 0
                    ? $"{enabledRealms.Count} enabled binding{(enabledRealms.Count == 1 ? "" : "s")}."
                    : realms.Count > 0 ? "Every binding on the tenant is disabled." : "No forest is bound to this CA's tenant; tickets from any forest are refused.",
            Items = realms.Select(r => $"{r.Realm}: {(r.IsEnabled ? "enabled" : "disabled")}, service principal {r.ServicePrincipal}").ToList(),
            Fix = enabledRealms.Count > 0 ? null : realmFix,
        });

        // 5. Keys per realm.
        var now = DateTime.UtcNow;
        var keyItems = new List<string>();
        var keyState = enabledRealms.Count == 0 ? MsaeReadinessState.Skip : MsaeReadinessState.Pass;
        foreach (var realm in enabledRealms)
        {
            var live = realm.Keys.Where(k => k.RetireAfter == null || k.RetireAfter > now).ToList();
            if (live.Count == 0)
            {
                keyState = MsaeReadinessState.Fail;
                keyItems.Add($"{realm.Realm}: no live key; every ticket is refused as Invalid.");
                continue;
            }
            var versions = string.Join(", ", live.Select(k => k.Kvno).Distinct().OrderBy(v => v));
            var retiring = live.Count(k => k.RetireAfter != null);
            var seen = realm.LastUsedAt.HasValue ? $"last ticket accepted {realm.LastUsedAt:yyyy-MM-dd HH:mm} UTC" : "no ticket accepted yet";
            keyItems.Add($"{realm.Realm}: key version{(live.Select(k => k.Kvno).Distinct().Count() == 1 ? "" : "s")} {versions}{(retiring > 0 ? $" ({retiring} retiring)" : "")}; {seen}.");
        }
        steps.Add(new MsaeReadinessStep
        {
            Key = "realm-keys", Title = "Each bound forest has a live key",
            State = keyState,
            Detail = keyState switch
            {
                MsaeReadinessState.Skip => "No enabled forest to check.",
                MsaeReadinessState.Fail => "A forest without a live key cannot have its tickets decrypted.",
                _ => "Tickets from every enabled forest can be decrypted.",
            },
            Items = keyItems,
            Fix = keyState == MsaeReadinessState.Fail ? realmFix : null,
        });

        // 6. Enrollment identity per realm: exists, active, may enroll on this CA.
        var idItems = new List<string>();
        var idState = enabledRealms.Count == 0 ? MsaeReadinessState.Skip : MsaeReadinessState.Pass;
        foreach (var realm in enabledRealms)
        {
            var user = realm.EnrollmentUser;
            if (user == null)
            {
                idState = MsaeReadinessState.Fail;
                idItems.Add($"{realm.Realm}: the enrollment identity no longer exists.");
                continue;
            }
            if (!user.IsActive)
            {
                idState = MsaeReadinessState.Fail;
                idItems.Add($"{realm.Realm}: {user.Username} is disabled.");
                continue;
            }
            if (!await principals.MayEnrollAsync(user.Username, ca.Id))
            {
                idState = MsaeReadinessState.Fail;
                idItems.Add($"{realm.Realm}: {user.Username} holds no enrollment right on {ca.Label}; every request is refused as unauthorized.");
                continue;
            }
            idItems.Add($"{realm.Realm}: acts as {user.Username}{(user.IsServiceIdentity ? " (service identity)" : "")}, may enroll on {ca.Label}.");
        }
        steps.Add(new MsaeReadinessStep
        {
            Key = "enrollment-identity", Title = "Each forest's enrollment identity may enroll on this CA",
            State = idState,
            Detail = idState switch
            {
                MsaeReadinessState.Skip => "No enabled forest to check.",
                MsaeReadinessState.Fail => "Tickets would be accepted and then refused at authorization.",
                _ => "Accepted tickets act as an identity that may request certificates here.",
            },
            Items = idItems,
            Fix = idState == MsaeReadinessState.Fail ? new MsaeReadinessFix { Label = "Open Users", Path = $"/users?tab=service-identities{(hasTenant ? $"&tenant={ca.TenantId}" : "")}" } : null,
        });

        // 7. Templates offered to Windows.
        var templates = await db.CertificateTemplates.AsNoTracking()
            .Where(t => t.CaId == ca.Id && t.IsEnabled && t.MsaeTemplateOid != null)
            .OrderBy(t => t.Name).ToListAsync(cancellation);
        var tplItems = new List<string>();
        var tplState = templates.Count == 0 ? MsaeReadinessState.Fail : MsaeReadinessState.Pass;
        foreach (var t in templates)
        {
            var notes = new List<string>();
            if (!MsaeTemplateOids.IsValid(t.MsaeTemplateOid))
            {
                notes.Add("OID unreadable by Windows; the template is invisible to clients");
                tplState = MsaeReadinessState.Fail;
            }
            if (t.RequestProfileId.HasValue)
            {
                var effective = await profiles.ResolveRequestProfileAsync(t.RequestProfileId.Value);
                if (effective.RequireApproval)
                {
                    notes.Add("request profile requires approval, so every enrollment waits in the approval queue");
                    if (tplState == MsaeReadinessState.Pass) tplState = MsaeReadinessState.Warn;
                }
            }
            tplItems.Add($"{t.Name} (v{t.MsaeMajorVersion}.{t.MsaeMinorVersion}){(notes.Count > 0 ? ": " + string.Join("; ", notes) : "")}");
        }
        steps.Add(new MsaeReadinessStep
        {
            Key = "templates", Title = "At least one template is offered to Windows",
            State = tplState,
            Detail = templates.Count == 0
                ? "No enabled template on this CA is offered to Windows; the policy service lists nothing to enroll."
                : tplState == MsaeReadinessState.Fail
                    ? "A template with an OID Windows cannot parse never appears in the client's list."
                    : $"{templates.Count} template{(templates.Count == 1 ? "" : "s")} listed by the policy service.",
            Items = tplItems,
            Fix = tplState == MsaeReadinessState.Pass ? null : new MsaeReadinessFix { Label = "Open Templates", Path = $"/templates{scope}" },
        });

        // 8. The name clients reach the CA by, and the name the forest issues tickets for. The
        //    service principal may name the public hostname or any hostname of this tenant; a
        //    tenant hostname must also carry a live endpoint certificate, or clients cannot
        //    connect to it at all. Whichever name it is must resolve canonically.
        var publicHost = PublicNameResolver.Normalize(config.Https.PublicDomain);
        var hostItems = new List<string>();
        var hostnamesFix = hasTenant
            ? new MsaeReadinessFix { Label = "Open the tenant's Hostnames", Path = $"/tenants/{ca.TenantId}?tab=hostnames" }
            : realmFix;
        MsaeReadinessState hostState;
        MsaeReadinessFix? hostFix = null;
        if (publicHost == null)
        {
            hostState = MsaeReadinessState.Fail;
            hostItems.Add("No public hostname is configured, so the policy service cannot advertise a URL clients can reach.");
            hostFix = new MsaeReadinessFix { Label = "Open Settings", Path = "/settings?tab=General" };
        }
        else
        {
            hostState = MsaeReadinessState.Pass;
            var toProbe = new List<string>();
            if (enabledRealms.Count == 0) toProbe.Add(publicHost);
            foreach (var realm in enabledRealms)
            {
                var spnHost = PublicNameResolver.HostFromServicePrincipal(realm.ServicePrincipal) ?? realm.ServicePrincipal;
                var known = await names.ResolveAsync(spnHost, ca.TenantId, cancellation);
                if (known == null)
                {
                    hostState = MsaeReadinessState.Fail;
                    hostItems.Add($"{realm.Realm}: the service principal names {spnHost}, which is neither the public hostname {publicHost} nor a hostname of this tenant; the forest issues tickets for a name this service is not called by.");
                    hostFix ??= realmFix;
                    continue;
                }
                if (known.TenantHostname != null)
                {
                    var cert = known.TenantHostname.CertificateId == null ? null
                        : await db.Certificates.AsNoTracking()
                            .Where(c => c.CertificateId == known.TenantHostname.CertificateId)
                            .Select(c => new { c.NotAfter, c.Revoked })
                            .FirstOrDefaultAsync(cancellation);
                    if (cert == null)
                    {
                        hostState = MsaeReadinessState.Fail;
                        hostItems.Add($"{realm.Realm}: {spnHost} is a hostname of this tenant but has no endpoint certificate, so no client can connect to it over TLS. Reissue it.");
                        hostFix = hostnamesFix;
                    }
                    else if (cert.NotAfter.ToUniversalTime() <= now)
                    {
                        hostState = MsaeReadinessState.Fail;
                        hostItems.Add($"{realm.Realm}: the endpoint certificate for {spnHost} expired on {cert.NotAfter:yyyy-MM-dd}; every connection to it fails. Reissue it.");
                        hostFix = hostnamesFix;
                    }
                    else if (cert.Revoked)
                    {
                        hostState = MsaeReadinessState.Fail;
                        hostItems.Add($"{realm.Realm}: the endpoint certificate for {spnHost} is revoked. Reissue it.");
                        hostFix = hostnamesFix;
                    }
                    else
                    {
                        hostItems.Add($"{realm.Realm}: tickets are requested for HTTP/{spnHost}, a hostname of this tenant whose endpoint certificate is valid until {cert.NotAfter:yyyy-MM-dd}.");
                    }
                }
                if (!toProbe.Contains(known.Host)) toProbe.Add(known.Host);
            }
            foreach (var name in toProbe)
            {
                var canonical = await hostNames.CanonicalNameAsync(name, cancellation);
                if (canonical == null)
                {
                    if (hostState == MsaeReadinessState.Pass) hostState = MsaeReadinessState.Warn;
                    hostItems.Add($"{name} does not resolve from this host. Clients in the forest resolve through their own DNS, so this may still work, but it cannot be checked from here.");
                }
                else if (!string.Equals(canonical.TrimEnd('.'), name.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                {
                    hostState = MsaeReadinessState.Fail;
                    hostItems.Add($"{name} is an alias of {canonical}. Windows canonicalises the name before asking for a ticket, asks for HTTP/{canonical}, and falls back to NTLM. Publish {name} as an A record, or register HTTP/{canonical} on the service account as well.");
                    hostFix ??= realmFix;
                }
                else
                {
                    hostItems.Add($"{name} resolves as a canonical name; tickets are requested for HTTP/{name}.");
                }
            }
        }
        steps.Add(new MsaeReadinessStep
        {
            Key = "hostname", Title = "Clients and the forest agree on the CA's name",
            State = hostState,
            Detail = hostState == MsaeReadinessState.Pass
                ? "The service principal names a hostname this service is called by, and the name is canonical."
                : "Kerberos tickets are issued for a name; when the name clients use differs from the one registered, or the name has no working certificate, authentication silently falls back to NTLM and is refused.",
            Items = hostItems,
            Fix = hostState == MsaeReadinessState.Pass ? null : (hostFix ?? realmFix),
        });

        // 9. What the client needs, stated rather than checked.
        steps.Add(new MsaeReadinessStep
        {
            Key = "client-policy", Title = "Clients point at this policy service",
            State = MsaeReadinessState.Pass,
            Detail = "Register the policy server on each domain member, or push it by Group Policy; the tenant root must be trusted on the client.",
            Items =
            [
                $"Policy server URL: {result.CepUrl}",
                .. enabledRealms.Where(r => advertised[r.Id] != result.CepUrl).Select(r => $"Policy server URL for {r.Realm}: {advertised[r.Id]}"),
                $"Policy id: {result.PolicyId}",
                "Authentication: Windows integrated (Kerberos)",
                "Group Policy: Certificate Services Client - Certificate Enrollment Policy, then Auto-Enrollment enabled with renew and update.",
            ],
        });

        result.Ready = steps.All(s => s.State is MsaeReadinessState.Pass or MsaeReadinessState.Warn or MsaeReadinessState.Skip);
        return result;
    }
}
