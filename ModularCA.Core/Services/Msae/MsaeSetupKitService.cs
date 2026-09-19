using System.IO.Compression;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services.Hostnames;
using ModularCA.Core.Services.Msae.Kerberos;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Builds the zip a customer's domain administrator needs to point a forest at one CA: the
/// service-account script, the Group Policy push, the tenant root, a client self-check, and a
/// readme with the two rules that are not obvious.
/// </summary>
/// <remarks>
/// Everything in the kit derives from the binding and the CA; nothing needs a round trip to a
/// client. The policy id Windows records for a policy server is the CA's own id, and the friendly
/// name is the one the policy service advertises, so the Group Policy entry the script writes is
/// exactly what a hand registration would have produced. No secret is in the kit: the account
/// password, when ModularCA generated one, was shown once at import and is not stored.
/// </remarks>
public sealed class MsaeSetupKitService(ModularCADbContext db, SystemConfig config, IPublicNameResolver names)
{
    /// <summary>One file in the kit.</summary>
    public sealed record KitFile(string Name, string Content);

    /// <summary>The kit for <paramref name="realmId"/> against <paramref name="caId"/>, or null when either is missing or they belong to different tenants.</summary>
    public async Task<byte[]?> BuildAsync(Guid caId, Guid realmId, CancellationToken cancellation = default)
    {
        var files = await FilesAsync(caId, realmId, cancellation);
        if (files == null) return null;
        using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var file in files)
            {
                var entry = zip.CreateEntry(file.Name, CompressionLevel.Optimal);
                using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
                writer.Write(file.Content);
            }
        }
        return stream.ToArray();
    }

    /// <summary>The kit's files, unzipped. Null when the CA or realm is missing or they belong to different tenants.</summary>
    public async Task<IReadOnlyList<KitFile>?> FilesAsync(Guid caId, Guid realmId, CancellationToken cancellation = default)
    {
        var ca = await db.CertificateAuthorities.AsNoTracking().Include(c => c.Certificate).Include(c => c.Tenant)
            .FirstOrDefaultAsync(c => c.Id == caId, cancellation);
        var realm = await db.KerberosRealms.AsNoTracking().FirstOrDefaultAsync(r => r.Id == realmId, cancellation);
        if (ca == null || realm == null || realm.TenantId != ca.TenantId) return null;

        // The name in the kit is the one the forest issues tickets for, taken from the binding's
        // service principal, when it is a name this service is known by for the tenant; otherwise
        // the public domain, and the readiness check says why.
        var known = await names.ResolveAsync(PublicNameResolver.HostFromServicePrincipal(realm.ServicePrincipal), ca.TenantId, cancellation);
        var host = known?.Host ?? config.Https.PublicDomain;
        var baseUrl = names.BaseUrl(known?.Host);
        var cepUrl = $"{baseUrl}/msae/{ca.Label}/cep";
        var policyId = $"{{{ca.Id.ToString().ToUpperInvariant()}}}";
        var friendlyName = $"{ca.Name} (ModularCA)";
        var tenantName = ca.Tenant?.Name ?? "tenant";

        var files = new List<KitFile>
        {
            new("README.md", Readme(ca.Label, realm.Realm, realm.DnsDomain, cepUrl, policyId, host)),
            new("1-ad-service-account.ps1", KerberosRealmService.SetupScript(realm, tenantName, cepUrl, null, null)),
            new("2-gpo-policy-server.ps1", GpoScript(cepUrl, policyId, friendlyName, realm.DnsDomain)),
            new("3-client-check.ps1", ClientCheck(baseUrl, ca.Label, ca.Name, host)),
        };
        if (!string.IsNullOrWhiteSpace(ca.Certificate?.Pem))
            files.Add(new($"{ca.Label}-root.cer", ca.Certificate.Pem.Trim() + "\n"));
        return files;
    }

    private static string Readme(string label, string realm, string dnsDomain, string cepUrl, string policyId, string host) => $"""
        # Windows autoenrollment from {label}, forest {realm}

        Run these in order. Each script says what it needs at the top.

        1. `1-ad-service-account.ps1` on a domain controller or any machine with the ActiveDirectory
           module, as a domain administrator. Creates the service account that holds the enrollment
           name and restricts it to AES. If ModularCA generated the account password, paste it when
           asked; it was shown once at import and is not in this kit.
        2. `2-gpo-policy-server.ps1` as a domain administrator with the Group Policy tools. Writes the
           policy server and autoenrollment settings into a Group Policy object (the Default Domain
           Policy unless you pass -GpoName). Members pick it up at their next refresh.
        3. `{label}-root.cer` must be trusted by every member. Either publish it through the same GPO
           (Public Key Policies, Trusted Root Certification Authorities) or import it by hand.
        4. `3-client-check.ps1` on one member, run as SYSTEM (for machine certificates) after a policy
           refresh. It shows what the CA thinks of the machine's ticket and pulses autoenrollment.

        Values the scripts carry:

        - Policy server URL: {cepUrl}
        - Policy id: {policyId}
        - Authentication: Windows integrated (Kerberos)

        Two rules that are not obvious:

        - Members must resolve `{host}` as a canonical name, an A record, never a CNAME or a
          hosts-file line that lists another name first. Windows canonicalises the name before it
          asks for a ticket; an alias makes it ask for the wrong name and fall back to NTLM, which
          the CA refuses.
        - Machine certificates are requested under the machine account. A test run from an ordinary
          admin window enrolls as that user; use `psexec -s` or a scheduled task as SYSTEM to test
          what Group Policy will do.

        Every accepted or refused request appears on the CA's audit page under MSAE, with the reason.
        """.Replace("\r\n", "\n");

    private static string GpoScript(string cepUrl, string policyId, string friendlyName, string dnsDomain) => $$"""
        <#
        .SYNOPSIS
          Point this domain's members at the ModularCA policy server and turn on autoenrollment.

        .DESCRIPTION
          Writes the same registry values a hand registration records, into a Group Policy object,
          so every member enrolls with no command run on it. Run as a domain administrator on a
          machine with the Group Policy management tools (RSAT); the script installs them if missing.

            .\2-gpo-policy-server.ps1                       # Default Domain Policy
            .\2-gpo-policy-server.ps1 -GpoName 'ModularCA'  # a GPO you created and linked
        #>
        [CmdletBinding()]
        param(
          [string]$GpoName = 'Default Domain Policy',
          [string]$Domain = '{{dnsDomain}}'
        )
        $ErrorActionPreference = 'Stop'

        $CepUrl       = '{{cepUrl}}'
        $PolicyId     = '{{policyId}}'
        $FriendlyName = '{{friendlyName}}'

        if (-not (Get-Module -ListAvailable GroupPolicy)) {
          Write-Host '==> Installing RSAT: Group Policy Management Tools'
          Add-WindowsCapability -Online -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0' | Out-Null
        }
        Import-Module GroupPolicy

        # One key per policy server under the Policies hive; the name only has to be unique.
        $serverKey = "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\PolicyServers\$PolicyId"
        # Flags: 0x01 set by Group Policy, 0x10 autoenrollment enabled, 0x20 no strong validation of the policy server's TLS chain.
        $flags = 0x31
        Write-Host "==> $GpoName : policy server $CepUrl (Kerberos, autoenrollment on)"
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName URL          -Type String -Value $CepUrl | Out-Null
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName PolicyID     -Type String -Value $PolicyId | Out-Null
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName FriendlyName -Type String -Value $FriendlyName | Out-Null
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName Flags        -Type DWord  -Value $flags | Out-Null
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName AuthFlags    -Type DWord  -Value 2 | Out-Null   # 2 = Kerberos
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName Cost         -Type DWord  -Value 1 | Out-Null
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\PolicyServers' -ValueName Flags -Type DWord -Value 0 | Out-Null

        Write-Host '==> Autoenrollment: enabled, renew expired, update pending, update templates'
        # AEPolicy bits: 1 renew and update expired, 2 update pending, 4 update templates.
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type DWord -Value 7 | Out-Null
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName OfflineExpirationPercent -Type DWord -Value 10 | Out-Null
        Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName OfflineExpirationStoreNames -Type MultiString -Value @('MY') | Out-Null

        Get-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey | Format-Table ValueName, Value -AutoSize
        Write-Host 'Done. On a member: gpupdate /force; certutil -pulse; then check Cert:\LocalMachine\My.'
        Write-Host 'The CA root must be trusted on members as well: Public Key Policies > Trusted Root Certification Authorities in the same GPO.'
        """.Replace("\r\n", "\n");

    private static string ClientCheck(string baseUrl, string label, string caName, string host) => $$"""
        <#
        .SYNOPSIS
          What the CA thinks of this machine's Kerberos ticket, then one autoenrollment pulse.

        .DESCRIPTION
          Run as SYSTEM to test machine enrollment (psexec -s, or a scheduled task), after
          gpupdate /force. Prints the accepted principal or the CA's refusal with its reason, then
          pulses autoenrollment and lists certificates from the CA in the machine store.
        #>
        $ErrorActionPreference = 'Continue'
        "identity: " + [Security.Principal.WindowsIdentity]::GetCurrent().Name
        "resolves {{host}} as: " + (try { ([Net.Dns]::GetHostEntry('{{host}}')).HostName } catch { 'unresolvable' })
        "ticket for HTTP/{{host}}:"
        klist get "HTTP/{{host}}" 2>&1 | Select-String 'Server:|Cached|error|failed' | ForEach-Object { '  ' + $_.Line.Trim() }
        "whoami at the CA:"
        try {
          $b = New-Object -ComObject WinHttp.WinHttpRequest.5.1
          $b.SetAutoLogonPolicy(0)
          $b.Open('GET', '{{baseUrl}}/msae/{{label}}/whoami', $false); $b.Send()
          "  " + $b.Status + " " + $b.ResponseText
        } catch { "  error: " + $_.Exception.Message }
        "autoenrollment pulse:"
        certutil -pulse | Select-Object -Last 1
        Start-Sleep -Seconds 20
        "certificates issued by {{caName}} in the machine store:"
        Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*{{caName}}*' } | ForEach-Object {
          $tpl = ($_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' })
          "  {0}  {1:yyyy-MM-dd HH:mm} -> {2:yyyy-MM-dd HH:mm}  {3}  {4}" -f $_.Thumbprint.Substring(0,8), $_.NotBefore, $_.NotAfter, $_.Subject, $(if ($tpl) { ($tpl.Format($false) -replace ',.*','') } else { '' })
        }
        """.Replace("\r\n", "\n");
}
