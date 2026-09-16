<#
.SYNOPSIS
  Windows client side of the MSAE Kerberos lab: join the Samba forest, trust the tenant CA,
  and enroll from ModularCA by Windows integrated authentication.

.DESCRIPTION
  Run in an elevated PowerShell on a throwaway Windows 10/11 VM. Each step is a switch so the
  script can be re-run after the reboot the join requires.

    .\client-enroll.ps1 -Join -DcIp 192.168.1.10 -DnsDomain lab.msae.test
      (reboots; log back in as LAB\Administrator or a local admin)
    .\client-enroll.ps1 -TrustRoot -RootCer .\tenant-root.cer
    .\client-enroll.ps1 -Ticket
    .\client-enroll.ps1 -Enroll -Template LabDevice -CaLabel staging-ca-r1
    .\client-enroll.ps1 -Enroll -Template LabDevice -CaLabel other-tenant-ca   # expect a refusal

  The policy server URL is https://<CaHost>/msae/<CaLabel>/cep. No credential is passed: the
  enrollment engine obtains a service ticket for HTTP/<CaHost> from the lab KDC and ModularCA
  accepts it against the realm binding.
#>
[CmdletBinding()]
param(
  [switch]$Join,
  [switch]$TrustRoot,
  [switch]$Ticket,
  [switch]$Enroll,
  [string]$DcIp,
  [string]$DnsDomain = 'lab.msae.test',
  [string]$RootCer,
  [string]$CaHost = 'ca4.maroongang.net',
  [string]$CaLabel = 'staging-ca-r1',
  [string]$Template = 'LabDevice',
  [string]$InterfaceAlias = 'Ethernet'
)

$ErrorActionPreference = 'Stop'

if ($Join) {
  if (-not $DcIp) { throw 'Join needs -DcIp' }
  Write-Host "==> DNS -> $DcIp (the DC forwards public names upstream, so $CaHost still resolves)"
  Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DcIp
  Clear-DnsClientCache
  Resolve-DnsName "_kerberos._udp.$DnsDomain" -Type SRV | Out-Null
  Write-Host "==> Joining $DnsDomain (you will be asked for LAB\Administrator; the machine reboots)"
  Add-Computer -DomainName $DnsDomain -Credential (Get-Credential "$($DnsDomain.Split('.')[0].ToUpper())\Administrator") -Restart
  return
}

if ($TrustRoot) {
  if (-not $RootCer) { throw 'TrustRoot needs -RootCer <tenant root .cer>' }
  Write-Host "==> Trusting the tenant CA root in LocalMachine\Root (Get-Certificate refuses an untrusted issuer)"
  Import-Certificate -FilePath $RootCer -CertStoreLocation Cert:\LocalMachine\Root | Format-List Subject, Thumbprint
  return
}

if ($Ticket) {
  Write-Host "==> Machine account (SYSTEM logon session 0x3e7): can it get a ticket for HTTP/$CaHost?"
  klist -li 0x3e7 purge | Out-Null
  klist -li 0x3e7 get "HTTP/$CaHost"
  Write-Host ""
  Write-Host "==> Signed-in user: same question (fails with 0x520 when signed in with a local account; that is expected)"
  klist purge | Out-Null
  klist get "HTTP/$CaHost"
  Write-Host "A ticket listed above means the SPN is registered and the KDC issues for it. ModularCA never sees this step."
  Write-Host "Get-Certificate enrolls as the signed-in user; run it under SYSTEM (psexec -s) or via Group Policy for the machine's own certificate."
  return
}

if ($Enroll) {
  $url = "https://$CaHost/msae/$CaLabel/cep"
  Write-Host "==> Enrolling $Template from $url with Windows integrated authentication (no credential)"
  $result = Get-Certificate -Template $Template -Url $url -CertStoreLocation Cert:\LocalMachine\My
  $result | Format-List Status, Certificate
  if ($result.Certificate) {
    $result.Certificate | Format-List Subject, DnsNameList, NotAfter, Thumbprint
    Write-Host "Subject came from the Kerberos identity, not from this machine: expect CN=<host>.$DnsDomain"
  }
  Write-Host "Check the MSAE audit tab in ModularCA: caller krb:<machine>$@<REALM>, auth Kerberos, or the refusal reason."
  return
}

Write-Host 'Nothing selected. Use -Join, -TrustRoot, -Ticket or -Enroll. See the header comment.'
