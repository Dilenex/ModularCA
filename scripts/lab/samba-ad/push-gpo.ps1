<#
.SYNOPSIS
  Push the ModularCA enrollment policy server and autoenrollment into the lab domain's Default
  Domain Policy, so a freshly joined machine enrolls with no command run on it.

.DESCRIPTION
  Run on a domain-joined Windows machine, in a PowerShell started as a domain admin
  (LAB\Administrator). Needs the Group Policy management tools; the script installs them if
  missing (Settings > Optional features, RSAT: Group Policy Management Tools; needs Windows
  Update reachability). Samba stores policy in SYSVOL like any DC, and the GroupPolicy module
  writes registry.pol there directly.

  The values are the ones the enrollment client itself records when a policy server is registered
  by hand (HKLM\SOFTWARE\Microsoft\Cryptography\PolicyServers\<hash>), placed under the Policies
  key instead. PolicyId comes from the CEP GetPolicies response for the CA.

    .\push-gpo.ps1 -CepUrl https://ca4.maroongang.net/msae/staging-ca-r1/cep `
                   -PolicyId '{C862CB48-E273-4B4F-8F85-9150C1D719E0}' -FriendlyName 'Staging CA R1 (ModularCA)'

  Then on any member: gpupdate /force; certutil -pulse. The tenant root still has to be trusted;
  the GPMC's Public Key Policies editor can publish it, or client-enroll.ps1 -TrustRoot per machine.

  Untested against Samba as of 2026-09-15; the manual registration path proved the same client
  behaviour. If Windows ignores the entry, compare with what Add-CertificateEnrollmentPolicyServer
  writes on a member and adjust Flags.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$CepUrl,
  [Parameter(Mandatory)] [string]$PolicyId,
  [string]$FriendlyName = 'ModularCA',
  [string]$GpoName = 'Default Domain Policy',
  [string]$Domain = 'lab.msae.test'
)
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable GroupPolicy)) {
  Write-Host '==> Installing RSAT: Group Policy Management Tools'
  Add-WindowsCapability -Online -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0' | Out-Null
}
Import-Module GroupPolicy

# One registry key per policy server, named by a GUID of our choosing (the client hashes the
# URL for its own entries; under Policies any unique name works).
$serverKey = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\PolicyServers\{7B1B1F3A-4D7A-4F0E-9C2B-0D2F3A5E6C10}'
# Flags: 0x01 location is Group Policy, 0x10 autoenrollment enabled, 0x20 do not require the
# policy server's TLS CA to be trusted for policy validation (RequireStrongValidation = false).
$flags = 0x31
Write-Host "==> $GpoName : policy server $CepUrl (Kerberos, autoenrollment on)"
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName URL          -Type String -Value $CepUrl | Out-Null
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName PolicyID     -Type String -Value $PolicyId | Out-Null
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName FriendlyName -Type String -Value $FriendlyName | Out-Null
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName Flags        -Type DWord  -Value $flags | Out-Null
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName AuthFlags    -Type DWord  -Value 2 | Out-Null   # 2 = Kerberos
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey -ValueName Cost         -Type DWord  -Value 1 | Out-Null
# The parent key's Flags marks the policy-server list as configured by policy.
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\PolicyServers' -ValueName Flags -Type DWord -Value 0 | Out-Null

Write-Host '==> Autoenrollment: enabled, renew expired, update pending, update templates'
# AEPolicy: 1 renew/update expired, 2 update pending, 4 update templates; 0x8000 would disable.
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type DWord -Value 7 | Out-Null
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName OfflineExpirationPercent -Type DWord -Value 10 | Out-Null
Set-GPRegistryValue -Name $GpoName -Domain $Domain -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName OfflineExpirationStoreNames -Type MultiString -Value @('MY') | Out-Null

Get-GPRegistryValue -Name $GpoName -Domain $Domain -Key $serverKey | Format-Table ValueName, Value -AutoSize
Write-Host 'Done. On a member: gpupdate /force; certutil -pulse; then check Cert:\LocalMachine\My.'
