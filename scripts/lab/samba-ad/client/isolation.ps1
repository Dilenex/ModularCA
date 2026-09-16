$ErrorActionPreference = 'Continue'
klist purge | Out-Null
$base = 'https://ca4.maroongang.net/msae/<other-tenant-ca-label>'
"== identity: " + [Security.Principal.WindowsIdentity]::GetCurrent().Name
"== whoami against <other-tenant-ca-label> with the LAB.MSAE.TEST machine ticket"
$b = New-Object -ComObject WinHttp.WinHttpRequest.5.1
$b.SetAutoLogonPolicy(0)
$b.Open('GET', "$base/whoami", $false); $b.Send()
"status: " + $b.Status + " " + $b.ResponseText
"== engine: register <other-tenant-ca-label> as a policy server"
try {
  Add-CertificateEnrollmentPolicyServer -Url "$base/cep" -Context Machine -ErrorAction Stop | Format-List Url, AuthType | Out-String
} catch { "registration error: " + $_.Exception.Message }
"== engine: enroll LabDevice from <other-tenant-ca-label>"
try {
  $r = Get-Certificate -Template LabDevice -Url "$base/cep" -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
  "status: " + $r.Status
  if ($r.Certificate) { $r.Certificate | Format-List Subject, Issuer, Thumbprint | Out-String }
} catch { "enroll error: " + $_.Exception.Message }
"== control: staging-ca-r1 still issues"
$c = New-Object -ComObject WinHttp.WinHttpRequest.5.1
$c.SetAutoLogonPolicy(0)
$c.Open('GET', 'https://ca4.maroongang.net/msae/staging-ca-r1/whoami', $false); $c.Send()
"status: " + $c.Status
