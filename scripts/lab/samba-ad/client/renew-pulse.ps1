param([int]$WaitSeconds = 0)
$ErrorActionPreference = 'Continue'
function Show($label) {
  "== $label  (now " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ")"
  Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*Staging CA R1*' } | Sort-Object NotBefore | ForEach-Object {
    $ext = $_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }
    $tpl = if ($ext) { (($ext.Format($false) -replace '\s+', ' ') -replace ',.*', '') } else { '(no template ext)' }
    $left = $_.NotAfter - (Get-Date)
    "  {0}  {1:yyyy-MM-dd HH:mm} -> {2:yyyy-MM-dd HH:mm}  ({3:0.0} h left)  serial {4}  {5}" -f $_.Thumbprint.Substring(0,8), $_.NotBefore, $_.NotAfter, $left.TotalHours, $_.SerialNumber, $tpl
  }
}
if ($WaitSeconds -gt 0) { "waiting $WaitSeconds s"; Start-Sleep -Seconds $WaitSeconds }
$since = Get-Date
Show 'before pulse'
certutil -pulse | Select-Object -Last 1
Start-Sleep -Seconds 30
Show 'after pulse'
"== enrollment events"
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$since} -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*CertificateServicesClient*' -and $_.Id -ne 58 } | Sort-Object TimeCreated | ForEach-Object { "[{0}] {1} {2}: {3}" -f $_.TimeCreated.ToString('HH:mm:ss'), $_.ProviderName.Replace('Microsoft-Windows-CertificateServicesClient-',''), $_.Id, ($_.Message -replace '\s+', ' ') }
