$ErrorActionPreference = 'Continue'
$since = Get-Date
"== removing the dead zero-lifetime LabReq certificate"
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*Staging CA R1*' -and $_.NotAfter -le $_.NotBefore } | ForEach-Object { "  removed " + $_.Thumbprint; Remove-Item $_.PSPath }
"== now " + (Get-Date -Format 'HH:mm:ss')
certutil -pulse | Select-Object -Last 1
Start-Sleep -Seconds 30
"== machine store (My)"
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*Staging CA R1*' } | Sort-Object NotBefore | ForEach-Object {
  $tpl = ($_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' })
  "  {0} {1:HH:mm}-{2:HH:mm} {3}" -f $_.Thumbprint.Substring(0,8), $_.NotBefore, $_.NotAfter, $(if ($tpl) { ($tpl.Format($false) -replace ',.*','') } else { '' })
}
"== pending requests the client keeps (REQUEST store)"
certutil -store REQUEST 2>&1 | Select-String -Pattern 'Serial Number|Subject:|Template|Request ID|NotBefore|Cert Hash|Enrollment|Policy' | ForEach-Object { "  " + $_.Line.Trim() }
"== autoenrollment events"
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$since} -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*CertificateServicesClient*' -and $_.Id -notin 58 } | Sort-Object TimeCreated | ForEach-Object { "[{0}] {1} {2}: {3}" -f $_.TimeCreated.ToString('HH:mm:ss'), $_.ProviderName.Replace('Microsoft-Windows-CertificateServicesClient-',''), $_.Id, (($_.Message -replace '\s+', ' ')) }
