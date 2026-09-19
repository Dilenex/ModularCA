$ErrorActionPreference = 'Continue'
$url = 'https://ca4.maroongang.net/msae/staging-ca-r1/cep'
"== identity: " + [Security.Principal.WindowsIdentity]::GetCurrent().Name
"== policy-server entries pushed by Group Policy"
Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\PolicyServers' -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object URL, PolicyID, Flags, AuthFlags, Cost | Format-List | Out-String }
"AEPolicy: " + (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ErrorAction SilentlyContinue).AEPolicy
"== remove the hand registration"
try { Remove-CertificateEnrollmentPolicyServer -Url $url -Context Machine -ErrorAction Stop; "removed" } catch { "remove: " + $_.Exception.Message }
"== policy servers now visible to the engine"
Get-CertificateEnrollmentPolicyServer -Scope All -Context Machine | Format-Table Url, AuthType, AutoEnrollmentEnabled -AutoSize | Out-String
"== clear lab certificates from the machine store"
$old = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*Staging CA R1*' }
$old | ForEach-Object { "removing " + $_.Subject + " " + $_.Thumbprint; Remove-Item $_.PSPath }
"== gpupdate + autoenrollment pulse"
gpupdate /force /target:computer | Select-Object -Last 1
certutil -pulse | Select-Object -Last 1
Start-Sleep -Seconds 20
"== machine store afterwards"
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*Staging CA R1*' } | Format-List Subject, NotBefore, Thumbprint | Out-String
"== CertEnroll / autoenrollment events, last 5 minutes"
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*CertificateServicesClient*' } | Select-Object -First 10 | ForEach-Object { "[{0}] {1} {2}: {3}" -f $_.TimeCreated.ToString('HH:mm:ss'), $_.ProviderName.Replace('Microsoft-Windows-CertificateServicesClient-',''), $_.Id, (($_.Message -replace '\s+', ' ')).Substring(0, [Math]::Min(260, $_.Message.Length)) }
