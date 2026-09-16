$ErrorActionPreference = 'Continue'
$url = 'https://ca4.maroongang.net/msae/staging-ca-r1'
"== identity: " + [Security.Principal.WindowsIdentity]::GetCurrent().Name
pktmon stop 2>$null | Out-Null
pktmon filter remove | Out-Null
pktmon filter add krb -p 88 | Out-Null
pktmon start --capture --pkt-size 0 --file-name C:\Users\zadmin\lab\krb2.etl | Out-Null
"== purge"
klist purge | Select-Object -Last 1
"== forced WinHTTP whoami"
try {
  $b = New-Object -ComObject WinHttp.WinHttpRequest.5.1
  $b.SetAutoLogonPolicy(0)
  $b.Open('GET', "$url/whoami", $false); $b.Send()
  "status: " + $b.Status
  "response: " + $b.ResponseText
  "www-authenticate: " + $(try { $b.GetResponseHeader('WWW-Authenticate') } catch { '(none)' })
} catch { "winhttp error: " + $_.Exception.Message }
"== tickets after forced test"
klist | Select-String -Pattern 'Server:|KerbTicket Encryption|Cache Flags' | ForEach-Object { $_.Line.Trim() }
"== enrollment engine LoadPolicy"
try {
  $p = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
  $p.Initialize("$url/cep", '', 2, $false, 2)
  $p.LoadPolicy(2)
  "loaded templates: " + $p.GetTemplates().Count
} catch { "loadpolicy error: " + $_.Exception.Message }
"== tickets after engine"
klist | Select-String -Pattern 'Server:' | ForEach-Object { $_.Line.Trim() }
pktmon stop | Out-Null
pktmon etl2pcap C:\Users\zadmin\lab\krb2.etl -o C:\Users\zadmin\lab\krb2.pcapng | Select-String 'Packets total'
