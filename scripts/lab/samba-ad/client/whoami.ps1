"tickets before: " + ((klist | Select-String 'Server: HTTP' | ForEach-Object { $_.Line.Trim() }) -join '; ')
$b = New-Object -ComObject WinHttp.WinHttpRequest.5.1
$b.SetAutoLogonPolicy(0)
$b.Open('GET', 'https://ca4.maroongang.net/msae/staging-ca-r1/whoami', $false); $b.Send()
"whoami: " + $b.Status + " " + $b.ResponseText
