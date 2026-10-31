Write-Output "=== $env:COMPUTERNAME ==="
Write-Output "User: $env:USERNAME"
Write-Output "OS: $((Get-WMIObject win32_operatingsystem).caption)"
Write-Output "IP: $((Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IpAddress -ne $null }).IPAddress -join ', ')"
Write-Output "Admins:"
net localgroup Administrators
Write-Output "Firewall:"
netsh advfirewall show allprofiles state
Write-Output "=== DONE ==="
