# Example hardening script. Runs elevated (admin over WinRM).
# stdout/stderr/exit code are reported per host by coordinate.

Write-Output "Hostname: $env:COMPUTERNAME"

# Enable the Windows Firewall on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Turn Defender real-time protection back on
Set-MpPreference -DisableRealtimeMonitoring $false

# Example: report local administrators (useful for scoring/recon)
Write-Output "Local admins:"
Get-LocalGroupMember -Group Administrators | ForEach-Object { Write-Output "  $($_.Name)" }
