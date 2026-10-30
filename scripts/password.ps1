# Password-rotation script for the -C / -U (config.json) flow.
# It rotates the current user's password and prints a single line
# "user,newpassword" that coordinate -C collects into config.json.
# Use -E "YOLO=1" style flags from your own wrapper if you want to gate it.

$user = $env:USERNAME
# Generate a random 20-char password
Add-Type -AssemblyName System.Web
$newpass = [System.Web.Security.Membership]::GeneratePassword(20, 4)

$secure = ConvertTo-SecureString $newpass -AsPlainText -Force
Set-LocalUser -Name $user -Password $secure

# This exact format (user,password) is what coordinate -C parses:
Write-Output "$user,$newpass"
