[CmdletBinding()]
param()

# Installs the Microsoft Active Directory PowerShell module required by the PCR scripts.
# Run this script from an elevated Windows PowerShell or PowerShell 7 session.
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator rights are required. Open PowerShell as Administrator and run .\setup-ad-module.ps1 again.'
}

if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory
    Write-Host 'ActiveDirectory module is already installed.' -ForegroundColor Green
}
else {
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -eq 1) {
        # Windows client: RSAT is an optional Windows capability.
        $capabilityName = 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
        $capability = Get-WindowsCapability -Online -Name $capabilityName
        if ($capability.State -ne 'Installed') {
            Add-WindowsCapability -Online -Name $capabilityName | Out-Host
        }
    }
    else {
        # Windows Server: the same tools are provided by the AD DS RSAT feature.
        if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
            Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature | Out-Host
        }
        else {
            throw 'Install-WindowsFeature is unavailable. Install RSAT-AD-PowerShell using Server Manager or the appropriate Server image.'
        }
    }

    Import-Module ActiveDirectory -ErrorAction Stop
}

$required = @(
    'Get-ADGroupMember',
    'Get-ADUser',
    'Get-ADDomain',
    'Set-ADAccountPassword',
    'Set-ADUser',
    'Unlock-ADAccount'
)
$missing = @($required | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($missing.Count -gt 0) {
    throw "ActiveDirectory installed, but required cmdlets are missing: $($missing -join ', ')"
}

Get-Module ActiveDirectory | Select-Object Name, Version, Path
Write-Host 'Active Directory module setup and verification completed.' -ForegroundColor Green
