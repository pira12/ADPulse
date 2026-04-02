<#
.SYNOPSIS
    Creates the low-privilege service account for the AD Security Engine.

.DESCRIPTION
    Creates a standard domain user account (svc-secmonitor) with a strong
    random password. This account needs NO special permissions — it only
    needs to be a member of Domain Users.

    Run this script as a Domain Admin ONCE during initial setup.

.PARAMETER AccountName
    The sAMAccountName for the service account (default: svc-secmonitor)

.PARAMETER OUPath
    The OU where the account should be created.
    Example: "OU=Service Accounts,DC=company,DC=local"
    If empty, uses the default Managed Service Accounts container.

.EXAMPLE
    .\create_service_account.ps1 -OUPath "OU=ServiceAccounts,DC=corp,DC=local"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$AccountName = "svc-secmonitor",

    [Parameter(Mandatory=$false)]
    [string]$OUPath = ""
)

$ErrorActionPreference = "Stop"

# Requires ActiveDirectory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "❌ ActiveDirectory PowerShell module not found." -ForegroundColor Red
    Write-Host "   Install RSAT: Install-WindowsFeature -Name RSAT-AD-PowerShell"
    exit 1
}

# Generate a strong random password
Add-Type -AssemblyName System.Web
$Password = [System.Web.Security.Membership]::GeneratePassword(30, 8)
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   AD Security Engine - Service Account Creator               ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if account already exists
$existing = Get-ADUser -Filter "SamAccountName -eq '$AccountName'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "⚠️  Account '$AccountName' already exists." -ForegroundColor Yellow
    Write-Host "   Resetting password and ensuring correct settings..."

    Set-ADUser -Identity $AccountName `
        -Description "AD Security Engine Service Account - Read-Only Domain User" `
        -PasswordNeverExpires $false `
        -CannotChangePassword $false

    Set-ADAccountPassword -Identity $AccountName -NewPassword $SecurePassword -Reset
    Enable-ADAccount -Identity $AccountName

    Write-Host "✅ Existing account updated." -ForegroundColor Green
} else {
    # Build parameters
    $params = @{
        Name                  = $AccountName
        SamAccountName        = $AccountName
        UserPrincipalName     = "$AccountName@$((Get-ADDomain).DNSRoot)"
        DisplayName           = "AD Security Engine Monitor"
        Description           = "AD Security Engine Service Account - Read-Only Domain User - NO ADMIN RIGHTS"
        AccountPassword       = $SecurePassword
        Enabled               = $true
        PasswordNeverExpires  = $false
        CannotChangePassword  = $false
        ChangePasswordAtLogon = $false
    }

    if ($OUPath) {
        $params["Path"] = $OUPath
    }

    New-ADUser @params
    Write-Host "✅ Service account '$AccountName' created successfully." -ForegroundColor Green
}

# Explicitly ensure account is NOT in any admin groups (safety check)
$adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                 "Account Operators", "Backup Operators", "Server Operators")

foreach ($group in $adminGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
        if ($members | Where-Object { $_.SamAccountName -eq $AccountName }) {
            Write-Host "⚠️  Removing '$AccountName' from '$group' (should not be there)" -ForegroundColor Yellow
            Remove-ADGroupMember -Identity $group -Members $AccountName -Confirm:$false
        }
    } catch {}
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ Service Account Ready                                     ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Account Name : $AccountName"
Write-Host "  Password     : $Password"
Write-Host "  Privileges   : Standard Domain User (Domain Users group only)"
Write-Host ""
Write-Host "  ⚠️  IMPORTANT: Save this password securely NOW."
Write-Host "  Add it to your config.ini under [ldap] > password"
Write-Host ""
Write-Host "  The account will be able to read all standard LDAP attributes"
Write-Host "  by default — no additional permissions are required."
Write-Host ""
