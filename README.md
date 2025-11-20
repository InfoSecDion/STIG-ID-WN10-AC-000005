# STIG ID: WN10-AC-000005 - Windows 10 account lockout duration must be configured to 15 minutes or greater.

## Synopsis
This PowerShell script ensures that the account lockout duration is set to 15 minutes.

## Notes
- **Author**: Dion Alexander
- **LinkedIn**: 
- **GitHub**: 
- **Date Created**: 2025-11-19
- **Last Modified**: 2025-11-19
- **Version**: 1.0
- **CVEs**: N/A
- **Plugin IDs**: N/A
- **STIG-ID**: WN10-AC-000005
  
## Tested On
- **Date(s) Tested**: 
- **Tested By**: 
- **Systems Tested**: 
- **PowerShell Ver.**: 

## Usage
Put any usage instructions here.

Example syntax:

Example syntax:

```powershell
# STIG ID: WN10-AC-000005
# Title: Account lockout duration must be configured to 15 minutes or greater.

# Requires administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host "This script requires administrative privileges. Please run PowerShell as an Administrator." -ForegroundColor Red
    exit 1
}

$requiredMinutes = 15

Write-Host "Checking current account lockout duration..." -ForegroundColor Cyan

# Get current lockout duration from 'net accounts'
$lockoutLine = net accounts | Select-String "Lockout duration"

if (-not $lockoutLine) {
    Write-Host "Unable to read current lockout duration. Applying STIG value of $requiredMinutes minutes..." -ForegroundColor Yellow
    net accounts /lockoutduration:$requiredMinutes | Out-Null
}
else {
    # Extract numeric minutes
    $match = [regex]::Match($lockoutLine.ToString(), '\d+')

    if (-not $match.Success) {
        Write-Host "Could not parse lockout duration. Applying STIG value of $requiredMinutes minutes..." -ForegroundColor Yellow
        net accounts /lockoutduration:$requiredMinutes | Out-Null
    }
    else {
        [int]$currentMinutes = $match.Value
        Write-Host "Current lockout duration: $currentMinutes minute(s)."

        if ($currentMinutes -lt $requiredMinutes) {
            Write-Host "Current value is below STIG requirement. Setting lockout duration to $requiredMinutes minutes..." -ForegroundColor Cyan
            net accounts /lockoutduration:$requiredMinutes | Out-Null
        }
        else {
            Write-Host "Lockout duration already meets or exceeds STIG requirement. No change needed." -ForegroundColor Green
        }
    }
}

# Verify the change
Write-Host "Verifying lockout duration after configuration..." -ForegroundColor Cyan
$verifyLine = net accounts | Select-String "Lockout duration"
Write-Host $verifyLine.ToString()

Write-Host "STIG WN10-AC-000005 enforcement complete. A logoff or reboot may be required for the change to fully apply." -ForegroundColor Green
```
