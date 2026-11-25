<#
  Windows Server 2025 (shared rules also fit 2022) - thin wrapper around the common engines.
  Default is Audit (no changes).
    .\Run-Hardening.ps1                                  # registry rules, audit only
    .\Run-Hardening.ps1 -Policy                          # + audit policy & account policy (needs Administrator)
    .\Run-Hardening.ps1 -Policy -Role DC                 # domain controller rule set
    .\Run-Hardening.ps1 -Policy -PolicyType Right        # user rights only - read the README first
    .\Run-Hardening.ps1 -Mode Apply -Severity CAT1,CAT2 -WhatIf
    .\Run-Hardening.ps1 -Mode Rollback -BackupFile ..\Common\backup-YYYYMMDD-HHMMSS.json
    .\Run-Hardening.ps1 -Policy -Mode Rollback -BackupDir ..\Common\policy-backup-YYYYMMDD-HHMMSS
  Without -Policy only the registry engine runs. With -Policy only the policy engine runs.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Audit', 'Apply', 'Rollback')][string]$Mode = 'Audit',
    [ValidateSet('CAT1', 'CAT2', 'CAT3')][string[]]$Severity,
    [string]$BackupFile,
    [switch]$Policy,
    [ValidateSet('Audit', 'Account', 'Right')][string[]]$PolicyType = @('Audit', 'Account'),
    [ValidateSet('Member', 'DC')][string]$Role = 'Member',
    [string]$BackupDir
)
if ($Policy) {
    $splat = @{ PolicyFile = (Join-Path $PSScriptRoot 'policy-settings.csv'); Mode = $Mode; Type = $PolicyType; Role = $Role }
    if ($Severity) { $splat.Severity = $Severity }
    if ($BackupDir) { $splat.BackupDir = $BackupDir }
    if ($WhatIfPreference) { $splat.WhatIf = $true }
    & (Join-Path $PSScriptRoot '..\Common\Invoke-PolicyHardening.ps1') @splat
    return
}
$files = 'stig-settings.csv', 'custom-settings.csv' | ForEach-Object { Join-Path $PSScriptRoot $_ }
$splat = @{ SettingsFile = $files; Mode = $Mode }
if ($Severity) { $splat.Severity = $Severity }
if ($BackupFile) { $splat.BackupFile = $BackupFile }
if ($WhatIfPreference) { $splat.WhatIf = $true }
& (Join-Path $PSScriptRoot '..\Common\Invoke-RegistryHardening.ps1') @splat
