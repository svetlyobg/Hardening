<#
.SYNOPSIS
  Registry-based hardening engine. Works on Windows Home too (no gpedit/LGPO needed).
.PARAMETER SettingsFile
  CSV with columns: Id,Severity,Path,Name,Type,Value,Description
.PARAMETER Mode
  Audit    (default) only report what differs, changes nothing
  Apply    set the values (saves previous values to a backup file first)
  Rollback restore values from -BackupFile
.PARAMETER Severity
  Limit to CAT1, CAT2 or CAT3 (default: all)
.EXAMPLE
  .\Invoke-RegistryHardening.ps1 -SettingsFile '..\Windows 11\settings.csv'
  .\Invoke-RegistryHardening.ps1 -SettingsFile '..\Windows 11\settings.csv' -Mode Apply -Severity CAT1,CAT2
  .\Invoke-RegistryHardening.ps1 -SettingsFile x.csv -Mode Rollback -BackupFile .\backup-20260101-120000.json
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string[]]$SettingsFile,
    [ValidateSet('Audit', 'Apply', 'Rollback')][string]$Mode = 'Audit',
    [ValidateSet('CAT1', 'CAT2', 'CAT3')][string[]]$Severity,
    [string]$BackupFile
)
$ErrorActionPreference = 'Stop'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-Current($path, $name) {
    $key = "Registry::$path"
    if (-not (Test-Path -LiteralPath $key)) { return $null }
    $p = Get-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    $p.$name
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "OS: $($os.Caption) (build $($os.BuildNumber)) | Mode: $Mode" -ForegroundColor Cyan
if ($Mode -ne 'Audit' -and -not (Test-Admin)) { throw 'Run as Administrator for Apply/Rollback.' }

if ($Mode -eq 'Rollback') {
    if (-not $BackupFile) { throw '-BackupFile is required for Rollback.' }
    foreach ($b in (Get-Content $BackupFile -Raw | ConvertFrom-Json)) {
        $key = "Registry::$($b.Path)"
        if ($null -eq $b.Old) {
            if ($PSCmdlet.ShouldProcess("$($b.Path)\$($b.Name)", 'Remove')) {
                Remove-ItemProperty -LiteralPath $key -Name $b.Name -ErrorAction SilentlyContinue
            }
        }
        elseif ($PSCmdlet.ShouldProcess("$($b.Path)\$($b.Name)", "Restore $($b.Old)")) {
            if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
            New-ItemProperty -LiteralPath $key -Name $b.Name -Value $b.Old -PropertyType $b.Type -Force | Out-Null
        }
    }
    Write-Host 'Rollback done.' -ForegroundColor Green
    return
}

$rows = $SettingsFile | ForEach-Object { Import-Csv $_ }
if ($Severity) { $rows = $rows | Where-Object { $Severity -contains $_.Severity } }
# same key listed twice (e.g. in STIG and custom file): first one wins, so the backup stays correct
$rows = $rows | Group-Object { "$($_.Path)|$($_.Name)".ToLower() } | ForEach-Object { $_.Group[0] }

$backup = @()
$report = @()
foreach ($r in $rows) {
    $want = if ($r.Type -eq 'DWord') { [int]$r.Value } else { $r.Value }
    $cur = Get-Current $r.Path $r.Name
    $ok = ($null -ne $cur) -and ("$cur" -eq "$want")
    $state = if ($ok) { 'OK' } else { 'DIFF' }
    if (-not $ok -and $Mode -eq 'Apply' -and $PSCmdlet.ShouldProcess("$($r.Path)\$($r.Name)", "Set $want")) {
        $backup += [pscustomobject]@{ Path = $r.Path; Name = $r.Name; Type = $r.Type; Old = $cur }
        $key = "Registry::$($r.Path)"
        if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -LiteralPath $key -Name $r.Name -Value $want -PropertyType $r.Type -Force | Out-Null
        $state = 'APPLIED'
    }
    $report += [pscustomobject]@{ Id = $r.Id; Sev = $r.Severity; State = $state; Current = $cur; Wanted = $want; Setting = $r.Name; Description = $r.Description }
}
$report | Format-Table -AutoSize
Write-Host (($report | Group-Object State | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ' | ') -ForegroundColor Cyan

if ($backup.Count) {
    $BackupFile = Join-Path $PSScriptRoot ('backup-{0:yyyyMMdd-HHmmss}.json' -f (Get-Date))
    ConvertTo-Json -InputObject $backup | Set-Content $BackupFile -Encoding UTF8
    Write-Host "Backup saved: $BackupFile  (undo with -Mode Rollback -BackupFile ...)" -ForegroundColor Yellow
}
