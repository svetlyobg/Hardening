<#
.SYNOPSIS
  Applies / audits the non-registry STIG rules: advanced audit policy (auditpol), account & password policy and
  user rights (secedit). Works on Windows Home too (auditpol and secedit ship with every edition).
.PARAMETER PolicyFile
  policy-settings.csv produced by Convert-StigPolicyToCsv.ps1
.PARAMETER Mode
  Audit (default) report only | Apply | Rollback (needs -BackupDir)
.PARAMETER Type
  Audit, Account, Right. Default: Audit,Account.  Right is OFF by default because a wrong user-right change can lock
  people out of network shares / RDP / local logon - request it explicitly with -Type Right.
.PARAMETER Role
  Server STIGs split rules by role. Member (default) = member/standalone server + client, DC = domain controller.
.NOTES
  Needs an elevated prompt for every mode (auditpol/secedit refuse otherwise).
  Subcategory names are the English auditpol names.
.EXAMPLE
  .\Invoke-PolicyHardening.ps1 -PolicyFile '..\Windows 11\policy-settings.csv'
  .\Invoke-PolicyHardening.ps1 -PolicyFile ... -Mode Apply -Type Audit -WhatIf
  .\Invoke-PolicyHardening.ps1 -PolicyFile ... -Mode Rollback -BackupDir .\policy-backup-20260101-120000
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$PolicyFile,
    [ValidateSet('Audit', 'Apply', 'Rollback')][string]$Mode = 'Audit',
    [ValidateSet('Audit', 'Account', 'Right')][string[]]$Type = @('Audit', 'Account'),
    [ValidateSet('Member', 'DC')][string]$Role = 'Member',
    [ValidateSet('CAT1', 'CAT2', 'CAT3')][string[]]$Severity,
    [string]$BackupDir
)
$ErrorActionPreference = 'Stop'

# ---------- pure helpers (no system access, unit-testable) ----------
function Test-Compliant {
    param([string]$Op, $Current, $Wanted)
    if ($null -eq $Current -or "$Current" -eq '') { return $false }
    $c = [int64]$Current; $w = [int64]$Wanted
    switch ($Op) {
        'eq'     { $c -eq $w }
        'ge'     { $c -ge $w }
        'le'     { $c -le $w }
        'le_nz'  { $c -ge 1 -and $c -le $w }     # "N or less, 0 is unacceptable" (0 and -1 mean "never")
        'ge_or0' { $c -ge $w -or $c -eq 0 -or $c -eq -1 }   # "N or greater, 0 also acceptable" (-1 = until admin unlocks)
        default  { throw "Unknown op $Op" }
    }
}
function ConvertTo-SidSet {
    # "*S-1-5-32-544,*S-1-5-19" or "Administrators,*S-1-5-19" -> sorted unique SIDs ('*' stripped)
    param([string]$List)
    $set = foreach ($t in ($List -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $t = $t.TrimStart('*')
        if ($t -notmatch '^S-1-') {
            try { $t = ([Security.Principal.NTAccount]$t).Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
        }
        $t
    }
    @($set | Sort-Object -Unique)
}
function Test-AuditCompliant {
    param([string]$Current, [string]$Wanted)   # Current: "No Auditing"|"Success"|"Failure"|"Success and Failure"
    $needS = $Wanted -match 'Success'; $needF = $Wanted -match 'Failure'
    $hasS = $Current -match 'Success'; $hasF = $Current -match 'Failure'
    (-not $needS -or $hasS) -and (-not $needF -or $hasF)
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced for tests: stop after defining helpers

# ---------- system access ----------
function Test-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Test-Admin)) { throw 'Run from an elevated (Administrator) PowerShell - auditpol/secedit need it, even for Audit.' }

function Export-SecPolicy([string]$Path) {
    & secedit.exe /export /cfg $Path /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit /export failed ($LASTEXITCODE)" }
}
function Read-Ini([string]$Path) {
    $h = @{}; $sec = ''
    foreach ($l in Get-Content -LiteralPath $Path) {
        if ($l -match '^\[(.+)\]$') { $sec = $Matches[1]; continue }
        if ($l -match '^\s*([^=]+?)\s*=\s*(.*)$') { $h["$sec|$($Matches[1])"] = $Matches[2].Trim() }
    }
    $h
}
$script:AuditTable = $null
function Get-AuditSetting([string]$Sub) {
    # one call for every subcategory; CSV columns: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
    if (-not $script:AuditTable) {
        $script:AuditTable = @{}
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $lines = & auditpol.exe /get /category:* /r 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match ',' }
        $ErrorActionPreference = $old
        if ($LASTEXITCODE -ne 0 -or -not $lines) { throw "auditpol /get failed (exit $LASTEXITCODE)" }
        foreach ($l in ($lines | Select-Object -Skip 1)) {
            $f = $l -split ','
            if ($f.Count -ge 5) { $script:AuditTable[$f[2].Trim()] = $f[4].Trim() }
        }
    }
    $script:AuditTable[$Sub]   # $null when auditpol does not know the name (e.g. non-English Windows)
}

if ($Mode -eq 'Rollback') {
    if (-not $BackupDir -or -not (Test-Path $BackupDir)) { throw '-BackupDir is required for Rollback.' }
    $db = Join-Path $env:TEMP 'rollback.sdb'
    if (Test-Path "$BackupDir\audit.csv") { if ($PSCmdlet.ShouldProcess('audit policy', 'restore')) { & auditpol.exe /restore /file:"$BackupDir\audit.csv" | Out-Null } }
    if (Test-Path "$BackupDir\secpol.inf") { if ($PSCmdlet.ShouldProcess('security policy / user rights', 'restore')) { & secedit.exe /configure /db $db /cfg "$BackupDir\secpol.inf" /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null } }
    Write-Host 'Rollback done.' -ForegroundColor Green; return
}

$rows = Import-Csv $PolicyFile | Where-Object { $Type -contains $_.Type }
$rows = $rows | Where-Object { if ($Role -eq 'DC') { $_.Role -in 'All', 'DC' } else { $_.Role -in 'All', 'MS', $null, '' } }
if ($Severity) { $rows = $rows | Where-Object { $Severity -contains $_.Severity } }

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "OS: $($os.Caption) (build $($os.BuildNumber)) | Mode: $Mode | Types: $($Type -join ',') | Role: $Role" -ForegroundColor Cyan

$tmp = Join-Path $env:TEMP ("secpol-{0}.inf" -f [guid]::NewGuid())
Export-SecPolicy $tmp
$ini = Read-Ini $tmp

# merge duplicate audit rows (Success + Failure for the same subcategory)
$report = @(); $auditNeed = @{}; $accountSet = [ordered]@{}; $rightSet = [ordered]@{}
foreach ($r in $rows) {
    switch ($r.Type) {
        'Audit' {
            $cur = Get-AuditSetting $r.Key
            $ok = $null -ne $cur -and (Test-AuditCompliant $cur $r.Value)
            if (-not $ok) { $auditNeed["$($r.Key)"] = (@($auditNeed["$($r.Key)"], $r.Value) -join ' ') }
            $report += [pscustomobject]@{ Type = 'Audit'; Id = $r.Id; Sev = $r.Severity; State = if ($ok) { 'OK' } else { 'DIFF' }; Setting = $r.Key; Current = $cur; Wanted = $r.Value }
        }
        'Account' {
            $cur = $ini["System Access|$($r.Key)"]
            $ok = Test-Compliant $r.Op $cur $r.Value
            if (-not $ok) { $accountSet[$r.Key] = $r.Value }
            $report += [pscustomobject]@{ Type = 'Account'; Id = $r.Id; Sev = $r.Severity; State = if ($ok) { 'OK' } else { 'DIFF' }; Setting = $r.Key; Current = $cur; Wanted = "$($r.Op) $($r.Value)" }
        }
        'Right' {
            $cur = $ini["Privilege Rights|$($r.Key)"]
            $have = @(ConvertTo-SidSet $cur); $want = @(ConvertTo-SidSet $r.Value)
            $ok = (($have -join ';') -eq ($want -join ';'))
            if (-not $ok) { $rightSet[$r.Key] = $r.Value }
            $report += [pscustomobject]@{ Type = 'Right'; Id = $r.Id; Sev = $r.Severity; State = if ($ok) { 'OK' } else { 'DIFF' }; Setting = $r.Key; Current = ($have -join ','); Wanted = ($want -join ',') }
        }
    }
}

if ($Mode -eq 'Apply' -and ($auditNeed.Count + $accountSet.Count + $rightSet.Count)) {
    $BackupDir = Join-Path $PSScriptRoot ('policy-backup-{0:yyyyMMdd-HHmmss}' -f (Get-Date))
    # no complete backup = no changes
    if ($PSCmdlet.ShouldProcess($BackupDir, 'Create backup of audit + security policy')) {
        New-Item -ItemType Directory -Path $BackupDir -Confirm:$false | Out-Null
        & auditpol.exe /backup /file:"$BackupDir\audit.csv" | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath "$BackupDir\audit.csv")) { throw "auditpol /backup failed (exit $LASTEXITCODE) - nothing was changed." }
        Copy-Item -LiteralPath $tmp -Destination "$BackupDir\secpol.inf" -Confirm:$false
        Write-Host "Backup saved: $BackupDir" -ForegroundColor Yellow
    }
    elseif (-not $WhatIfPreference) { throw 'Backup declined - nothing was changed.' }
    # audit policy: only switch on what is missing, never turn anything off
    foreach ($sub in $auditNeed.Keys) {
        $want = $auditNeed[$sub]
        $aa = @("/set", "/subcategory:$sub")
        if ($want -match 'Success') { $aa += '/success:enable' }
        if ($want -match 'Failure') { $aa += '/failure:enable' }
        if ($PSCmdlet.ShouldProcess("auditpol $sub", ($aa -join ' '))) { & auditpol.exe @aa | Out-Null; if ($LASTEXITCODE -ne 0) { Write-Warning "auditpol failed for $sub" } }
    }
    # account policy + user rights via one INF
    if ($accountSet.Count + $rightSet.Count) {
        $inf = Join-Path $env:TEMP ("apply-{0}.inf" -f [guid]::NewGuid())
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('[Unicode]').AppendLine('Unicode=yes').AppendLine('[Version]').AppendLine('signature="$CHICAGO$"').AppendLine('Revision=1')
        if ($accountSet.Count) { [void]$sb.AppendLine('[System Access]'); foreach ($k in $accountSet.Keys) { [void]$sb.AppendLine("$k = $($accountSet[$k])") } }
        if ($rightSet.Count) { [void]$sb.AppendLine('[Privilege Rights]'); foreach ($k in $rightSet.Keys) { [void]$sb.AppendLine("$k = " + ($rightSet[$k] -replace ';', ',')) } }
        Set-Content -LiteralPath $inf -Value $sb.ToString() -Encoding Unicode
        $db = Join-Path $env:TEMP 'apply.sdb'
        if ($PSCmdlet.ShouldProcess('security policy', "secedit /configure ($($accountSet.Count) account, $($rightSet.Count) rights)")) {
            & secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning "secedit /configure returned $LASTEXITCODE (see %windir%\security\logs\scesrv.log)" }
        }
        Remove-Item $inf -ErrorAction SilentlyContinue
    }
    if (-not $WhatIfPreference) { foreach ($x in $report | Where-Object State -eq 'DIFF') { $x.State = 'APPLIED' } }
}
Remove-Item $tmp -ErrorAction SilentlyContinue

$report | Format-Table -AutoSize
Write-Host (($report | Group-Object State | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ' | ') -ForegroundColor Cyan
