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
function Get-SecPolicyDifference {
    # keys ("Section|Name") where the current security policy does not match a backup
    param([hashtable]$Backup, [hashtable]$Current)
    foreach ($k in $Backup.Keys) {
        if ($k -like 'System Access|*' -and "$($Current[$k])" -ne "$($Backup[$k])") { $k }
    }
    # a right nobody held is missing from an export, so look at the keys of both sides
    $rights = @($Backup.Keys) + @($Current.Keys) | Where-Object { $_ -like 'Privilege Rights|*' } | Sort-Object -Unique
    foreach ($k in $rights) {
        if (((ConvertTo-SidSet $Backup[$k]) -join ';') -ne ((ConvertTo-SidSet $Current[$k]) -join ';')) { $k }
    }
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
function Invoke-SecEditConfigure([string]$Inf) {
    # a fresh database every time: secedit merges a template into an existing one, which would replay old settings
    $db = Join-Path $env:TEMP ("hardening-{0}.sdb" -f [guid]::NewGuid())
    & secedit.exe /configure /db $db /cfg $Inf /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $db, ([IO.Path]::ChangeExtension($db, 'jfm')) -ErrorAction SilentlyContinue -Confirm:$false
    $code
}
function Get-RowResult($Row, [hashtable]$Ini) {
    switch ($Row.Type) {
        'Audit' {
            $cur = Get-AuditSetting $Row.Key
            @{ Ok = ($null -ne $cur -and (Test-AuditCompliant $cur $Row.Value)); Current = $cur; Wanted = $Row.Value }
        }
        'Account' {
            $cur = $Ini["System Access|$($Row.Key)"]
            @{ Ok = (Test-Compliant $Row.Op $cur $Row.Value); Current = $cur; Wanted = "$($Row.Op) $($Row.Value)" }
        }
        'Right' {
            $have = @(ConvertTo-SidSet $Ini["Privilege Rights|$($Row.Key)"]); $want = @(ConvertTo-SidSet $Row.Value)
            @{ Ok = (($have -join ';') -eq ($want -join ';')); Current = ($have -join ','); Wanted = ($want -join ',') }
        }
    }
}

if ($Mode -eq 'Rollback') {
    if (-not $BackupDir -or -not (Test-Path $BackupDir)) { throw '-BackupDir is required for Rollback.' }
    $auditFile = Join-Path $BackupDir 'audit.csv'
    $secFile = Join-Path $BackupDir 'secpol.inf'
    $done = @(); $failed = @()

    if (-not (Test-Path -LiteralPath $auditFile)) { $failed += 'audit policy: audit.csv is missing from the backup' }
    elseif ($PSCmdlet.ShouldProcess('audit policy', 'restore')) {
        & auditpol.exe /restore /file:"$auditFile" | Out-Null
        if ($LASTEXITCODE -ne 0) { $failed += "audit policy: auditpol /restore returned $LASTEXITCODE" } else { $done += 'audit policy' }
    }

    if (-not (Test-Path -LiteralPath $secFile)) { $failed += 'security policy: secpol.inf is missing from the backup' }
    elseif ($PSCmdlet.ShouldProcess('security policy / user rights', 'restore')) {
        $code = Invoke-SecEditConfigure $secFile
        # read the policy back: exit code 0 alone does not prove that every setting returned
        $now = Join-Path $env:TEMP ("secpol-{0}.inf" -f [guid]::NewGuid())
        Export-SecPolicy $now
        $diff = @(Get-SecPolicyDifference (Read-Ini $secFile) (Read-Ini $now))
        Remove-Item -LiteralPath $now -ErrorAction SilentlyContinue -Confirm:$false
        if ($code -ne 0) { $failed += "security policy: secedit /configure returned $code (see %windir%\security\logs\scesrv.log)" }
        if ($diff) { $failed += "security policy: still differs from the backup: $(($diff | Sort-Object) -join ', ')" }
        if ($code -eq 0 -and -not $diff) { $done += 'security policy and user rights' }
    }

    if ($done) { Write-Host "Restored: $($done -join ', ')" -ForegroundColor Green }
    if ($failed) { throw ("Rollback INCOMPLETE:`n - " + ($failed -join "`n - ")) }
    if (-not $done) { Write-Host 'Nothing was restored.' -ForegroundColor Yellow }
    return
}

$rows = Import-Csv $PolicyFile | Where-Object { $Type -contains $_.Type }
$rows = $rows | Where-Object { if ($Role -eq 'DC') { $_.Role -in 'All', 'DC' } else { $_.Role -in 'All', 'MS', $null, '' } }
if ($Severity) { $rows = $rows | Where-Object { $Severity -contains $_.Severity } }
$rows = @($rows)

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "OS: $($os.Caption) (build $($os.BuildNumber)) | Mode: $Mode | Types: $($Type -join ',') | Role: $Role" -ForegroundColor Cyan

$tmp = Join-Path $env:TEMP ("secpol-{0}.inf" -f [guid]::NewGuid())
Export-SecPolicy $tmp
$ini = Read-Ini $tmp

# merge duplicate audit rows (Success + Failure for the same subcategory)
$report = @(); $auditNeed = @{}; $accountSet = [ordered]@{}; $rightSet = [ordered]@{}
foreach ($r in $rows) {
    $res = Get-RowResult $r $ini
    if (-not $res.Ok) {
        switch ($r.Type) {
            'Audit' { $auditNeed["$($r.Key)"] = (@($auditNeed["$($r.Key)"], $r.Value) -join ' ') }
            'Account' { $accountSet[$r.Key] = $r.Value }
            'Right' { $rightSet[$r.Key] = $r.Value }
        }
    }
    $report += [pscustomobject]@{ Type = $r.Type; Id = $r.Id; Sev = $r.Severity; State = if ($res.Ok) { 'OK' } else { 'DIFF' }; Setting = $r.Key; Current = $res.Current; Wanted = $res.Wanted }
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
    $tried = @{}   # "Type|Setting" for which a change was actually attempted
    # audit policy: only switch on what is missing, never turn anything off
    foreach ($sub in $auditNeed.Keys) {
        $want = $auditNeed[$sub]
        $aa = @("/set", "/subcategory:$sub")
        if ($want -match 'Success') { $aa += '/success:enable' }
        if ($want -match 'Failure') { $aa += '/failure:enable' }
        if ($PSCmdlet.ShouldProcess("auditpol $sub", ($aa -join ' '))) { $tried["Audit|$sub"] = $true; & auditpol.exe @aa | Out-Null; if ($LASTEXITCODE -ne 0) { Write-Warning "auditpol failed for $sub" } }
    }
    # account policy + user rights via one INF
    if ($accountSet.Count + $rightSet.Count) {
        $inf = Join-Path $env:TEMP ("apply-{0}.inf" -f [guid]::NewGuid())
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('[Unicode]').AppendLine('Unicode=yes').AppendLine('[Version]').AppendLine('signature="$CHICAGO$"').AppendLine('Revision=1')
        if ($accountSet.Count) { [void]$sb.AppendLine('[System Access]'); foreach ($k in $accountSet.Keys) { [void]$sb.AppendLine("$k = $($accountSet[$k])") } }
        if ($rightSet.Count) { [void]$sb.AppendLine('[Privilege Rights]'); foreach ($k in $rightSet.Keys) { [void]$sb.AppendLine("$k = " + ($rightSet[$k] -replace ';', ',')) } }
        Set-Content -LiteralPath $inf -Value $sb.ToString() -Encoding Unicode
        if ($PSCmdlet.ShouldProcess('security policy', "secedit /configure ($($accountSet.Count) account, $($rightSet.Count) rights)")) {
            foreach ($k in $accountSet.Keys) { $tried["Account|$k"] = $true }
            foreach ($k in $rightSet.Keys) { $tried["Right|$k"] = $true }
            $code = Invoke-SecEditConfigure $inf
            if ($code -ne 0) { Write-Warning "secedit /configure returned $code (see %windir%\security\logs\scesrv.log)" }
        }
        Remove-Item $inf -ErrorAction SilentlyContinue
    }
    # read the settings back: APPLIED only if the system now really complies, otherwise FAILED
    if ($tried.Count) {
        $script:AuditTable = $null
        Export-SecPolicy $tmp
        $after = Read-Ini $tmp
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $line = $report[$i]
            if ($line.State -eq 'DIFF' -and $tried["$($line.Type)|$($line.Setting)"]) {
                $line.State = if ((Get-RowResult $rows[$i] $after).Ok) { 'APPLIED' } else { 'FAILED' }
            }
        }
    }
}
Remove-Item $tmp -ErrorAction SilentlyContinue

$report | Format-Table -AutoSize
Write-Host (($report | Group-Object State | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ' | ') -ForegroundColor Cyan
$notApplied = @($report | Where-Object State -eq 'FAILED').Count
if ($notApplied) { Write-Warning "$notApplied setting(s) were not applied - see the FAILED rows." }
