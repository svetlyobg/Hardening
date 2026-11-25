<#
.SYNOPSIS
  Converts the NON-registry rules of a DISA STIG XCCDF into policy-settings.csv for Invoke-PolicyHardening.ps1:
    Audit    advanced audit policy (auditpol)
    Account  password / lockout policy and a few security options (secedit [System Access])
    Right    user rights assignment (secedit [Privilege Rights])
  Rules that cannot be expressed exactly (domain-only, SIDs/accounts we cannot map, etc.) go to policy-needs-review.csv.
  The XML is treated purely as data; nothing in it is executed.
.EXAMPLE
  .\Convert-StigPolicyToCsv.ps1 -XccdfFile .\U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml -OutDir '..\Windows 11'
#>
param(
    [Parameter(Mandatory)][string]$XccdfFile,
    [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
[xml]$doc = Get-Content -LiteralPath $XccdfFile -Raw -Encoding UTF8
$ns = New-Object Xml.XmlNamespaceManager $doc.NameTable
$ns.AddNamespace('x', $doc.DocumentElement.NamespaceURI)
$sevMap = @{ high = 'CAT1'; medium = 'CAT2'; low = 'CAT3' }

# display name -> secedit [System Access] key, comparison
$account = @{
    'Account lockout duration'                    = @('LockoutDuration', 'ge_or0')
    'Account lockout threshold'                   = @('LockoutBadCount', 'le_nz')
    'Reset account lockout counter after'         = @('ResetLockoutCount', 'ge')
    'Enforce password history'                    = @('PasswordHistorySize', 'ge')
    'Maximum Password Age'                        = @('MaximumPasswordAge', 'le_nz')
    'Minimum Password Age'                        = @('MinimumPasswordAge', 'ge')
    'Minimum password length'                     = @('MinimumPasswordLength', 'ge')
    'Password must meet complexity requirements'  = @('PasswordComplexity', 'eq')
    'Store passwords using reversible encryption' = @('ClearTextPassword', 'eq')
    'Accounts: Guest account status'              = @('EnableGuestAccount', 'eq')
    'Network access: Allow anonymous SID/Name translation' = @('LSAAnonymousNameLookup', 'eq')
}
# user right display name -> privilege constant
$rights = @{
    'Access Credential Manager as a trusted caller' = 'SeTrustedCredManAccessPrivilege'
    'Access this computer from the network'         = 'SeNetworkLogonRight'
    'Act as part of the operating system'           = 'SeTcbPrivilege'
    'Allow log on locally'                          = 'SeInteractiveLogonRight'
    'Back up files and directories'                 = 'SeBackupPrivilege'
    'Change the system time'                        = 'SeSystemtimePrivilege'
    'Create a pagefile'                             = 'SeCreatePagefilePrivilege'
    'Create a token object'                         = 'SeCreateTokenPrivilege'
    'Create global objects'                         = 'SeCreateGlobalPrivilege'
    'Create permanent shared objects'               = 'SeCreatePermanentPrivilege'
    'Create symbolic links'                         = 'SeCreateSymbolicLinkPrivilege'
    'Debug programs'                                = 'SeDebugPrivilege'
    'Enable computer and user accounts to be trusted for delegation' = 'SeEnableDelegationPrivilege'
    'Force shutdown from a remote system'           = 'SeRemoteShutdownPrivilege'
    'Impersonate a client after authentication'     = 'SeImpersonatePrivilege'
    'Load and unload device drivers'                = 'SeLoadDriverPrivilege'
    'Lock pages in memory'                          = 'SeLockMemoryPrivilege'
    'Manage auditing and security log'              = 'SeSecurityPrivilege'
    'Modify firmware environment values'            = 'SeSystemEnvironmentPrivilege'
    'Perform volume maintenance tasks'              = 'SeManageVolumePrivilege'
    'Profile single process'                        = 'SeProfileSingleProcessPrivilege'
    'Restore files and directories'                 = 'SeRestorePrivilege'
    'Take ownership of files or other objects'      = 'SeTakeOwnershipPrivilege'
    'Generate security audits'                      = 'SeAuditPrivilege'
    'Increase scheduling priority'                  = 'SeIncreaseBasePriorityPrivilege'
}
# only well-known accounts with fixed SIDs (locale independent). Anything else -> needs review
$sids = @{
    'administrators' = '*S-1-5-32-544'; 'users' = '*S-1-5-32-545'; 'guests' = '*S-1-5-32-546'
    'remote desktop users' = '*S-1-5-32-555'; 'backup operators' = '*S-1-5-32-551'
    'local service' = '*S-1-5-19'; 'network service' = '*S-1-5-20'; 'service' = '*S-1-5-6'
    'authenticated users' = '*S-1-5-11'; 'everyone' = '*S-1-1-0'; 'enterprise domain controllers' = '*S-1-5-9'
}

$out = [System.Collections.Generic.List[object]]::new()
$rev = [System.Collections.Generic.List[object]]::new()

foreach ($g in $doc.SelectNodes('//x:Group', $ns)) {
    $rule = $g.SelectSingleNode('x:Rule', $ns)
    $check = [string]$rule.check.'check-content'
    if ($check -match 'Registry Path') { continue }   # handled by Convert-StigToCsv.ps1
    $fixRaw = [string]$rule.fixtext.'#text'
    $fix = $fixRaw -replace '\s+', ' '
    $meta = @{ Id = $g.id; Severity = $sevMap[$rule.severity]; StigId = $rule.version; Description = [string]$rule.title }
    # Server STIGs split rules by role: -DC- = domain controller only, -MS- = member/standalone server
    $role = if ($meta.StigId -match '-DC-') { 'DC' } elseif ($meta.StigId -match '-MS-') { 'MS' } else { 'All' }
    function Add-Row($type, $key, $op, $value) {
        $out.Add([pscustomobject]@{ Type = $type; Id = $meta.Id; Severity = $meta.Severity; Role = $role; Key = $key; Op = $op; Value = $value; Description = $meta.Description; StigId = $meta.StigId })
    }
    function Add-Rev($reason) {
        $rev.Add([pscustomobject]@{ Id = $meta.Id; Severity = $meta.Severity; StigId = $meta.StigId; Title = $meta.Description; Reason = $reason })
    }

    # ---- advanced audit policy ----
    if ($fix -match 'Advanced Audit Policy') {
        $name = $null; $val = $null
        if ($fix -match '"Audit ([^"]+)"\s*(?:with|to)\s*"([^"]+)"') { $name = $Matches[1]; $val = $Matches[2] }
        elseif ($fix -match '>>\s*Audit ([^>"]+?)"?\s+with\s+"?([^"]+?)"?\s+selected') { $name = $Matches[1]; $val = $Matches[2] }
        if (-not $name) { Add-Rev 'audit rule not parsed'; continue }
        # GUI says "Audit <subcategory>", auditpol uses the bare subcategory name - except this one, whose real name starts with "Audit"
        if ($name.Trim() -eq 'Policy Change') { $name = 'Audit Policy Change' }
        if ($name.Trim() -eq 'PNP Activity') { $name = 'Plug and Play Events' }   # GUI name differs from the auditpol name
        if ($val -in 'Success', 'Failure', 'Success and Failure') { Add-Row 'Audit' $name.Trim() 'include' $val }
        else { Add-Rev "audit setting not parsed: $val" }
        continue
    }

    # ---- account policy / security options ----
    $hit = $account.Keys | Where-Object { $fix -match ('"' + [regex]::Escape($_) + '"') } | Select-Object -First 1
    if ($hit) {
        $key, $op = $account[$hit]
        if ($fix -match ('"' + [regex]::Escape($hit) + '"\s*(?:to|with)\s+(?:at least\s+)?"([^"]+)"')) {
            $v = $Matches[1]
            if ($v -eq 'Enabled') { $v = '1' } elseif ($v -eq 'Disabled') { $v = '0' }
            if ($v -match '^\d+$') { Add-Row 'Account' $key $op $v } else { Add-Rev "account value not numeric: $v" }
        }
        else { Add-Rev 'account rule value not parsed' }
        continue
    }

    # ---- user rights ----
    if ($fix -match 'User Rights Assignment >> "?(.+?)"? (?:to be defined|to include|to only include)') {
        $name = $Matches[1]
        if (-not $rights.ContainsKey($name)) { Add-Rev "user right not mapped: $name"; continue }
        if ($fix -match 'Domain Systems Only|this is NA') { Add-Rev 'conditional / domain-specific user right'; continue }
        if ($fix -match 'defined but containing no entries') { Add-Row 'Right' $rights[$name] 'exact' ''; continue }
        if ($fixRaw -match '(?s)(?:groups or accounts|accounts or groups):\s*(.+)$') {
            $accts = $Matches[1] -split "`r?`n" | ForEach-Object { ($_.Trim() -replace '^-\s*', '') -replace '[.,]$', '' } | Where-Object { $_ }
            $mapped = @(); $bad = $null
            foreach ($a in $accts) {
                if ($sids.ContainsKey($a.ToLower())) { $mapped += $sids[$a.ToLower()] } else { $bad = $a; break }
            }
            if ($bad) { Add-Rev "unmapped account in user right: $bad" } else { Add-Row 'Right' $rights[$name] 'exact' ($mapped -join ';') }
        }
        else { Add-Rev 'user right list not parsed' }
        continue
    }
    # everything else (services, features, renames, banners ...) is not handled here
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out | Export-Csv (Join-Path $OutDir 'policy-settings.csv') -NoTypeInformation -Encoding UTF8
$rev | Export-Csv (Join-Path $OutDir 'policy-needs-review.csv') -NoTypeInformation -Encoding UTF8
Write-Host "ready: $($out.Count) | needs review: $($rev.Count)" -ForegroundColor Cyan
$out | Group-Object Type | ForEach-Object { '  {0,-8} {1}' -f $_.Name, $_.Count }
$rev | Group-Object Reason | Sort-Object Count -Descending | ForEach-Object { '  review {0,3}  {1}' -f $_.Count, $_.Name }
