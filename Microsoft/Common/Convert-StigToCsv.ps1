<#
.SYNOPSIS
  Converts a DISA STIG XCCDF (Manual STIG xml) into CSV files for Invoke-RegistryHardening.ps1.
.DESCRIPTION
  Parses the "Registry Hive / Registry Path / Value Name / Type / Value" blocks of each rule's check text.
    settings.csv      unambiguous HKLM registry rules (exact DWORD/String value) -> safe for the engine
    needs-review.csv  everything else (conditional, ranges, per-user, multi-value, non-registry) with the reason
  Treats the XML purely as data. Nothing in it is executed.
.EXAMPLE
  .\Convert-StigToCsv.ps1 -XccdfFile .\U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml -OutDir '..\Windows 11' -Prefix stig
#>
param(
    [Parameter(Mandatory)][string]$XccdfFile,
    [Parameter(Mandatory)][string]$OutDir,
    [string]$Prefix = 'stig'
)
$ErrorActionPreference = 'Stop'
[xml]$doc = Get-Content -LiteralPath $XccdfFile -Raw -Encoding UTF8
$ns = New-Object Xml.XmlNamespaceManager $doc.NameTable
$ns.AddNamespace('x', $doc.DocumentElement.NamespaceURI)
$sevMap = @{ high = 'CAT1'; medium = 'CAT2'; low = 'CAT3' }
$typeMap = @{ REG_DWORD = 'DWord'; REG_QWORD = 'QWord'; REG_SZ = 'String' }

$good = [System.Collections.Generic.List[object]]::new()
$review = [System.Collections.Generic.List[object]]::new()

foreach ($g in $doc.SelectNodes('//x:Group', $ns)) {
    $rule = $g.SelectSingleNode('x:Rule', $ns)
    $vid = $g.id
    $stigId = $rule.version
    $sev = $sevMap[$rule.severity]
    $title = $rule.title
    $text = [string]$rule.check.'check-content'

    function Add-Review($reason) {
        $review.Add([pscustomobject]@{ Id = $vid; Severity = $sev; StigId = $stigId; Title = $title; Reason = $reason })
    }

    if ($text -notmatch 'Registry Path') { Add-Review 'not a registry rule (policy/audit/service/manual check)'; continue }

    # collect (hive, path, name, type, value) tuples
    $tuples = @(); $hive = $null; $path = $null; $cur = $null
    foreach ($line in ($text -split "`r?`n")) {
        $l = $line.Trim()
        if ($l -match '^Registry Hive:\s*(\S+)') { $hive = $Matches[1] }
        elseif ($l -match '^Registry Path:\s*(.+)$') { $path = $Matches[1].Trim() }
        elseif ($l -match '^Value Name:\s*(.+)$') { $cur = @{ Hive = $hive; Path = $path; Name = $Matches[1].Trim() } }
        elseif ($l -match '^(?:Value )?Type:\s*(\S+)' -and $cur) { $cur.Type = $Matches[1] }
        elseif ($l -match '^Value:\s*(.*)$' -and $cur) { $cur.Value = $Matches[1].Trim(); $tuples += [pscustomobject]$cur; $cur = $null }
    }
    if (-not $tuples) { Add-Review 'registry path found but no Value Name/Type/Value block parsed'; continue }

    $reason = $null
    if ($text -match '\bNA\b|N/A|not applicable') { $reason = 'has an NA/conditional clause' }
    elseif ($text -match 'one of the following|either|If the system is|If the device is|domain-joined|member of a domain') { $reason = 'conditional / alternative values' }
    elseif (($tuples.Name | Select-Object -Unique).Count -ne $tuples.Count) { $reason = 'same value name with several allowed values' }
    elseif ($tuples | Where-Object { $_.Hive -ne 'HKEY_LOCAL_MACHINE' }) { $reason = 'per-user / non-HKLM hive' }
    elseif ($tuples | Where-Object { -not $_.Path -or -not $_.Hive }) { $reason = 'registry path/hive not parsed' }
    elseif ($tuples | Where-Object { -not $_.Type -or -not $typeMap.ContainsKey($_.Type) }) { $reason = 'unsupported registry type' }
    if ($reason) { Add-Review $reason; continue }

    $rows = @()
    foreach ($t in $tuples) {
        if ($t.Type -eq 'String') {
            if ($t.Value -notmatch '^[^()]+$') { $reason = "complex string value: $($t.Value)"; break }
            $val = $t.Value
        }
        else {
            # accept "1", "0x00000001 (1)", "0x00000001 (1) (label)", "0 (or if the Value Name does not exist)";
            # reject anything offering alternatives or ranges ("or less", "1, 3, or 8", ...)
            $v = $t.Value -replace '\(or if the Value Name does not exist\)', ''
            if ($v -match '\bor\b|,' -or $v -notmatch '^(?:0x[0-9a-fA-F]+\s*\()?(\d+)\)?(?:\s|$)') { $reason = "non-exact value: $($t.Value)"; break }
            $val = $Matches[1]
        }
        $rows += [pscustomobject]@{
            Id = $vid; Severity = $sev
            Path = 'HKLM' + ('\' + $t.Path.Trim('\'))
            Name = $t.Name; Type = $typeMap[$t.Type]; Value = $val
            Description = $title; StigId = $stigId
        }
    }
    if ($reason) { Add-Review $reason; continue }
    foreach ($r in $rows) { $good.Add($r) }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$good | Export-Csv (Join-Path $OutDir "$Prefix-settings.csv") -NoTypeInformation -Encoding UTF8
$review | Export-Csv (Join-Path $OutDir "$Prefix-needs-review.csv") -NoTypeInformation -Encoding UTF8
Write-Host "Rules: $(@($doc.SelectNodes('//x:Group',$ns)).Count) | ready: $($good.Count) rows | needs review: $($review.Count)" -ForegroundColor Cyan
$review | Group-Object Reason | Sort-Object Count -Descending | ForEach-Object { '  {0,3}  {1}' -f $_.Count, $_.Name }
