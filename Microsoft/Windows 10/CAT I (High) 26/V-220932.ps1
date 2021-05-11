# V-220932 - Anonymous access to Named Pipes and Shares must be restricted

$RestrictNullSessAccess = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess 

if ( $RestrictNullSessAccess.RestrictNullSessAccess -eq 1)
{
    Write-Host V-220932 result is $RestrictNullSessAccess.RestrictNullSessAccess
    Write-Host
    Write-Host "and"
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess 
    Whrite-Host "This is not a finding"
}

else
{
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess 
Write-Host V-220932 result is $RestrictNullSessAccess.RestrictNullSessAccess
}