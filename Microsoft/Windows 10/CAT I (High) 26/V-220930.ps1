# V-220930 - Anonymous enumeration of shares must be restricted.

$RestrictAnonymous = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymous

if ( $RestrictAnonymous.RestrictNullSessAccess -eq 1)
{
    Write-Host V-220930 result is $RestrictAnonymous.RestrictAnonymous
    Write-Host
    Write-Host "and"
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymous 
    Write-Host "This is not a finding" -ForegroundColor Green
}

else 
{
    Write-Host V-220930 result is $RestrictAnonymous.RestrictAnonymous
    Write-Host
    Write-Host "and"
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymous 
    Write-Host "This is a finding" -ForegroundColor Red
}