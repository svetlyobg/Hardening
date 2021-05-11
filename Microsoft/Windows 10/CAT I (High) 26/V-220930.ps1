# V-220930 - Anonymous enumeration of shares must be restricted

$RestrictAnonymous = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymous | select -ExpandProperty restrictanonymous

if ( $RestrictAnonymous -eq 1)
{
    Write-Host
    Write-Host V-220930 result is $RestrictAnonymous
    Write-Host    
    Write-Host "This is not a finding" -ForegroundColor Green

    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymous
}

else 
{
    Write-Host
    Write-Host V-220930 result is $RestrictAnonymous
    Write-Host
    Write-Host "This is a finding" -ForegroundColor Red

    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymous
    
}