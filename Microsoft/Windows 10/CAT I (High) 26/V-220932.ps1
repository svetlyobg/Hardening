# V-220932 - Anonymous access to Named Pipes and Shares must be restricted

#$RestrictNullSessAccess = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess 
$RestrictNullSessAccess = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters | select -ExpandProperty RestrictNullSessAccess

if ( $RestrictNullSessAccess -eq 1)
{
    Write-Host "`n$line"
    Write-Host V-220932 result is $RestrictNullSessAccess
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220932 result is $RestrictNullSessAccess
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess
    }