#  V-220718 - Internet Information System (IIS) or its subcomponents must not be installed on a workstation
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220718

$State = Get-WindowsOptionalFeature -FeatureName IIS-WebServerRole  -Online | select -ExpandProperty State

    if ( $State -eq 'Disabled')
{
    Write-Host "`n$line"
    Write-Host V-220718 result is $State 
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-WindowsOptionalFeature -FeatureName IIS-WebServerRole  -Online 
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220718 result is $State
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-WindowsOptionalFeature -FeatureName IIS-WebServerRole  -Online 
    }