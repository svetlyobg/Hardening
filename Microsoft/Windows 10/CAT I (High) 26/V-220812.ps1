# V-220812 - Credential Guard must be running on Windows 10 domain-joined systems
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220812

$SecurityServicesRunning = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select -ExpandProperty SecurityServicesRunning

    if ( $SecurityServicesRunning -eq 1 -and $SecurityServicesRunning -eq 2)
{
    Write-Host "`n$line"
    Write-Host V-220812 result is $SecurityServicesRunning 
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220812 result is $SecurityServicesRunning
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
    }
