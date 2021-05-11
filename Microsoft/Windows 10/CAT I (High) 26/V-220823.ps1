# V-220823 - Solicited Remote Assistance must not be allowed
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220823

$fAllowToGetHelp = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' | Select -ExpandProperty fAllowToGetHelp

    if ( $fAllowToGetHelp -eq 0)
{
    Write-Host "`n$line"
    Write-Host V-220718 result is $fAllowToGetHelp 
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220718 result is $fAllowToGetHelp
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 
    }
