# V-220862 - The Windows Remote Management (WinRM) client must not use Basic authentication
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220862

$AllowBasic = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' | Select -ExpandProperty AllowBasic

    if ( $AllowBasic -eq 0)
{
    Write-Host "`n$line"
    Write-Host V-220862 result is $AllowBasic 
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\'
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220823 result is $AllowBasic
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' 
    }
