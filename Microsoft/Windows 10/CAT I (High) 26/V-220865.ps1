# V-220865 - The Windows Remote Management (WinRM) service must not use Basic authentication
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220865

$AllowBasic = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' | Select -ExpandProperty AllowBasic

    if ( $AllowBasic -eq 0)
{
    Write-Host "`n$line"
    Write-Host V-220865 result is $AllowBasic 
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\'
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220865 result is $AllowBasic
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' 
    }
