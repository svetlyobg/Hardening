# V-220827 - Autoplay must be turned off for non-volume devices
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220827

$NoAutoplayfornonVolume = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\' | Select -ExpandProperty NoDataExecutionPrevention

  if ( $NoAutoplayfornonVolume -eq 1)
{
    Write-Host "`n$line"
    Write-Host V-220827 result is $NoAutoplayfornonVolume 
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\'
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220827 result is $NoAutoplayfornonVolume
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\' 
    }
