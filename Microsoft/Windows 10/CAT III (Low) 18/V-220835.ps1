# V-220835 - Windows Update must not obtain updates from other PCs on the Internet
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220835

$DODownloadMode = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\' | Select -ExpandProperty DODownloadMode

 if ( $DODownloadMode -eq 0 -or   $DODownloadMode -eq 1)
        {
            Write-Host "`n$line"
            Write-Host V-220835 result is $DODownloadMode 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220835 result is $DODownloadMode
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\'
            }