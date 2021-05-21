# V-220831 - Microsoft consumer experiences must be turned off
# https://www.stigviewer.com/stig/windows_10/2020-10-15/finding/V-220831

$DisableWindowsConsumerFeatures = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CloudContent\' | Select -ExpandProperty DisableWindowsConsumerFeatures

    if ( $NoDriveTypeAutoRun -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-220831 result is $DisableWindowsConsumerFeatures 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CloudContent\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220831 result is $DisableWindowsConsumerFeatures
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CloudContent\'
            }