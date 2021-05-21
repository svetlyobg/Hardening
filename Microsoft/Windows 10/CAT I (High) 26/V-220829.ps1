# V-220829	- Autoplay must be disabled for all drives
# https://www.stigviewer.com/stig/windows_10/2020-10-15/finding/V-220829

$NoDriveTypeAutoRun = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' | Select -ExpandProperty NoDriveTypeAutoRun

    if ( $NoDriveTypeAutoRun -eq 255 )
        {
            Write-Host "`n$line"
            Write-Host V-220829 result is $NoDriveTypeAutoRun 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220829 result is $NoDriveTypeAutoRun
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\'
            }