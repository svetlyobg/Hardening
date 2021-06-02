# V-220838 - https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220838
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220838

$NoHeapTerminationOnCorruption = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\' | Select -ExpandProperty NoHeapTerminationOnCorruption

 if ( $NoHeapTerminationOnCorruption -eq 0 )
        {
            Write-Host "`n$line"
            Write-Host V-220838 result is $NoHeapTerminationOnCorruption 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\'
            }

elseif ($NoHeapTerminationOnCorruption -eq 1)
            {
             Write-Host "`n$line"
                Write-Host V-220838 result is $NoHeapTerminationOnCorruption
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220838 result is $NoHeapTerminationOnCorruption
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\'
            } 